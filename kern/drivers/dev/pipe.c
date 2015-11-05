/* Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
 * Portions Copyright © 1997-1999 Vita Nuova Limited
 * Portions Copyright © 2000-2007 Vita Nuova Holdings Limited
 *                                (www.vitanuova.com)
 * Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
 *
 * Modified for the Akaros operating system:
 * Copyright (c) 2013-2014 The Regents of the University of California
 * Copyright (c) 2013-2015 Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include <vfs.h>
#include <kfs.h>
#include <slab.h>
#include <kmalloc.h>
#include <kref.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <error.h>
#include <cpio.h>
#include <pmap.h>
#include <smp.h>
#include <ip.h>

struct dev pipedevtab;

static char *devname(void)
{
	return pipedevtab.name;
}

typedef struct Pipe Pipe;
struct Pipe {
	qlock_t qlock;
	Pipe *next;
	struct kref ref;
	uint32_t path;
	struct queue *q[2];
	int qref[2];
	struct dirtab *pipedir;
	char *user;
};

static struct {
	spinlock_t lock;
	uint32_t path;
	int pipeqsize;
} pipealloc;

enum {
	Qdir,
	Qdata0,
	Qdata1,
};

static
struct dirtab pipedir[] = {
	{".", {Qdir, 0, QTDIR}, 0, DMDIR | 0500},
	{"data", {Qdata0}, 0, 0660},
	{"data1", {Qdata1}, 0, 0660},
};

static void freepipe(Pipe * p)
{
	if (p != NULL) {
		kfree(p->user);
		kfree(p->q[0]);
		kfree(p->q[1]);
		kfree(p->pipedir);
		kfree(p);
	}
}

static void pipe_release(struct kref *kref)
{
	Pipe *pipe = container_of(kref, Pipe, ref);
	freepipe(pipe);
}

static void pipeinit(void)
{
	pipealloc.pipeqsize = 32 * 1024;
}

/*
 *  create a pipe, no streams are created until an open
 */
static struct chan *pipeattach(char *spec)
{
	ERRSTACK(2);
	Pipe *p;
	struct chan *c;

	c = devattach(devname(), spec);
	p = kzmalloc(sizeof(Pipe), 0);
	if (p == 0)
		error(ENOMEM, NULL);
	if (waserror()) {
		freepipe(p);
		nexterror();
	}
	p->pipedir = kzmalloc(sizeof(pipedir), 0);
	if (p->pipedir == 0)
		error(ENOMEM, NULL);
	memmove(p->pipedir, pipedir, sizeof(pipedir));
	kstrdup(&p->user, current->user);
	kref_init(&p->ref, pipe_release, 1);
	qlock_init(&p->qlock);

	p->q[0] = qopen(pipealloc.pipeqsize, Qcoalesce, 0, 0);
	if (p->q[0] == 0)
		error(ENOMEM, NULL);
	p->q[1] = qopen(pipealloc.pipeqsize, Qcoalesce, 0, 0);
	if (p->q[1] == 0)
		error(ENOMEM, NULL);
	poperror();

	spin_lock(&(&pipealloc)->lock);
	p->path = ++pipealloc.path;
	spin_unlock(&(&pipealloc)->lock);

	c->qid.path = NETQID(2 * p->path, Qdir);
	c->qid.vers = 0;
	c->qid.type = QTDIR;
	c->aux = p;
	c->dev = 0;
	return c;
}

static int
pipegen(struct chan *c, char *unused,
		struct dirtab *tab, int ntab, int i, struct dir *dp)
{
	int id, len;
	struct qid qid;
	Pipe *p;

	if (i == DEVDOTDOT) {
		devdir(c, c->qid, devname(), 0, eve, 0555, dp);
		return 1;
	}
	i++;	/* skip . */
	if (tab == 0 || i >= ntab)
		return -1;
	tab += i;
	p = c->aux;
	switch (NETTYPE(tab->qid.path)) {
		case Qdata0:
			len = qlen(p->q[0]);
			break;
		case Qdata1:
			len = qlen(p->q[1]);
			break;
		default:
			len = tab->length;
			break;
	}
	id = NETID(c->qid.path);
	qid.path = NETQID(id, tab->qid.path);
	qid.vers = 0;
	qid.type = QTFILE;
	devdir(c, qid, tab->name, len, eve, tab->perm, dp);
	return 1;
}

static struct walkqid *pipewalk(struct chan *c, struct chan *nc, char **name,
								int nname)
{
	struct walkqid *wq;
	Pipe *p;

	p = c->aux;
	wq = devwalk(c, nc, name, nname, p->pipedir, ARRAY_SIZE(pipedir), pipegen);
	if (wq != NULL && wq->clone != NULL && wq->clone != c) {
		qlock(&p->qlock);
		kref_get(&p->ref, 1);
		if (c->flag & COPEN) {
			switch (NETTYPE(c->qid.path)) {
				case Qdata0:
					p->qref[0]++;
					break;
				case Qdata1:
					p->qref[1]++;
					break;
			}
		}
		qunlock(&p->qlock);
	}
	return wq;
}

static int pipestat(struct chan *c, uint8_t * db, int n)
{
	Pipe *p;
	struct dir dir;
	struct dirtab *tab;

	p = c->aux;
	tab = p->pipedir;

	switch (NETTYPE(c->qid.path)) {
		case Qdir:
			devdir(c, c->qid, ".", 0, eve, DMDIR | 0555, &dir);
			break;
		case Qdata0:
			devdir(c, c->qid, tab[1].name, qlen(p->q[0]), eve, tab[1].perm,
				   &dir);
			break;
		case Qdata1:
			devdir(c, c->qid, tab[2].name, qlen(p->q[1]), eve, tab[2].perm,
				   &dir);
			break;
		default:
			panic("pipestat");
	}
	n = convD2M(&dir, db, n);
	if (n < BIT16SZ)
		error(ENODATA, NULL);
	return n;
}

/*
 *  if the stream doesn't exist, create it
 */
static struct chan *pipeopen(struct chan *c, int omode)
{
	ERRSTACK(2);
	Pipe *p;

	if (c->qid.type & QTDIR) {
		if (omode & O_WRITE)
			error(EINVAL, "Can only open directories O_READ, mode is %o oct",
				  omode);
		c->mode = openmode(omode);
		c->flag |= COPEN;
		c->offset = 0;
		return c;
	}

	openmode(omode);	/* check it */

	p = c->aux;
	qlock(&p->qlock);
	if (waserror()) {
		qunlock(&p->qlock);
		nexterror();
	}
	switch (NETTYPE(c->qid.path)) {
		case Qdata0:
			devpermcheck(p->user, p->pipedir[1].perm, omode);
			p->qref[0]++;
			break;
		case Qdata1:
			devpermcheck(p->user, p->pipedir[2].perm, omode);
			p->qref[1]++;
			break;
	}
	poperror();
	qunlock(&p->qlock);

	c->mode = openmode(omode);
	c->flag |= COPEN;
	c->offset = 0;
	c->iounit = qiomaxatomic;
	return c;
}

static void pipeclose(struct chan *c)
{
	Pipe *p;

	p = c->aux;
	qlock(&p->qlock);

	if (c->flag & COPEN) {
		/*
		 *  closing either side hangs up the stream
		 */
		switch (NETTYPE(c->qid.path)) {
			case Qdata0:
				p->qref[0]--;
				if (p->qref[0] == 0) {
					qhangup(p->q[1], 0);
					qclose(p->q[0]);
				}
				break;
			case Qdata1:
				p->qref[1]--;
				if (p->qref[1] == 0) {
					qhangup(p->q[0], 0);
					qclose(p->q[1]);
				}
				break;
		}
	}

	/*
	 *  if both sides are closed, they are reusable
	 */
	if (p->qref[0] == 0 && p->qref[1] == 0) {
		qreopen(p->q[0]);
		qreopen(p->q[1]);
	}

	qunlock(&p->qlock);
	/*
	 *  free the structure on last close
	 */
	kref_put(&p->ref);
}

static long piperead(struct chan *c, void *va, long n, int64_t ignored)
{
	Pipe *p;

	p = c->aux;

	switch (NETTYPE(c->qid.path)) {
		case Qdir:
			return devdirread(c, va, n, p->pipedir, ARRAY_SIZE(pipedir),
							  pipegen);
		case Qdata0:
			return qread(p->q[0], va, n);
		case Qdata1:
			return qread(p->q[1], va, n);
		default:
			panic("piperead");
	}
	return -1;	/* not reached */
}

static struct block *pipebread(struct chan *c, long n, uint32_t offset)
{
	Pipe *p;

	p = c->aux;

	switch (NETTYPE(c->qid.path)) {
		case Qdata0:
			return qbread(p->q[0], n);
		case Qdata1:
			return qbread(p->q[1], n);
	}

	return devbread(c, n, offset);
}

/*
 *  A write to a closed pipe causes an EPIPE error to be thrown.
 */
static long pipewrite(struct chan *c, void *va, long n, int64_t ignored)
{
	ERRSTACK(2);
	Pipe *p;

	if (waserror()) {
		poperror();
		error(EPIPE, NULL);
	}

	p = c->aux;

	switch (NETTYPE(c->qid.path)) {
		case Qdata0:
			n = qwrite(p->q[1], va, n);
			break;

		case Qdata1:
			n = qwrite(p->q[0], va, n);
			break;

		default:
			panic("pipewrite");
	}

	poperror();
	return n;
}

static long pipebwrite(struct chan *c, struct block *bp, uint32_t junk)
{
	ERRSTACK(2);
	long n;
	Pipe *p;

	if (waserror()) {
		poperror();
		error(EPIPE, NULL);
	}

	p = c->aux;
	switch (NETTYPE(c->qid.path)) {
		case Qdata0:
			n = qbwrite(p->q[1], bp);
			break;

		case Qdata1:
			n = qbwrite(p->q[0], bp);
			break;

		default:
			n = 0;
			panic("pipebwrite");
	}

	poperror();
	return n;
}

static int pipewstat(struct chan *c, uint8_t *dp, int n)
{
	ERRSTACK(2);
	struct dir *d;
	Pipe *p;
	int d1;

	if (c->qid.type & QTDIR)
		error(EPERM, NULL);
	p = c->aux;
	if (strcmp(current->user, p->user) != 0)
		error(EPERM, NULL);
	d = kzmalloc(sizeof(*d) + n, 0);
	if (waserror()) {
		kfree(d);
		nexterror();
	}
	n = convM2D(dp, n, d, (char *)&d[1]);
	if (n == 0)
		error(ENODATA, NULL);
	d1 = NETTYPE(c->qid.path) == Qdata1;
	if (!emptystr(d->name)) {
		validwstatname(d->name);
		if (strlen(d->name) >= KNAMELEN)
			error(ENAMETOOLONG, NULL);
		if (strncmp(p->pipedir[1 + !d1].name, d->name, KNAMELEN) == 0)
			error(EEXIST, NULL);
		strncpy(p->pipedir[1 + d1].name, d->name, KNAMELEN);
	}
	if (d->mode != ~0UL)
		p->pipedir[d1 + 1].perm = d->mode & 0777;
	poperror();
	kfree(d);
	return n;
}

struct dev pipedevtab __devtab = {
	"pipe",

	devreset,
	pipeinit,
	devshutdown,
	pipeattach,
	pipewalk,
	pipestat,
	pipeopen,
	devcreate,
	pipeclose,
	piperead,
	pipebread,
	pipewrite,
	pipebwrite,
	devremove,
	pipewstat,
	devpower,
	devchaninfo,
};
