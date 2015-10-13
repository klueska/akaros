/*
 * Copyright (c) 2015 The Regents of the University of California
 * Valmon Leymarie <leymariv@berkeley.edu>
 * Kevin Klues <klueska@cs.berkeley.edu>
 * See LICENSE for details.
 */

#ifndef AKAROS_KERN_PACKED_COREALLOC_H
#define AKAROS_KERN_PACKED_COREALLOC_H

/* Forward declare from packed_corealloc.c */
struct sched_pnode;

/* The core request algorithm maintains an internal array of these: the
 * global pcore map. Note the prov_proc and alloc_proc are weak (internal)
 * references, and should only be used as a ref source while the ksched has a
 * valid kref. */
struct sched_pcore {
	TAILQ_ENTRY(sched_pcore)   prov_next;    /* on a proc's prov list */
	TAILQ_ENTRY(sched_pcore)   alloc_next;   /* on an alloc list (idle)*/
	struct proc                *prov_proc;   /* who this is prov to */
	struct proc                *alloc_proc;  /* who this is alloc to */
	struct sched_pnode         *spn;
	struct core_info           *spc_info;
};
TAILQ_HEAD(sched_pcore_tailq, sched_pcore);

struct core_request_data {
	struct sched_pcore_tailq  alloc_me;           /* cores alloced to us */
	struct sched_pcore_tailq  prov_alloc_me;      /* prov cores alloced us */
	struct sched_pcore_tailq  prov_not_alloc_me;  /* maybe alloc to others */
};

static inline uint32_t spc2pcoreid(struct sched_pcore *spc)

{
	return spc->spc_info->core_id;
}

static inline struct sched_pcore *pcoreid2spc(uint32_t pcoreid)
{
	extern struct sched_pcore *all_pcores;
	return &all_pcores[pcoreid];
}

static inline struct proc *get_alloc_proc(struct sched_pcore *c)
{
	return c->alloc_proc;
}

static inline struct proc *get_prov_proc(struct sched_pcore *c)
{
	return c->prov_proc;
}

#endif // AKAROS_KERN_PACKED_CORERALLOC_H
