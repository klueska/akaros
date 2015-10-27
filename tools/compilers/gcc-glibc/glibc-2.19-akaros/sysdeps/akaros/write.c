/* Copyright (C) 1991, 1995, 1996, 1997, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sysdep.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <parlib/event.h>
#include <ros/syscall.h>

#define unlikely(x) __builtin_expect(!!(x), 0)

/* Write NBYTES of BUF to FD. Return the number written, or -1. Since signals
 * are a user-space construct in Akaros, handle the SIGPIPE case as well. */
ssize_t __libc_write(int fd, const void *buf, size_t nbytes)
{
	int ret = ros_syscall(SYS_write, fd, buf, nbytes, 0, 0, 0);

	if (unlikely((ret != 0) && (errno == EPIPE))) {
		sigset_t mask;

		sigprocmask(0, NULL, &mask);
		if (!__sigismember(&mask, SIGPIPE)) {
			struct event_msg msg = {0};

			msg.ev_type = EV_POSIX_SIGNAL;
			msg.ev_arg1 = SIGPIPE;
			ros_syscall(SYS_self_notify, -1, EV_POSIX_SIGNAL, &msg, 0, 0, 0);
		}
	}
	return ret;
}
libc_hidden_def (__libc_write)

weak_alias (__libc_write, __write)
libc_hidden_weak (__write)
weak_alias (__libc_write, write)
