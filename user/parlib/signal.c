/* Copyright (c) 2013 The Regents of the University of California
 * Barret Rhoden <brho@cs.berkeley.edu>
 * Kevin Klues <klueska@cs.berkeley.edu>
 * See LICENSE for details.
 *
 * POSIX signal handling glue.  All glibc programs link against parlib, so they
 * will get this mixed in.  Mostly just registration of signal handlers.
 *
 * POSIX signal handling caveats:
 * 	- We don't copy signal handling tables or anything across forks or execs
 *	- We don't send meaningful info in the siginfos, nor do we pass pid/uids on
 *	signals coming from a kill.  This is especially pertinent for sigqueue,
 *	which needs a payload (value) and sending PID
 * 	- We run handlers in vcore context, so any blocking syscall will spin.
 * 	Regular signals have restrictions on their syscalls too, though not this
 * 	great.  We could spawn off a uthread to run the handler, given that we have
 * 	a 2LS (which we don't for SCPs).
 * 	- We don't do anything with signal blocking/masking.  When in a signal
 * 	handler, you won't get interrupted with another signal handler (so long as
 * 	you run it in vcore context!).  With uthreads, you could get interrupted.
 * 	There is also no process wide signal blocking yet (sigprocmask()).  If this
 * 	is desired, we can abort certain signals when we h_p_signal(), 
 * 	- Likewise, we don't do waiting for particular signals yet.  Just about the
 * 	only thing we do is allow the registration of signal handlers. 
 * 	- Check each function for further notes.  */

#include <sched.h>
#include <signal.h>
#include <stdio.h>

#include <parlib/parlib.h>
#include <parlib/event.h>
#include <errno.h>
#include <parlib/assert.h>
#include <ros/procinfo.h>
#include <ros/syscall.h>
#include <sys/mman.h>
#include <parlib/vcore.h> /* for print_user_context() */
#include <parlib/waitfreelist.h>
#include <parlib/stdio.h>

/* This is list of sigactions associated with each posix signal. */
static struct sigaction sigactions[_NSIG];

/* This is the default global sigmask. */
static sigset_t sigmask;

/* Forward declare some functions. */
static int __sigprocmask(int __how, __const sigset_t *__restrict __set,
                         sigset_t *__restrict __oset);
static void __incoming_signal(int signo);

/* The default definition of signal_ops (similar to sched_ops in uthread.c) */
struct signal_ops default_signal_ops = {
	.sigprocmask = __sigprocmask,
	.incoming_signal = __incoming_signal,
};
struct signal_ops *signal_ops = &default_signal_ops;

/* This is a wait-free-list used to hold the data necessary to execute signal
 * handlers inside a 2LS. We are able to store them in a wfl because all
 * sigdata structs are created equal, and reuse is encouraged as uthreads
 * ask for them on demand. */
static struct wfl sigdata_list;
#define SIGNAL_STACK_SIZE (2*PGSIZE + sizeof(struct sigdata))

/* These are the default handlers for each posix signal.  They are listed in
 * SIGNAL(7) of the Linux Programmer's Manual.  We run them as default
 * sigactions, instead of the older handlers, so that we have access to the
 * faulting context.
 *
 * Exit codes are set as suggested in the following link.  I wish I could find
 * the definitive source, but this will have to do for now.
 * http://unix.stackexchange.com/questions/99112/default-exit-code-when-process-is-terminated
 * */
static void default_term_handler(int signr, siginfo_t *info, void *ctx)
{
	ros_syscall(SYS_proc_destroy, __procinfo.pid, signr, 0, 0, 0, 0);
}

static void default_core_handler(int signr, siginfo_t *info, void *ctx)
{
	printf("Segmentation Fault (sorry, no core dump yet)\n");
	if (ctx)
		print_user_context((struct user_context*)ctx);
	else
		printf("No ctx for %s\n", __func__);
	if (info) {
		/* ghetto, we don't have access to the PF err, since we only have a few
		 * fields available in siginfo (e.g. there's no si_trapno). */
		printf("Fault type %d at addr %p\n", info->si_errno,
		        info->si_addr);
	} else {
		printf("No fault info\n");
	}
	default_term_handler((1 << 7) + signr, info, ctx);
}

static void default_stop_handler(int signr, siginfo_t *info, void *ctx)
{
	printf("Stop signal received!  No support to stop yet though!\n");
}

static void default_cont_handler(int signr, siginfo_t *info, void *ctx)
{
	printf("Cont signal received!  No support to cont yet though!\n");
}

typedef void (*__sigacthandler_t)(int, siginfo_t *, void *);
#define SIGACT_ERR	((__sigacthandler_t) -1)	/* Error return.  */
#define SIGACT_DFL	((__sigacthandler_t) 0)		/* Default action.  */
#define SIGACT_IGN	((__sigacthandler_t) 1)		/* Ignore signal.  */

static __sigacthandler_t default_handlers[] = {
	[SIGHUP]    = default_term_handler, 
	[SIGINT]    = default_term_handler, 
	[SIGQUIT]   = default_core_handler, 
	[SIGILL]    = default_core_handler, 
	[SIGTRAP]   = default_core_handler, 
	[SIGABRT]   = default_core_handler, 
	[SIGIOT]    = default_core_handler, 
	[SIGBUS]    = default_core_handler, 
	[SIGFPE]    = default_core_handler, 
	[SIGKILL]   = default_term_handler, 
	[SIGUSR1]   = default_term_handler, 
	[SIGSEGV]   = default_core_handler, 
	[SIGUSR2]   = default_term_handler, 
	[SIGPIPE]   = default_term_handler, 
	[SIGALRM]   = default_term_handler, 
	[SIGTERM]   = default_term_handler, 
	[SIGSTKFLT] = default_term_handler, 
	[SIGCHLD]   = SIGACT_IGN,
	[SIGCONT]   = default_cont_handler, 
	[SIGSTOP]   = default_stop_handler, 
	[SIGTSTP]   = default_stop_handler, 
	[SIGTTIN]   = default_stop_handler, 
	[SIGTTOU]   = default_stop_handler, 
	[SIGURG]    = default_term_handler, 
	[SIGXCPU]   = SIGACT_IGN,
	[SIGXFSZ]   = default_core_handler, 
	[SIGVTALRM] = default_term_handler, 
	[SIGPROF]   = default_term_handler, 
	[SIGWINCH]  = SIGACT_IGN,
	[SIGIO]     = default_term_handler, 
	[SIGPWR]    = SIGACT_IGN,
	[SIGSYS]    = default_core_handler,
	[SIGSYS+1 ... _NSIG-1] = SIGACT_IGN
};

/* This function allocates a sigdata struct for use when running signal
 * handlers inside a 2LS. The sigdata struct returned is pre-initialized with
 * the 'stack' field pointing to a valid stack.  Space is allocated for both
 * the sigdata struct and the stack in a single mmap call.  The sigdata struct
 * just sits at the bottom of the stack, and its 'stack' field points just
 * above it.  */
struct sigdata *alloc_sigdata()
{
	struct sigdata *data = wfl_remove(&sigdata_list);
	if (data == NULL) {
		void *stack = mmap(0, SIGNAL_STACK_SIZE,
		                   PROT_READ|PROT_WRITE|PROT_EXEC,
		                   MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
		assert(stack != MAP_FAILED);
		data = stack + SIGNAL_STACK_SIZE - sizeof(struct sigdata);
		data->stack = data;
	}
	return data;
}

/* This function frees a previously allocated sigdata struct. */
void free_sigdata(struct sigdata *sigdata)
{
	wfl_insert(&sigdata_list, sigdata);
}

/* This is the akaros posix signal trigger.  Signals are dispatched from
 * this function to their proper posix signal handler */
void trigger_posix_signal(int sig_nr, struct siginfo *info, void *aux)
{
	struct sigaction *action;
	if (sig_nr >= _NSIG || sig_nr < 0)
		return;
	action = &sigactions[sig_nr];
	/* Would like a switch/case here, but they are pointers.  We can also get
	 * away with this check early since sa_handler and sa_sigaction are macros
	 * referencing the same union.  The man page isn't specific about whether or
	 * not you need to care about SA_SIGINFO when sending DFL/ERR/IGN. */
	if (action->sa_handler == SIG_ERR)
		return;
	if (action->sa_handler == SIG_IGN)
		return;
	if (action->sa_handler == SIG_DFL) {
		if (default_handlers[sig_nr] != SIGACT_IGN)
			default_handlers[sig_nr](sig_nr, info, aux);
		return;
	}

	if (action->sa_flags & SA_SIGINFO) {
		/* If NULL info struct passed in, construct our own */
		struct siginfo s = {0};
		if (info == NULL)
			info = &s;
		/* Make sure the caller either already set singo in the info struct, or
		 * if they didn't, make sure it has been zeroed out (i.e. not just some
		 * garbage on the stack. */
		assert(info->si_signo == sig_nr || info->si_signo == 0);
		info->si_signo = sig_nr;
		/* TODO: consider info->pid and whatnot */
		/* We assume that this function follows the proper calling convention
		 * (i.e. it wasn't written in some crazy assembly function that
		 * trashes all its registers, i.e GO's default runtime handler) */
		action->sa_sigaction(sig_nr, info, aux);
	} else {
		action->sa_handler(sig_nr);
	}
}

/* This is the catch all akaros event->posix signal handler.  All posix signals
 * are received in a single akaros event type.  They are then dispatched from
 * this function to their proper posix signal handler */
static void handle_event(struct event_msg *ev_msg, unsigned int ev_type,
                         void *data)
{
	assert(ev_msg);
	signal_ops->incoming_signal(ev_msg->ev_arg1);
}

static void __incoming_signal(int sig_nr)
{
	if (!__sigismember(&sigmask, sig_nr)) {
		struct siginfo info = {0};

		info.si_code = SI_USER;
		trigger_posix_signal(sig_nr, &info, 0);
	}
}

/* Called from uthread_slim_init() */
void init_posix_signals(void)
{
	struct event_queue *posix_sig_ev_q;

	register_ev_handler(EV_POSIX_SIGNAL, handle_event, 0);
	posix_sig_ev_q = get_eventq(EV_MBOX_UCQ);
	assert(posix_sig_ev_q);
	posix_sig_ev_q->ev_flags = EVENT_IPI | EVENT_INDIR | EVENT_SPAM_INDIR |
	                           EVENT_WAKEUP;
	register_kevent_q(posix_sig_ev_q, EV_POSIX_SIGNAL);
	sigmask = 0;
	wfl_init(&sigdata_list);
}

int sigaddset(sigset_t *__set, int __signo)
{
	if (__signo == 0 || __signo >= _NSIG) {
		errno = EINVAL;
		return -1;
	}
	__sigaddset(__set, __signo);
	return 0;
}

int sigdelset(sigset_t *__set, int __signo)
{
	if (__signo == 0 || __signo >= _NSIG) {
		errno = EINVAL;
		return -1;
	}
	__sigdelset(__set, __signo);
	return 0;
}

int sigismember(__const sigset_t *__set, int __signo)
{
	if (__signo == 0 || __signo >= _NSIG) {
		errno = EINVAL;
		return -1;
	}
	__sigismember(__set, __signo);
	return 0;
}

static int __sigprocmask(int how, __const sigset_t *__restrict set,
                         sigset_t *__restrict oset)
{
	if (set && (how != SIG_BLOCK) &&
	           (how != SIG_SETMASK) &&
	           (how != SIG_UNBLOCK)) {
		errno = EINVAL;
		return -1;
	}

	if (oset)
		*oset = sigmask;
	if (set) {
		switch (how) {
			case SIG_BLOCK:
				sigmask = sigmask | *set;
				break;
			case SIG_SETMASK:
				sigmask = *set;
				break;
			case SIG_UNBLOCK:
				sigmask = sigmask & ~(*set);
				break;
		}
	}
	/* Ensures signals we just unmasked get processed if they are pending */
	sched_yield();
	return 0;
}

int sigprocmask(int __how, __const sigset_t *__restrict __set,
                sigset_t *__restrict __oset)
{
	return signal_ops->sigprocmask(__how, __set, __oset);
}

/* Could do this with a loop on delivery of the signal, sleeping and getting
 * woken up by the kernel on any event, like we do with async syscalls. */
int sigsuspend(__const sigset_t *__set)
{
	return 0;
}

int sigaction(int __sig, __const struct sigaction *__restrict __act,
              struct sigaction *__restrict __oact)
{
	if (__sig >= _NSIG || __sig < 0)
		return -1;
	if (__oact) {
		*__oact = sigactions[__sig];
	}
	if (!__act)
		return 0;
	sigactions[__sig] = *__act;
	return 0;
}

/* Not really possible or relevant - you'd need to walk/examine the event UCQ */
int sigpending(sigset_t *__set)
{
	return 0;
}

/* Can be done similar to sigsuspend */
int sigwait(__const sigset_t *__restrict __set, int *__restrict __sig)
{
	return 0;
}

/* Can be done similar to sigsuspend */
int sigwaitinfo(__const sigset_t *__restrict __set,
                siginfo_t *__restrict __info)
{
	return 0;
}

/* Can be done similar to sigsuspend, with an extra alarm syscall */
int sigtimedwait(__const sigset_t *__restrict __set,
                 siginfo_t *__restrict __info,
                 __const struct timespec *__restrict __timeout)
{
	return 0;
}

/* Needs support with trigger_posix_signal to deal with passing values with POSIX
 * signals. */
int sigqueue(__pid_t __pid, int __sig, __const union sigval __val)
{
	return 0;
}

/* Old BSD interface, deprecated */
int sigvec(int __sig, __const struct sigvec *__vec, struct sigvec *__ovec)
{
	return 0;
}

/* Linux specific, and not really needed for us */
int sigreturn(struct sigcontext *__scp)
{
	return 0;
}

/* Akaros can't have signals interrupt syscalls to need a restart, though we can
 * re-wake-up the process while it is waiting for its syscall. */
int siginterrupt(int __sig, int __interrupt)
{
	return 0;
}

/* This is managed by vcore / 2LS code */
int sigstack(struct sigstack *__ss, struct sigstack *__oss)
{
	return 0;
}

/* This is managed by vcore / 2LS code */
int sigaltstack(__const struct sigaltstack *__restrict __ss,
                struct sigaltstack *__restrict __oss)
{
	return 0;
}

__sighandler_t signal(int sig, __sighandler_t handler)
{
	int ret;
	struct sigaction newsa = {0};
	struct sigaction oldsa = {0};
	newsa.sa_handler = handler;
	ret = sigaction(sig, &newsa, &oldsa);
	if (ret < 0) {
		errno = EINVAL;
		return SIG_ERR;
	}
	return oldsa.sa_handler;
}
