/*******************************************************************************
  Copyright (c) 2015-2016 Vladimir Kondratyev <wulf@cicgroup.ru>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*******************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "sys/signalfd.h"
#include "worker.h"
#include "utils.h"

typedef struct signalfd {
	sigset_t set;
	int sig;
} signalfd_t;

#define MAX_SIGNUM	NSIG
#define	NO_SIG		0

static void  signalfd_read_handler(event_t *ev, int flags);
static int   signalfd_write_handler(event_t *ev, uint64_t sig);
static void  signalfd_kevent_handler(event_t *ev, const struct kevent *ke);
static void  signalfd_free_handler(event_t *ev, int flags);
static void *signalfd_get_readvalue(event_t *ev);

static eventdesc_t signalfddesc = {
	.name		= "signalfd",
	.readsize	= sizeof(struct signalfd_siginfo),
	.datasize	= sizeof(signalfd_t),
	.read_handler	= signalfd_read_handler,
	.write_handler	= signalfd_write_handler,
	.kevent_handler	= signalfd_kevent_handler,
	.free_handler	= signalfd_free_handler,
	.get_readvalue	= signalfd_get_readvalue
};
#define SIGNALFD (&signalfddesc)

static int signalfd_initialized = 0;
static struct signalfd_siginfo ss[MAX_SIGNUM];
static sigset_t pending;
static sigset_t registered;
static event_t dummy = {
	.des = SIGNALFD,
	.io = { 0, 0 }
};

void
signalfd_ignhandler()
{
	/* DO NOTHING */
}

static const int signals_ign[] =
    { SIGURG, SIGCONT, SIGCHLD, SIGIO, SIGWINCH, SIGINFO };
#define	NSIGNALS_IGN	(sizeof(signals_ign) / sizeof(*signals_ign))
#define	SFD_SET		0
#define	SFD_RESET	1

void
signalfd_set_ignhandler(int sig, int action)
{
	size_t i;
	struct sigaction sa;
	void *hdl_from, *hdl_to;

	hdl_from = action == SFD_SET ? SIG_DFL : &signalfd_ignhandler;
	hdl_to = action == SFD_SET ? &signalfd_ignhandler : SIG_DFL;

	for (i = 0; i < NSIGNALS_IGN; i++) {
		if (sig == signals_ign[i] &&
		    sigaction(sig, NULL, &sa) != -1 &&
		    sa.sa_handler == hdl_from) {
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = hdl_to;
			sa.sa_flags = SA_RESTART;
			sigaction(sig, &sa, NULL);
			DBG(&dummy,
			    "'do nothing' handler %s for signal %d (%s)",
			    action == SFD_SET ? "installed" : "removed",
			    sig, strsignal(sig));
			break;
		}
	}
}

static void
signalfd_dumpsigset(event_t *ev, const sigset_t *set)
{
	int sig;
	char buf[MAX_SIGNUM];

	for (sig = 1; sig < MAX_SIGNUM; sig++)
		buf[sig - 1] = sigismember(set, sig) ? 'X' : '.';
	buf[MAX_SIGNUM - 1] = 0;
	if (ev == NULL)
		LOG(1, "sigset: %s", buf);
	else
		DBG(ev, "sigset: %s", buf);
}

static void
signalfd_dumpsiginfo(struct signalfd_siginfo *ssi)
{
	DBG(&dummy, "signalfd_siginfo:");
	DBG(&dummy, "  ssi_signo:   %"PRIu32, ssi->ssi_signo);
	DBG(&dummy, "  ssi_errno:   %"PRIi32, ssi->ssi_errno);
	DBG(&dummy, "  ssi_code:    %"PRIi32, ssi->ssi_code);
	DBG(&dummy, "  ssi_pid:     %"PRIu32, ssi->ssi_pid);
	DBG(&dummy, "  ssi_uid:     %"PRIu32, ssi->ssi_uid);
	DBG(&dummy, "  ssi_fd:      %"PRIi32, ssi->ssi_fd);
	DBG(&dummy, "  ssi_tid:     %"PRIu32, ssi->ssi_tid);
	DBG(&dummy, "  ssi_band:    %"PRIu32, ssi->ssi_band);
	DBG(&dummy, "  ssi_overrun: %"PRIu32, ssi->ssi_overrun);
	DBG(&dummy, "  ssi_trapno:  %"PRIu32, ssi->ssi_trapno);
	DBG(&dummy, "  ssi_status:  %"PRIi32, ssi->ssi_status);
	DBG(&dummy, "  ssi_int:     %"PRIi32, ssi->ssi_int);
	DBG(&dummy, "  ssi_ptr:     0x%"PRIx64, ssi->ssi_ptr);
	DBG(&dummy, "  ssi_utime:   %"PRIu64, ssi->ssi_utime);
	DBG(&dummy, "  ssi_stime:   %"PRIu64, ssi->ssi_stime);
	DBG(&dummy, "  ssi_addr:    0x%"PRIx64, ssi->ssi_addr);
}

static void
siginfo_to_signalfd(const siginfo_t *si, struct signalfd_siginfo *ssi)
{

	memset(ssi, 0, sizeof(struct signalfd_siginfo));
	ssi->ssi_signo =	si->si_signo;
	ssi->ssi_errno =	si->si_errno;
	ssi->ssi_code =		si->si_code;
	ssi->ssi_pid =		si->si_pid;
	ssi->ssi_uid =		si->si_uid;
	ssi->ssi_fd =		-1;	/* Linux specific */
	ssi->ssi_int =		si->si_value.sival_int;
	ssi->ssi_ptr =		(uint64_t)si->si_value.sival_ptr;
	ssi->ssi_utime =	0;	/* Linux specific */
	ssi->ssi_stime =	0;	/* Linux specific */
	ssi->ssi_addr =		(uint64_t)si->si_addr;
	ssi->ssi_status =	si->si_status;
	ssi->ssi_band =		si->si_band;
	ssi->ssi_trapno =	si->si_trapno;
	ssi->ssi_tid =		si->si_timerid;
	ssi->ssi_overrun =	si->si_overrun;
}

static void
signalfd_init(void)
{
	sigemptyset(&registered);
	sigemptyset(&pending);
	signalfd_initialized = 1;
}

static int
signalfd_setkevents(sigset_t *set)
{
	struct kevent ke;
	int sig;
	ushort flags;

	for (sig = 1; sig < MAX_SIGNUM; sig++) {
		flags = 0;
		if (sigismember(set, sig) && !sigismember(&registered, sig))
			flags = EV_ADD;
		if (!sigismember(set, sig) && sigismember(&registered, sig))
			flags = EV_DELETE;
		if (flags == 0)
			continue;
		EV_SET(&ke, sig, EVFILT_SIGNAL, flags, 0, 0, &dummy);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) {
			ERR(&dummy, "failed to register signal %d kevent", sig);
			return (-1);
		}
		switch (flags) {
		case EV_ADD:
			sigaddset(&registered, sig);
			signalfd_set_ignhandler(sig, SFD_SET);
			break;
		case EV_DELETE:
			sigdelset(&registered, sig);
			sigdelset(&pending, sig);
			signalfd_set_ignhandler(sig, SFD_RESET);
			break;
		}
	}
	return (0);
}

void
sigunionset (sigset_t *set1, const sigset_t *set2)
{
	int sig;

	for (sig = 1; sig < MAX_SIGNUM; sig++)
		if (sigismember(set2, sig))
			sigaddset(set1, sig);
}

void
signalfd_maskunion(sigset_t *set)
{
	event_t *ev;
	signalfd_t *sg;

	sigemptyset(set);

	/* EVENTLIST_LOCK(); */
	SLIST_FOREACH(ev, &events, next) {
		if (ev->des == SIGNALFD) {
			sg = get_data(ev);
			sigunionset(set, &sg->set);
		}
	}
	/* EVENTLIST_UNLOCK(); */
}

static void
signalfd_get_pending(event_t *ev)
{
	signalfd_t *sg;
	int sig;

	sg = get_data(ev);
	sg->sig = NO_SIG;
	ev->readable = 0;
	for (sig = 1; sig < MAX_SIGNUM; sig++) {
		if (sigismember(&pending, sig)) {
			sg->sig = sig;
			ev->readable = 1;
			return;
		}
	}
}

static void
signalfd_read_handler(event_t *ev, int flags)
{
	event_t *listev;
	signalfd_t *sg, *listsg;

	sg = get_data(ev);
	assert(sg->sig != NO_SIG);

	sigdelset(&pending, sg->sig);
	/* EVENTLIST_LOCK(); */
	SLIST_FOREACH(listev, &events, next) {
		if (ev == listev || listev->des != SIGNALFD)
			continue;

		listsg = get_data(listev);
		if (listsg->sig == sg->sig &&
		    clear_readbuf(listev, NULL) == 0)
			ERR(ev, "RACE: siginfo has been read 2 or more times");
	}
	/* EVENTLIST_UNLOCK(); */

	signalfd_get_pending(ev);
}

static int
signalfd_write_handler(event_t *ev, uint64_t sig)
{
	signalfd_t *sg;

	sg = get_data(ev);
	sg->sig = sig;
	ev->readable = 1;

	return (1);
}

static void
signalfd_kevent_handler(event_t *dummyev, const struct kevent *ke)
{
	event_t *ev;
	signalfd_t *sg;
	sigset_t set;
	siginfo_t info;
	struct signalfd_siginfo ssi;
	struct timespec timeout;
	int sig, siginfo_changed = 0;

	sig = ke->ident;
	DBG(dummyev, "kevent: signal %d (%s)", sig, strsignal(sig));

	sigemptyset(&set);
	sigaddset(&set, sig);
	timespecclear(&timeout);

	if (sigtimedwait(&set, &info, &timeout) == -1) {
		/* Siginfo fails when sigaction is set to "ignore" */
		ERR(dummyev, "failed to get siginfo");
		info.si_signo = sig;
	}
	assert(info.si_signo == sig);
	siginfo_to_signalfd(&info, &ssi);
	signalfd_dumpsiginfo(&ssi);
	if (memcmp(&ssi, &ss[sig - 1], sizeof(ssi)) != 0) {
		memcpy(&ss[sig - 1], &ssi, sizeof(ssi));
		siginfo_changed = 1;
	}
	sigaddset(&pending, sig);

	/* Broadcast signalinfo to readers */
	/* EVENTLIST_LOCK(); */
	SLIST_FOREACH(ev, &events, next) {
		if (ev->des != SIGNALFD)
			continue;
		sg = get_data(ev);
		if (sigismember(&sg->set, sig) &&
		    (sg->sig == NO_SIG || sg->sig > sig ||
		    (sg->sig == sig && siginfo_changed)))
			clobber_readbuf(ev, sig);
	}
	/* EVENTLIST_UNLOCK(); */
}

static void
signalfd_free_handler(event_t *ev, int flags)
{
	sigset_t set;
	signalfd_t *sg;
	int sig;

	if (flags & EV_CLEANUPCHILD) {
		for (sig = 1; sig < MAX_SIGNUM; sig++)
			if (sigismember(&registered, sig))
				signalfd_set_ignhandler(sig, SFD_RESET);
		signalfd_init();
	} else {
		sg = get_data(ev);
		sigemptyset(&sg->set);
		signalfd_maskunion(&set);
		signalfd_setkevents(&set);
	}
}

static void *
signalfd_get_readvalue(event_t *ev)
{
	signalfd_t *sg;

	sg = get_data(ev);
	return (&ss[sg->sig - 1]);
}

static int
signalfd_update(event_t *ev, void *data)
{
	signalfd_t *sg;
	sigset_t set;

	sg = get_data(ev);
	if (!sigismember(data, sg->sig) && sigismember(&sg->set, sg->sig)) {
		clear_readbuf(ev, NULL);
		signalfd_get_pending(ev);
		fill_readbuf(ev);
	}
	sg->set = *(sigset_t *)data;
	signalfd_maskunion(&set);
	signalfd_setkevents(&set);
	return (0);
}

static int
signalfd_add(event_t *ev, void *data)
{
	signalfd_t *sg;
	sigset_t set;

	sg = get_data(ev);
	set = registered;
	sigunionset(&set, &sg->set);
	return (signalfd_setkevents(&set));
}

static int
signalfd_create(const sigset_t *set, int flags)
{
	int fd;
	event_t *ev;
	signalfd_t *sg;

	ev = event_init(SIGNALFD);
	if (ev == NULL)
		return (-1);

	if (flags & (SFD_NONBLOCK | O_NONBLOCK))
		ev->flags |= EV_NONBLOCK;
	if (flags & (SFD_CLOEXEC | O_CLOEXEC))
		ev->flags |= EV_CLOEXEC;

	sg = get_data(ev);
	sg->set = *set;
	sg->sig = NO_SIG;
	fd = event_insert(ev);
	if (fd == -1)
		return (fd);

	if (event_exec(ev, signalfd_add, NULL) == -1) {
		close(fd);
		return (-1);
	}

	shutdown(fd, SHUT_WR);
	return (fd);
}

EXPORT int
signalfd(int fd, const sigset_t *set, int flags)
{
	event_t *ev;

	LOG(1, ">>>>>>>> signalfd(%d, sigset, %d)", fd, flags);
	signalfd_dumpsigset(NULL, set);

	if (flags & ~(SFD_NONBLOCK|O_NONBLOCK|SFD_CLOEXEC|O_CLOEXEC)) {
		errno = EINVAL;
		return (-1);
	}

	if (fd != -1 && fd_valid(fd))
		return (-1);

	if (mem_valid(set, sizeof(sigset_t)))
		return (-1);

	if (fd != -1) {
		ev = event_find(fd, SIGNALFD);
		if (ev == NULL)
			return (-1);
		EVENTLIST_UNLOCK();

		if (event_exec(ev, signalfd_update, (void *)set) == -1)
			return (-1);

		ev = event_find(fd, SIGNALFD);
		if (ev == NULL)
			return (-1);
		set_cloexec_flag(fd, flags & (SFD_CLOEXEC | O_CLOEXEC));
		set_nonblock_flag(fd, flags & (SFD_NONBLOCK | O_NONBLOCK));
		tune_blockmode(ev, flags & (SFD_NONBLOCK | O_NONBLOCK));
		EVENTLIST_UNLOCK();
		return (fd);
	}

	if (!signalfd_initialized)
		signalfd_init();

	fd = signalfd_create(set, flags);

	return (fd);
}
