/*-
 * Copyright (c) 2007 Roman Divacky
 * Copyright (c) 2014 Dmitry Chagin
 * Copyright (c) 2015-2016 Vladimir Kondratyev <wulf@cicgroup.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/selinfo.h>
#include <sys/timespec.h>

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sys/epoll.h"
#include "utils.h"

/*
 * epoll defines 'struct epoll_event' with the field 'data' as 64 bits
 * on all architectures. But on 32 bit architectures BSD 'struct kevent' only
 * has 32 bit opaque pointer as 'udata' field. So we can't pass epoll supplied
 * data verbatuim. Therefore we allocate 64-bit memory block to pass
 * user supplied data for every file descriptor.
 */

struct epoll_emuldata {
	uint32_t	fdc;		/* epoll udata max index */
	epoll_data_t	udata[1];	/* epoll user data vector */
};

#define	EPOLL_DEF_SZ		16
#define	EPOLL_SIZE(fdn)			\
	(sizeof(struct epoll_emuldata)+(fdn) * sizeof(epoll_data_t))

#define	LINUX_MAX_EVENTS	(INT_MAX / sizeof(struct epoll_event))

#define	EPOLL_EVRD	(EPOLLIN|EPOLLRDNORM|EPOLLHUP|EPOLLERR|EPOLLPRI)
#define	EPOLL_EVWR	(EPOLLOUT|EPOLLWRNORM)
#define	EPOLL_EVSUP	(EPOLLET|EPOLLONESHOT|EPOLL_EVRD|EPOLL_EVWR)

/* process emuldata flags */
#define LINUX_XUNSUP_EPOLL      0x00000002      /* unsupported epoll events */

struct linux_pemuldata {
	uint32_t	flags;		/* process emuldata flags */
	sem_t		pem_sx;		/* lock for this struct */
	void		*epoll;		/* epoll data */
};

static struct linux_pemuldata pem;

#define LINUX_PEM_XLOCK(p) do {						\
	do { /* NOTHING */						\
	} while (sem_wait(&(p).pem_sx) == -1 && errno == EINTR);	\
	assert(sem_value(&(p).pem_sx) == 0);				\
} while (0)
#define LINUX_PEM_XUNLOCK(p) do {					\
	assert(sem_value(&(p).pem_sx) == 0);				\
	sem_post(&(p).pem_sx);						\
} while (0)
#define LINUX_PEM_SLOCK(p)	LINUX_PEM_XLOCK(p)
#define LINUX_PEM_SUNLOCK(p)	LINUX_PEM_XUNLOCK(p)
#define LINUX_PEM_ISLOCKED(p)	(sem_value(&(p).pem_sx) == 0)

static void	epoll_cleanup_child();
static int	epoll_fd_install(int fd, epoll_data_t udata);
static int	epoll_to_kevent(int epfd, int fd, struct epoll_event *l_event,
		    int *kev_flags, struct kevent *kevent, int *nkevents);
static void	kevent_to_epoll(struct kevent *kevent, struct epoll_event *l_event);
static int	epoll_delete_event(int epfd, int fd, int filter);
static int	epoll_delete_all_events(int epfd, int fd);

pthread_once_t once_epoll_init = PTHREAD_ONCE_INIT;

static void
epoll_cleanup_child()
{

	if (LINUX_PEM_ISLOCKED(pem))
		LINUX_PEM_XUNLOCK(pem);
}

static void
epoll_init(void)
{

	pem = (struct linux_pemuldata) {
		.flags = 0,
		.epoll = NULL
	};
	sem_init(&pem.pem_sx, 0, 1);
	pthread_atfork(NULL, NULL, epoll_cleanup_child);
	epoll_fd_install(EPOLL_DEF_SZ, (epoll_data_t)0);
}

static int
epoll_fd_install(int fd, epoll_data_t udata)
{
	struct epoll_emuldata *emd;
	int error;

	LINUX_PEM_XLOCK(pem);
	if (pem.epoll == NULL) {
		emd = malloc(EPOLL_SIZE(fd));
		if (emd == NULL) {
			error = -1;
			goto leave;
		}
		emd->fdc = fd;
		pem.epoll = emd;
	} else {
		emd = pem.epoll;
		if (fd > emd->fdc) {
			emd = realloc(emd, EPOLL_SIZE(fd));
			if (emd == NULL) {
				error = -1;
				goto leave;
			}
			emd->fdc = fd;
			pem.epoll = emd;
		}
	}
	emd->udata[fd] = udata;
	error = 0;
leave:
	LINUX_PEM_XUNLOCK(pem);

	return (error);
}

static int
epoll_create_common(int flags)
{
	int kq;

	kq = kqueue();

	if (kq != -1) {
		pthread_once(&once_epoll_init, epoll_init);
		fcntl(kq, F_SETFD, flags);
	}

	return (kq);
}

EXPORT int
epoll_create(int size)
{

	/*
	 * args->size is unused. Linux just tests it
	 * and then forgets it as well.
	 */
	if (size <= 0) {
		errno = EINVAL;
		return (-1);
	}

	return (epoll_create_common(0));
}

EXPORT int
epoll_create1(int l_flags)
{
	int flags;

	if ((l_flags & ~(EPOLL_CLOEXEC)) != 0) {
		errno = EINVAL;
		return (-1);
	}

	flags = 0;
	if ((l_flags & EPOLL_CLOEXEC) != 0)
		flags |= FD_CLOEXEC;

	return (epoll_create_common(flags));
}

/* Structure converting function from epoll to kevent. */
static int
epoll_to_kevent(int epfd, int fd, struct epoll_event *l_event, int *kev_flags,
    struct kevent *kevent, int *nkevents)
{
	uint32_t levents = l_event->events;

	/* flags related to how event is registered */
	if ((levents & EPOLLONESHOT) != 0)
#if defined (EV_DISPATCH) && defined(PEDANTIC_CHECKS)
		/* one-shotness does not remove the epoll descriptor */
		*kev_flags |= EV_DISPATCH;
#else
		*kev_flags |= EV_ONESHOT;
#endif
	if ((levents & EPOLLET) != 0)
		*kev_flags |= EV_CLEAR;
	if ((levents & EPOLLERR) != 0)
		*kev_flags |= EV_ERROR;
	if ((levents & EPOLLRDHUP) != 0)
		*kev_flags |= EV_EOF;

	/* flags related to what event is registered */
	if ((levents & EPOLL_EVRD) != 0) {
		EV_SET(kevent++, fd, EVFILT_READ, *kev_flags, 0, 0, 0);
		++(*nkevents);
	}
	if ((levents & EPOLL_EVWR) != 0) {
		EV_SET(kevent++, fd, EVFILT_WRITE, *kev_flags, 0, 0, 0);
		++(*nkevents);
	}

	if ((levents & ~(EPOLL_EVSUP)) != 0) {

		assert(pem.epoll != NULL);

		LINUX_PEM_XLOCK(pem);
		if ((pem.flags & LINUX_XUNSUP_EPOLL) == 0) {
			pem.flags |= LINUX_XUNSUP_EPOLL;
			LINUX_PEM_XUNLOCK(pem);
			printf("epoll_ctl unsupported flags: 0x%x\n",
			    levents);
		} else
			LINUX_PEM_XUNLOCK(pem);
		errno = EINVAL;
		return (-1);
	}

	return (0);
}

/* 
 * Structure converting function from kevent to epoll. In a case
 * this is called on error in registration we store the error in
 * event->data and pick it up later in linux_epoll_ctl().
 */
static void
kevent_to_epoll(struct kevent *kevent, struct epoll_event *l_event)
{

	if ((kevent->flags & EV_ERROR) != 0) {
		l_event->events = EPOLLERR;
		return;
	}

	switch (kevent->filter) {
	case EVFILT_READ:
		l_event->events = EPOLLIN|EPOLLRDNORM|EPOLLPRI;
		if ((kevent->flags & EV_EOF) != 0)
			l_event->events |= EPOLLRDHUP;
	break;
	case EVFILT_WRITE:
		l_event->events = EPOLLOUT|EPOLLWRNORM;
	break;
	}
}

#ifdef PEDANTIC_CHECKS
/*
 * Test if event exists
 */
static int
epoll_test_event(int epfd, int fd, int filter)
{
	struct kevent kev;
	int error, save_errno;

	save_errno = errno;

	EV_SET(&kev, fd, filter, 0, 0, 0, 0);

	error = kevent(epfd, &kev, 1, NULL, 0, NULL);
	if (error == 0) {
		error = -1;
		errno = EEXIST;
	} else if (error < 0 && errno == ENOENT) {
		error = 0;
		errno = save_errno;
	}
	return (error);
}
#endif /* PEDANTIC_CHECKS */

/*
 * Load epoll filter, convert it to kevent filter
 * and load it into kevent subsystem.
 */
EXPORT int
epoll_ctl (int epfd, int op, int fd, struct epoll_event *event)
{
	struct kevent kev[2];
	int kev_flags;
	int nchanges = 0;
	int error;

	if (fd_valid(epfd) == -1)
		return (-1);

	if (fd_valid(fd) == -1)
		return (-1);

	if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
	    mem_valid(event, sizeof(struct epoll_event)))
		return (-1);

	/* Linux disallows spying on himself */
	if (epfd == fd) {
		errno = EINVAL;
		return (-1);
	}

	switch (op) {
	case EPOLL_CTL_MOD:
		/*
		 * We don't memorize which events were set for this FD
		 * on this level, so just delete all we could have set:
		 * EVFILT_READ and EVFILT_WRITE, ignoring any errors
		 */
		error = epoll_delete_all_events(epfd, fd);
		if (error)
			return (-1);

		kev_flags = EV_ADD | EV_ENABLE;
		break;

	case EPOLL_CTL_ADD:
#ifdef PEDANTIC_CHECKS
		if ((event->events & EPOLL_EVRD) != 0) {
			error = epoll_test_event(epfd, fd, EVFILT_READ);
			if (error)
				return (-1);
		}
		if ((event->events & EPOLL_EVWR) != 0) {
			error = epoll_test_event(epfd, fd, EVFILT_WRITE);
			if (error)
				return (-1);
		}
#endif /* PEDANTIC_CHECKS */
		kev_flags = EV_ADD | EV_ENABLE;
		break;

	case EPOLL_CTL_DEL:
		/* CTL_DEL means unregister this fd with this epoll */
		error = epoll_delete_all_events(epfd, fd);
		goto leave;

	default:
		errno = EINVAL;
		return (-1);
	}

	error = epoll_to_kevent(epfd, fd, event, &kev_flags, kev, &nchanges);
	if (error)
		return (-1);

	error = epoll_fd_install(fd, event->data);
	if (error)
		return (-1);

	error = kevent(epfd, kev, nchanges, NULL, 0, NULL);

leave:
	return (error);
}

/*
 * Wait for a filter to be triggered on the epoll file descriptor.
 */
static int
epoll_wait_common(int epfd, struct epoll_event *events, int maxevents,
    int timeout, const sigset_t *uset)
{
	struct epoll_emuldata *emd;
	struct timespec ts, *tsp;
	struct kevent *kevp;
	sigset_t omask;
	int error, count, i, fd;

	if (maxevents <= 0 || maxevents > LINUX_MAX_EVENTS) {
		errno = EINVAL;
		return (-1);
	}

	if (fd_valid(epfd) == -1)
		return (-1);

	if (mem_valid(events, sizeof(struct epoll_event) * maxevents))
		return (-1);

	if (uset != NULL && mem_valid(uset, sizeof(sigset_t)))
		return (-1);

	if (timeout < -1) {
		errno = EINVAL;
		return (-1);
	}

	kevp = calloc(maxevents, sizeof(struct kevent));
	if (kevp == NULL)
		return (-1);

	if (uset != NULL) {
		error = sigprocmask(SIG_SETMASK, uset, &omask);
		if (error != 0) {
			free (kevp);
			return (-1);
		}
	}

	if (timeout != -1) {
		/* Convert from milliseconds to timespec. */
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	} else {
		tsp = NULL;
	}

	count = kevent(epfd, NULL, 0, kevp, maxevents, tsp);
	if (uset != NULL)
		sigprocmask(SIG_SETMASK, &omask, NULL);
	if (count < 0) {
#ifdef PEDANTIC_CHECKS
		/* linux returns EINVAL on valid nonepoll fds */
		if (errno == EBADF)
			errno = EINVAL;
#endif
		goto leave;
	}

	LINUX_PEM_SLOCK(pem);
	emd = pem.epoll;
	assert(emd != NULL);

	for (i = 0; i < count; i++) {
		kevent_to_epoll(&kevp[i], &events[i]);

		fd = kevp[i].ident;
		assert(fd <= emd->fdc);
		events[i].data = emd->udata[fd];
	}
	LINUX_PEM_SUNLOCK(pem);

	/* 
	 * kern_kevent might return ENOMEM which is not expected from epoll_wait.
	 * Maybe we should translate that but I don't think it matters at all.
	 */
leave:
	free(kevp);
	return (count);
}

EXPORT int
epoll_wait (int epfd, struct epoll_event *events, int maxevents, int timeout)
{

	return (epoll_wait_common(epfd, events, maxevents, timeout, NULL));
}

EXPORT int
epoll_pwait (int epfd, struct epoll_event *events, int maxevents, int timeout,
    const sigset_t *ss)
{

	return (epoll_wait_common(epfd, events, maxevents, timeout, ss));
}

static int
epoll_delete_event(int epfd, int fd, int filter)
{
	struct kevent kev;
	int error, save_errno;

	save_errno = errno;

	EV_SET(&kev, fd, filter, EV_DELETE | EV_DISABLE, 0, 0, 0);

	error = kevent(epfd, &kev, 1, NULL, 0, NULL);

	/*
	 * here we ignore ENONT, because we don't keep track of events here
	 */
	if (error < 0 && errno == ENOENT) {
		error = 0;
		errno = save_errno;
	}
	return (error);
}

static int
epoll_delete_all_events(int epfd, int fd)
{
	int error1, error2;

	error1 = epoll_delete_event(epfd, fd, EVFILT_READ);
	error2 = epoll_delete_event(epfd, fd, EVFILT_WRITE);

	/* report any errors we got */
	return (error1 == 0 ? error2 : error1);
}
