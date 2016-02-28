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
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "worker.h"

#define EVENTEXEC_LOCK() do {						\
	do { /* NOTHING */						\
	} while (sem_wait(&evexec_sem) == -1 && errno == EINTR);	\
	assert(sem_value(&evexec_sem) == 0);				\
} while (0)
#define EVENTEXEC_UNLOCK() do {						\
	assert(sem_value(&evexec_sem) == 0);				\
	sem_post(&evexec_sem);						\
} while (0)
#define EVENTEXEC_WAIT() do {						\
	do { /* NOTHING */						\
	} while (sem_wait(&signal_sem) == -1 && errno == EINTR);	\
	assert(sem_value(&signal_sem) == 0);				\
} while (0)
#define EVENTEXEC_SIGNAL() do {						\
	assert(sem_value(&signal_sem) == 0);				\
	sem_post(&signal_sem);						\
} while (0)

static int initialized = 0;
static volatile int stopped = 1;
static pthread_once_t ev_once = PTHREAD_ONCE_INIT;
sem_t evlist_sem;		/* eventlist mutex */
static sem_t evexec_sem;	/* eventexec mutex */
static sem_t signal_sem;	/* thread syncronization semaphore */
int kq = -1;
eventlist_t events = SLIST_HEAD_INITIALIZER(events);
union {
	struct {
		user_handler_t func;
		void *args;
	} in;
	struct {
		int retval;
		int error;
	} out;
} exec;
static void event_free(event_t *ev, int flags);

static event_t execev;

event_t *
event_find(int fd, const eventdesc_t *evdes)
{
	event_t *ev;

	/* is worker initialized ? */
	if (!initialized || stopped) {
		errno = EINVAL;
		return (NULL);
	}

	EVENTLIST_LOCK();
	SLIST_FOREACH(ev, &events, next) {
		if (ev->io[USER_FD] == fd && ev->des == evdes)
			return (ev);
	}

	EVENTLIST_UNLOCK();
	errno = EINVAL;
	return (NULL);
}

/*
 * Execute user defined function with user defined args in eventloop context
 */
int
event_exec(event_t *ev, user_handler_t func, void *args)
{
	event_t *findev;
	struct kevent ke;
	int retval = -1, found = 0;

	EVENTEXEC_LOCK();

	EVENTLIST_LOCK();
	SLIST_FOREACH(findev, &events, next) {
		if (findev == ev) {
			found = 1;
			break;
		}
	}
	EVENTLIST_UNLOCK();
	if (!found) {
		errno = EBADF;
		goto leave;
	}

	exec.in.func = func;
	exec.in.args = args;

	/* send signal to worker thread to call user handler */
	EV_SET(&ke, kq, EVFILT_USER, 0, NOTE_TRIGGER, (uintptr_t)ev, &execev);
	if (kevent (kq, &ke, 1, NULL, 0, NULL) == -1) {
		ERR(ev, "failed to trigger EVFILT_USER kevent");
		goto leave;
	}

	/* And wait for answer sleeping on semaphore */
	EVENTEXEC_WAIT();

	retval = exec.out.retval;
	if (retval == -1)
		errno = exec.out.error;
leave:
	EVENTEXEC_UNLOCK();
	return (retval);
}

int
tune_blockmode(event_t *ev, int nonblock)
{
#if 0
	int readbufsize;

	/ * Limit read buffer size to two messages so EVFILT_WRITE will be
	 * triggered on empty sendbuffer condition * /
	readbufsize = nonblock ? ev->des->readsize * 2 + 64 : ev->des->readsize;
	if (set_bufsize(ev->io[KQ_FD], readbufsize) == -1) {
		LOG(0, "Failed to set readbuf size");
		return (-1);
	}

	if (setsockopt(ev->io[KQ_FD], SOL_SOCKET, SO_SNDLOWAT,
	    &readbufsize, sizeof(readbufsize)) == -1) {
		LOG(0, "Failed to set readbuf low watermark");
		return (-1);
	}

	if (nonblock != 0)
		ev->flags |= EV_NONBLOCK;
	else
		ev->flags &= ~EV_NONBLOCK;
#endif
	DBG(ev, "nonblock mode set to %d", !!nonblock);
	return (0);
}

ssize_t
clear_readbuf(event_t *ev, char *data)
{
	ssize_t len;
	char buf[ev->des->readsize], *tmp;
	int counter = 1000;
	int flags;

#ifdef MSG_NOSIGNAL
	flags = MSG_DONTWAIT|MSG_NOSIGNAL;
#else
	flags = MSG_DONTWAIT;
#endif
	if (!ev->readable)
		return (0);

	tmp = data == NULL ? buf : data;
	do {
		len = recv(ev->io[USER_FD], tmp, ev->des->readsize, flags);
		/* EINTR cannot occur, since we don't block. */
		if (len == -1 && errno == EAGAIN)
			len = 0;
	} while (len == 0 && fionread(ev->io[USER_FD]) > 0 && --counter);

	DBG(ev, "readbuf cleared (%zd bytes)", len);

	return (len);
}

ssize_t
fill_readbuf(event_t *ev)
{
	ssize_t len;
	int counter = 10;
	int flags;
	void *readvalue;

#ifdef MSG_NOSIGNAL
	flags = MSG_DONTWAIT|MSG_NOSIGNAL;
#else
	flags = MSG_DONTWAIT;
#endif

	if (!ev->readable)
		return (0);

	readvalue = get_readvalue(ev);
	/*
	 * For some unclear reasons there is a time gap between read() from
	 * user side of socket pair and ability to write() some bytes from
	 * worker side. So try to write() again on EAGAIN couple times
	 */
	do {
		len = send(ev->io[KQ_FD], readvalue, ev->des->readsize, flags);
		if (len != ev->des->readsize)
			ERR(ev, "partial readbuf write (%zd bytes)", len);
	} while (len == -1 && errno == EAGAIN && --counter);

	if (len == ev->des->readsize) {
		DBG(ev, "readbuf filled");
		memcpy(ev->data, readvalue, ev->des->readsize);
	}

	return (len);
}

void
clobber_readbuf(event_t *ev, uint64_t buf)
{
	ssize_t readsize = ev->des->readsize; /* signed to compare with -1 */
	char prev_data[readsize], readbuf_data[readsize];
	int fdflags;
	ssize_t len;

	DBG(ev, "clobber readbuf with value %"PRIu64, buf);

	/* Check for blocking mode */
	fdflags = fcntl(ev->io[USER_FD], F_GETFL, 0);
	if (fdflags < 0)
		return;

	/* Adjust readbuf size to blocking mode */
	if (!(fdflags & O_NONBLOCK) != !(ev->flags & EV_NONBLOCK) &&
	    tune_blockmode(ev, fdflags & O_NONBLOCK) == -1)
		return;

	/* readbuf is empty. Just write and goto for a new event */
	if (!ev->readable) {
#ifndef NDEBUG
		int size, count = 10000;
		do {
			size = fionread(ev->io[USER_FD]);
		} while (--count > 0 && size > 0);
		assert(size <= 0);
#endif
		invoke_write_handler(ev, buf);
		fill_readbuf(ev);
		return;
	}

	memcpy(prev_data, ev->data, readsize);
	assert(fionread(ev->io[USER_FD]) <= readsize);
	if (fdflags & O_NONBLOCK) {
		/* In nonblocked case do write->read sequence to ensure that
		 * the readbuf is always full */
		if (!invoke_write_handler(ev, buf))
			return;	/* bail out if data unchanged */
		fill_readbuf(ev);

		len = clear_readbuf(ev, readbuf_data);
		if (len == 0 ||
		    memcmp(readbuf_data, get_readvalue(ev), readsize) == 0) {
			if (len == 0) {
				DBG(ev, "RACE: old and new values have been read");
				invoke_read_handler(ev, 0);
			}
			invoke_read_handler(ev, 1);
			fill_readbuf(ev);
		} else if (memcmp(readbuf_data, prev_data, readsize) != 0) {
			DBG(ev, "bad readbuf data");
			clear_readbuf(ev, NULL);
			fill_readbuf(ev);
		}
	} else {
		/* In blockable case do a read->write sequence so no more than
		 * one record at once will be stored in the readbuf */
		len = clear_readbuf(ev, readbuf_data);
		if (len == 0) {
			invoke_read_handler(ev, 0);
		} else if (memcmp(readbuf_data, prev_data, readsize) != 0) {
			DBG(ev, "bad readbuf data");
			clear_readbuf(ev, NULL);
			fill_readbuf(ev);
			return;
		}
		invoke_write_handler(ev, buf);
		fill_readbuf(ev);
	}
}

void
worker_free()
{
	struct kevent ke;

	EV_SET(&ke, kq, EVFILT_USER, EV_DELETE, 0, 0, NULL);
	kevent (kq, &ke, 1, NULL, 0, NULL);
	stopped = 1;
	close(kq);
}

void*
worker (void *arg)
{
	sigset_t set;
	struct kevent ke;
	event_t *ev;
	int len, found;
	ssize_t readsize; /* signed to compare with -1 */

	sigfillset (&set);
	pthread_sigmask (SIG_BLOCK, &set, NULL);

	for (;;) {

		if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1) {
			if (errno != EINTR)
				LOG(0, "worker: kevent failed");
			continue;
		}
/*
		LOG(1, "worker: kevent: ident:%"PRIuPTR", filter:%d, "
		    "flags:0x%x, fflags:0x%x, data:0x%"PRIxPTR", udata:%p",
		    ke.ident, ke.filter, ke.flags, ke.fflags, ke.data, ke.udata);
*/
		LOG(1, "====================================================");
		ev = ke.udata;
		assert(ev != NULL);

		if (ke.flags & EV_EOF) {
			DBG(ev, "kevent: fd closed. delete event now");
			EVENTLIST_LOCK();
			SLIST_REMOVE(&events, ev, event_t, next);
			event_free(ev, 0);
			if (SLIST_EMPTY(&events)) {
				worker_free();
				/* Wake up event_exec callers */
				exec.out.retval = -1;
				exec.out.error = EBADF;
				EVENTEXEC_SIGNAL();
				EVENTLIST_UNLOCK();
				LOG(1, "worker: stopped");
				return (NULL);
			}
			EVENTLIST_UNLOCK();
		} else if (ke.filter == EVFILT_WRITE) {

			DBG(ev, "kevent: write to readbuf available");
			if (!ev->readable) {
				DBG(ev, "skip kevent as readbuf is not readable");
				continue;
			}
			len = fionread(ev->io[USER_FD]);
			readsize = ev->des->readsize; /* Convert to signed */
			assert(len <= readsize);
			if (len == -1) {
				ERR(ev, "failed to get avilable bytes in readbuf");
				continue;
			} else if (len == readsize) {
				DBG(ev, "actual readbuf read hasn't happened");
				continue;
			} else if (len != 0) {
				DBG(ev, "short readbuf read (%d bytes)", len);
				clear_readbuf(ev, NULL);
				fill_readbuf(ev);
				continue;
			}

			DBG(ev, "readbuff is empty after user did a read");
			invoke_read_handler(ev, 1);
			fill_readbuf(ev);
		} else if (ke.filter == EVFILT_USER) {
			found = 0;
			/* EVENTLIST_LOCK(); */
			SLIST_FOREACH(ev, &events, next) {
				if (ev == (event_t *)ke.data) {
					found = 1;
					break;
				}
			}
			/* EVENTLIST_UNLOCK(); */
			if (!found) {
				LOG(0, "kevent: user handler is invoked with "
				    "invalid event pointer");
				exec.out.retval = -1;
				exec.out.error = EBADF;
				EVENTEXEC_SIGNAL();
				continue;
			}
			DBG(ev, "kevent: run user handler in eventloop ctx");
			exec.out.retval = exec.in.func(ev, exec.in.args);
			exec.out.error = errno;
			EVENTEXEC_SIGNAL();
		} else {
			invoke_kevent_handler(ev, &ke);
		}
	}
}

static void
cleanup_child()
{
	event_t *ev;

	LOG(1, "worker: fork handler invoked");

	stopped = 1;
	/* unlock eventlist & event_exec mutexes */
	if (sem_value(&evlist_sem) == 0)
		EVENTLIST_UNLOCK();
	if (sem_value(&evexec_sem) == 0)
		EVENTEXEC_UNLOCK();

	while (!SLIST_EMPTY(&events)) {
		ev = SLIST_FIRST(&events);
		SLIST_REMOVE_HEAD(&events, next);
		event_free(ev, EV_CLEANUPCHILD);
	}
}

static void
worker_init()
{

	LOG(1, "worker: init");
	SLIST_INIT(&events);
	sem_init(&evlist_sem, 0, 1);	/* mutex */
	sem_init(&evexec_sem, 0, 1);	/* mutex */
	sem_init(&signal_sem, 0, 0);	/* semaphore */
	stopped = 1;
	initialized = 1;
	pthread_atfork(NULL, NULL, cleanup_child);
}

static int
worker_run()
{
	struct kevent ke;
	pthread_attr_t attr;
	pthread_t thread_id;
	int result;

	kq = kqueue();
	if (kq == -1) {
		LOG(0, "worker: failed to create a new kqueue");
		return (-1);
	}

	EV_SET(&ke, kq, EVFILT_USER, EV_ADD|EV_CLEAR, 0, 0, &execev);
	if (kevent (kq, &ke, 1, NULL, 0, NULL) == -1) {
		LOG(0, "worker: failed to register kqueue user event");
		close (kq);
		return (-1);
	}

	/* Semaphore value is set to 1 at worker thread exit. Set to 0 */
	while (sem_value(&signal_sem) > 0)
		EVENTEXEC_WAIT();

	/* create and run a worker thread */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	result = pthread_create(&thread_id, &attr, worker, NULL);

	pthread_attr_destroy(&attr);

	if (result != 0) {
		LOG(0, "worker: failed to run");
		close (kq);
		return (-1);
	}

	stopped = 0;
	return (0);
}
    
static void
event_free(event_t *ev, int flags)
{
	if (ev == NULL)
		return;
	if (ev->des->free_handler != NULL)
		invoke_free_handler(ev, flags);
	if (ev->io[KQ_FD] != -1)
		close(ev->io[KQ_FD]);
	free(ev);
}

event_t *
event_init(const eventdesc_t *evdes)
{
	event_t *ev;

	ev = malloc(offsetof(event_t, data) + evdes->readsize + evdes->datasize);
	if (ev == NULL) {
		LOG(0, "Failed to alloc event");
		return (NULL);
	}

	ev->des = evdes;
	ev->io[KQ_FD] = -1;
	ev->io[USER_FD] = -1;
	ev->flags = 0;
	ev->readable = 0;

	return (ev);
}

int
event_insert(event_t *ev)
{
	struct kevent ke;

	assert(ev->des != NULL);

	if (socketpair (PF_UNIX, SOCK_STREAM, 0, ev->io) == -1) {
		ERR(ev, "failed to create a socket pair");
		event_free(ev, 0);
		return (-1);
	}

	/* set kqueue end of the pipe cloexeced and nonblocking */
	if (set_cloexec_flag(ev->io[KQ_FD], 1) == -1 ||
	    set_nonblock_flag(ev->io[KQ_FD], 1) == -1 ||
	    /* set cloexec and nonblock flags of user end of the pipe */
	    set_cloexec_flag(ev->io[USER_FD], ev->flags & EV_CLOEXEC) == -1 ||
	    set_nonblock_flag(ev->io[USER_FD], ev->flags & EV_NONBLOCK) == -1 ||
	    tune_blockmode(ev, ev->flags & EV_NONBLOCK) == -1) {
		ERR(ev, "failed to tune socket options");
		event_free(ev, 0);
		close(ev->io[USER_FD]);
		return (-1);
	}

	fill_readbuf(ev);

	if (!initialized)
		pthread_once(&ev_once, worker_init);

	EVENTLIST_LOCK();
	if (stopped == 1 && worker_run()) {
		EVENTLIST_UNLOCK();
		ERR(ev, "failed to run worker thread");
		close(ev->io[USER_FD]);
		event_free(ev, 0);
		return (-1);
	}

	SLIST_NEXT(ev, next) = SLIST_FIRST(&events);

	EV_SET(&ke, ev->io[KQ_FD], EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, ev);
	if (kevent (kq, &ke, 1, NULL, 0, NULL) == -1) {
		EVENTLIST_UNLOCK();
		ERR(ev, "failed to register kqueue events");
		close (ev->io[USER_FD]);
		event_free(ev, 0);
		return (-1);
	}

	DBG(ev, "event created k%d/u%d", ev->io[KQ_FD], ev->io[USER_FD]);

	SLIST_INSERT_HEAD(&events, ev, next);
	EVENTLIST_UNLOCK();

	return (ev->io[USER_FD]);
}
