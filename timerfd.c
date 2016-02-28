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

#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "sys/timerfd.h"
#include "utils.h"
#include "worker.h"

#define TIMER_DISARM	0
#define TIMER_ONESHOT	0

/* Type for event counter.  */
typedef struct timerfd {
	uint64_t counter;
	clockid_t clock_id;
	ts64_t it_value;
	ts64_t it_interval;
	ts64_t next;
} timerfd_t;

static void  timerfd_read_handler(event_t *ev, int flags);
static int   timerfd_write_handler(event_t *ev, uint64_t increment);
static void  timerfd_kevent_handler(event_t *ev, const struct kevent *ke);
static void  timerfd_free_handler(event_t *ev, int flags);
static void *timerfd_get_readvalue(event_t *ev);

static const eventdesc_t timerfddesc = {
	.name		= "timerfd",
	.readsize	= sizeof(uint64_t),
	.datasize	= sizeof(timerfd_t),
	.read_handler	= timerfd_read_handler,
	.write_handler	= timerfd_write_handler,
	.kevent_handler	= timerfd_kevent_handler,
	.free_handler	= timerfd_free_handler,
	.get_readvalue	= timerfd_get_readvalue
};
#define TIMERFD (&timerfddesc)

static int
timerfd_arm(const event_t *ev, ts64_t period)
{
	struct kevent ke;
	u_short flags;
	u_int fflags;
	intptr_t data;
	int error, save_errno;

	if (period != TIMER_DISARM) {
		flags = EV_ADD | EV_ONESHOT;
#ifdef NOTE_NSECONDS_
		if (period < (uint64_t)INTPTR_MAX) {
			fflags = NOTE_NSECONDS;
			data = period + 1;
		} else
#endif
#ifdef NOTE_USECONDS_
		if (period / 1000 < (uint64_t)INTPTR_MAX) {
			fflags = NOTE_USECONDS;
			data = period / 1000 + 1;
		} else
#endif
		{
			fflags = 0; /* defaulted to NOTE_MSECONDS */
			data = period / 1000000 + 1;
		}
	} else {
		flags = EV_DELETE;
		fflags = 0;
		data = 0;
	}

	EV_SET(&ke, ev->io[KQ_FD], EVFILT_TIMER, flags, fflags, data,
	    (void *)ev);

	save_errno = errno;
	error = kevent(kq, &ke, 1, NULL, 0, NULL);
	if (error < 0 &&  errno != ENOENT) {
		ERR(ev, "Failed to register kqueue timer event");
		return (-1);
	}
	errno = save_errno;
	return (0);
}

static void
timerfd_read_handler(event_t *ev, int flags)
{
	timerfd_t *tr;

	tr = get_data(ev);
	tr->counter = 0;
	ev->readable = 0;
}

static int
timerfd_write_handler(event_t *ev, uint64_t increment)
{
	timerfd_t *tr;

	tr = get_data(ev);
	tr->counter += increment;

	ev->readable = tr->counter > 0;
	return (increment > 0);
}

static void
timerfd_kevent_handler(event_t *ev, const struct kevent *ke)
{
	timerfd_t *tr;
	ts64_t now;
	uint64_t increment = 0;

	assert(ke->filter == EVFILT_TIMER);
	assert(ke->ident == ev->io[KQ_FD]);
	assert(ev->des == TIMERFD);

	DBG(ev, "kevent: timer %"PRIuPTR, ke->ident);

	tr = get_data(ev);
	now = ts64_gettime(tr->clock_id);
	if (now == 0)
		return;

	if (now > tr->next) {
		if (tr->it_interval == TIMER_ONESHOT) {
			tr->it_value = TIMER_DISARM;
			increment = 1;
		} else {
			increment = (now - tr->next) / tr->it_interval + 1;
			/* XXX: Need atomics for update tr->next */
			tr->next += tr->it_interval * increment;
		}
	}

	if (tr->it_value != TIMER_DISARM &&
	    timerfd_arm(ev, tr->next - now) == -1)
		return;

	clobber_readbuf(ev, increment);
}

static void
timerfd_free_handler(event_t *ev, int flags)
{
	 timerfd_arm(ev, TIMER_DISARM);
}

static void *
timerfd_get_readvalue(event_t *ev)
{
	return (get_data(ev));
}

static int
timerfd_stop(event_t *ev, void* data)
{
	timerfd_arm(ev, TIMER_DISARM);
	return (0);
}

EXPORT int
timerfd_create(clockid_t clock_id, int flags)
{
	event_t *ev;
	timerfd_t *tr;

	LOG(1, ">>>>>>>> timerfd_create(%d, %d)", clock_id, flags);

	if (clock_id & ~(CLOCK_MONOTONIC|CLOCK_REALTIME) ||
	    flags & ~(TFD_NONBLOCK|O_NONBLOCK|TFD_CLOEXEC|O_CLOEXEC)) {
		errno = EINVAL;
		return (-1);
	}

	ev = event_init(TIMERFD);
	if (ev == NULL)
		return (-1);

	if (flags & (TFD_NONBLOCK | O_NONBLOCK))
		ev->flags |= EV_NONBLOCK;
	if (flags & (TFD_CLOEXEC | O_CLOEXEC))
		ev->flags |= EV_CLOEXEC;

	tr = get_data(ev);
	tr->clock_id = clock_id;
	tr->it_value = TIMER_DISARM;
	tr->it_interval = TIMER_ONESHOT;
	tr->next = 0;
	return (event_insert(ev));
}

void
timerfd_gettime_common(const timerfd_t *tr, ts64_t now,
    struct itimerspec *value)
{
	ts64_t next;

	if (tr->it_value == TIMER_DISARM) {
		timespecclear(&value->it_value);
	} else {
		/* XXX: Need atomics for reading tr->next */
		next = tr->next;
		if (next > now) {
			value->it_value = ts64tots(next - now);
		} else {
			/* timer expired but has not fired yet. Set it to
			 * minimal possible value */
			value->it_value = ts64tots(1);
		}
	}
	value->it_interval = ts64tots(tr->it_interval);
}

EXPORT int
timerfd_gettime(int fd, struct itimerspec *value)
{
	event_t *ev;
	timerfd_t *tr;
	ts64_t now;
	int retval = -1;

	LOG(1, ">>>>>>>> timerfd_gettime(%d, %p)", fd, value);

	if (fd_valid(fd) == -1)
		return (-1);

	if (mem_valid(value, sizeof(struct itimerspec)) == -1)
		return (-1);

	ev = event_find(fd, TIMERFD);
	if (ev == NULL)
		return (-1);

	tr = get_data(ev);
	now = ts64_gettime(tr->clock_id);
	if (now == 0)
		goto leave;

	timerfd_gettime_common(tr, now, value);
	retval = 0;
leave:
	EVENTLIST_UNLOCK();
	return (retval);
}

EXPORT int
timerfd_settime(int fd, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
	uint64_t counter = 0;
	event_t *ev;
	timerfd_t *tr;
	ts64_t now, it_value, it_interval;
	int retval = -1;

	LOG(1, ">>>>>>>> timerfd_settime(%d, %d, %p, %p)", fd, flags,
	    value, ovalue);

	if (flags & ~TFD_TIMER_ABSTIME) {
		errno = EINVAL;
		return (-1);
	}

	if (fd_valid(fd) == -1)
		return (-1);

	if (mem_valid(value, sizeof(struct itimerspec)) == -1)
		return (-1);

	if (ovalue != NULL &&
	    mem_valid(ovalue, sizeof(struct itimerspec)) == -1)
		return (-1);

	LOG(1, "value = { .it_value = {%ld, %ld}, .it_interval = {%ld, %ld}}",
	    value->it_value.tv_sec,  value->it_value.tv_nsec,
	    value->it_interval.tv_sec, value->it_interval.tv_nsec);

	if (value->it_interval.tv_nsec >= 1000000000 ||
	    value->it_interval.tv_nsec < 0 ||
	    value->it_value.tv_nsec >= 1000000000 ||
	    value->it_value.tv_nsec < 0) {
		errno = EINVAL;
		return (-1);
	}

	ev = event_find(fd, TIMERFD);
	if (ev == NULL)
		return (-1);

	tr = get_data(ev);
	now = ts64_gettime(tr->clock_id);
	if (now == 0)
		goto leave;

	if (tr->it_value != TIMER_DISARM) {
		EVENTLIST_UNLOCK();
		/* stop old timer */
		if (event_exec(ev, timerfd_stop, NULL) == -1)
			return (-1);
		ev = event_find(fd, TIMERFD); /* take lock again */
		if (ev == NULL)
			return (-1);
	}

	it_value = tstots64(value->it_value);
	it_interval = tstots64(value->it_interval);

	if (it_value != TIMER_DISARM && flags & TFD_TIMER_ABSTIME) {
		if (it_value < now) {
			/* timer set in the past */
			it_value = (it_interval == TIMER_ONESHOT) ?
			    TIMER_DISARM :
			    it_interval - ((now - it_value) % it_interval);
			counter = 1;
		} else {
			it_value -= now;
		}
	}

	clear_readbuf(ev, NULL);
	ev->readable = 0;

	if (timerfd_arm(ev, it_value) == -1)
		goto leave;

	if (ovalue != NULL)
		timerfd_gettime_common(tr, now, ovalue);

	tr->next = now + it_value;
	tr->it_value = it_value;
	tr->it_interval = it_interval;
	tr->counter = 0;

	timerfd_write_handler(ev, counter);
	fill_readbuf(ev);
	retval = 0;
leave:
	EVENTLIST_UNLOCK();
	return (retval);
}
