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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "sys/eventfd.h"
#include "utils.h"
#include "worker.h"

static void  eventfd_read_handler(event_t *ev, int flags);
static int   eventfd_write_handler(event_t *ev, uint64_t increment);
static void  eventfd_kevent_handler(event_t *ev, const struct kevent *ke);
static void *eventfd_get_readvalue(event_t *ev);

static const eventdesc_t eventfddesc = {
	.name		= "eventfd",
	.readsize	= sizeof(eventfd_t),
	.datasize	= sizeof(eventfd_t),
	.read_handler	= eventfd_read_handler,
	.write_handler	= eventfd_write_handler,
	.kevent_handler	= eventfd_kevent_handler,
	.free_handler	= NULL,
	.get_readvalue	= eventfd_get_readvalue
};
#define EVENTFD (&eventfddesc)
static const eventfd_t sem_readvalue = 0x1;

static void
unblock_write(event_t *ev)
{
	eventfd_t *counter, buf;
	ssize_t len;

	/* unblock write to eventfd if necessary */
	counter = get_data(ev);
	if (*counter < UINT64_MAX - 1) {
		len = read(ev->io[KQ_FD], &buf, sizeof(buf));
		DBG(ev, "write unblocked (%zd bytes flushed)", len);
	}
}

static void
eventfd_read_handler(event_t *ev, int flags)
{
	eventfd_t *counter, old_counter;

	counter = get_data(ev);
	old_counter = *counter;

	if (ev->flags & EV_SEMAPHORE && *counter > 0)
		--*counter;
	else
		*counter = 0;

	DBG(ev, "read: counter changed 0x%"PRIx64"->0x%"PRIx64, old_counter,
	    *counter);

	ev->readable = *counter > 0;
	if (flags && old_counter >= UINT64_MAX - 1)
		unblock_write(ev);
}

static int
eventfd_write_handler(event_t *ev, uint64_t inc)
{
	eventfd_t *counter, old_counter;

	counter = get_data(ev);
	old_counter = *counter;

	DBG(ev, "counter 0x%"PRIx64" incremented by 0x%"PRIx64, *counter, inc);
	/* Check for counter overflow */
	if (((*counter + inc) < *counter) || (*counter + inc) == UINT64_MAX) {
		DBG(ev, "counter overflown");
	} else {
		*counter += inc;
		DBG(ev, "counter`s value changed to 0x%"PRIx64, *counter);
	}

	ev->readable = *counter > 0;
	unblock_write(ev);

	return (*counter != old_counter);
}

static void
eventfd_kevent_handler(event_t *ev, const struct kevent *ke)
{
	eventfd_t inc;

	assert(ke->filter == EVFILT_READ);
	assert(ke->ident == ev->io[KQ_FD]);
	assert(ev->des == EVENTFD);

	DBG(ev, "kevent: write to %"PRIuPTR, ke->ident);
	/* Clear writebuf on partial write */
	if (ke->data != sizeof(eventfd_t)) {
		DBG(ev, "invalid data in writebuf: %"PRIiPTR" bytes. Skipped",
		    ke->data);
		unblock_write(ev);
		return;
	}

	/* Read writebuf value keeping buffer full so next writes
	 * will be blocked until unblock_write() is called */
	if (recv(ev->io[KQ_FD], &inc, sizeof(inc), MSG_PEEK) == -1) {
		ERR(ev, "writebuf read failed");
		return;
	}

	if (inc == 0 || inc == UINT64_MAX) {
		DBG(ev, "invalid value 0x%"PRIx64" ignored", inc);
		unblock_write(ev);
		return;
	}

	/* Do not update readbuf in semaphore case as it always contain 0x1 */
	if (ev->flags & EV_SEMAPHORE && ev->readable) {
		eventfd_write_handler(ev, inc);
		return;
	}

	clobber_readbuf(ev, inc);
}

static void *
eventfd_get_readvalue(event_t *ev)
{
	if (ev->flags & EV_SEMAPHORE)
		return ((void *)&sem_readvalue); /* 0x1 */
	else
		return (get_data(ev));
}

EXPORT int
eventfd(unsigned int count, int flags)
{
	event_t *ev;
	struct kevent ke;
	int fd;

	LOG(1, ">>>>>>>> eventfd(%u, %d)", count, flags);

	ev = event_init(EVENTFD);
	if (ev == NULL)
		return (-1);

	if (flags & EFD_SEMAPHORE)
		ev->flags |= EV_SEMAPHORE;
	if (flags & (EFD_NONBLOCK | O_NONBLOCK))
		ev->flags |= EV_NONBLOCK;
	if (flags & (EFD_CLOEXEC | O_CLOEXEC))
		ev->flags |= EV_CLOEXEC;

	*(eventfd_t *)get_data(ev) = count;
	ev->readable = count > 0;

	fd = event_insert(ev);
	if (fd == -1)
		return (-1);

	EV_SET(&ke, ev->io[KQ_FD], EVFILT_READ, EV_ADD | EV_CLEAR,
	    NOTE_LOWAT, sizeof(eventfd_t), ev);

	if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
		ERR(ev, "failed to register kqueue events on pipe");
		close (ev->io[USER_FD]); /* free via eventloop */
		return (-1);
	}

	/* Limit write buffer size to one message to block write queueing */
	if (set_bufsize(ev->io[USER_FD], sizeof(eventfd_t)) == -1) {
		ERR(ev, "failed to set writebuf size");
		close (ev->io[USER_FD]); /* free via eventloop */
		return (-1);
	}

	return (fd);
}

EXPORT int
eventfd_read(int fd, eventfd_t *value)
{
	eventfd_t buf;
	ssize_t len;

	len = read(fd, &buf, sizeof(buf));
	if (len == sizeof(buf)) {
		*value = buf;
		return (0);
	}
	if (len > 0)
		errno = EINVAL;
	return (-1);
}

EXPORT int
eventfd_write(int fd, eventfd_t value)
{
	ssize_t len;

	if (value == UINT64_MAX) {
		errno = EINVAL;
		return (-1);
	}

	len = write(fd, &value, sizeof(value));
	return (len == sizeof(value) ? 0 : -1);
}
