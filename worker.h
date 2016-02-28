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
#include <assert.h>
#include <semaphore.h>

typedef struct event_t event_t;
typedef struct lineventdesc eventdesc_t;
typedef SLIST_HEAD(, event_t) eventlist_t;

typedef void  (* read_handler_t)   (event_t *ev, int flags);
typedef int   (* write_handler_t)  (event_t *ev, uint64_t value);
typedef void  (* kevent_handler_t) (event_t *ev, const struct kevent *ke);
typedef void  (* free_handler_t)   (event_t *ev, int flags);
typedef int   (* user_handler_t)   (event_t *ev, void* data);
typedef void *(* get_readvalue_t)  (event_t *ev);

struct event_t {
	const eventdesc_t *des;
	int io[2];
	int flags;
	int readable;
	SLIST_ENTRY(event_t) next;
	char data[];
};

struct lineventdesc {
	const char *name;
	size_t readsize;
	size_t datasize;
	read_handler_t read_handler;
	write_handler_t write_handler;
	kevent_handler_t kevent_handler;
	free_handler_t free_handler;
	get_readvalue_t get_readvalue;
};

#define	invoke_read_handler(ev, ...) \
	(ev)->des->read_handler((ev), __VA_ARGS__)
#define	invoke_write_handler(ev, ...) \
	(ev)->des->write_handler((ev), __VA_ARGS__)
#define	invoke_kevent_handler(ev, ...) \
	(ev)->des->kevent_handler((ev), __VA_ARGS__)
#define	invoke_free_handler(ev, ...) \
	(ev)->des->free_handler((ev), __VA_ARGS__)
#define get_data(ev)	((void *)((ev)->data + (ev)->des->readsize))
#define	get_readvalue(ev) (ev)->des->get_readvalue(ev)

#define	USER_FD		0
#define	KQ_FD		1

#define	EV_CLOEXEC	(1<<0)
#define	EV_NONBLOCK	(1<<1)
#define	EV_SEMAPHORE	(1<<2)

/* free_handler flags */
#define EV_CLEANUPCHILD	(1<<0)

extern int kq;
extern sem_t evlist_sem;
extern eventlist_t events;

#define	EVENTLIST_LOCK() do {						\
	do { /* NOTHING */						\
	} while (sem_wait(&evlist_sem) == -1 && errno == EINTR);	\
	assert(sem_value(&evlist_sem) == 0);				\
} while (0)
#define EVENTLIST_UNLOCK() do {						\
	assert(sem_value(&evlist_sem) == 0);				\
	sem_post(&evlist_sem);						\
} while (0)

#define LOG2(level, ev, msg, ...)	LOG(level, "%s (fd=%d): "msg,	\
	(ev)->des->name, (ev)->io[USER_FD], ##__VA_ARGS__)
#define ERR(...)	LOG2(0, __VA_ARGS__)
#define DBG(...)	LOG2(1, __VA_ARGS__)

event_t *event_init(const eventdesc_t *evdes);
int      event_insert(event_t *ev);
event_t *event_find(int fd, const eventdesc_t *evdes);
int      event_exec(event_t *ev, user_handler_t func, void *args);
int      tune_blockmode(event_t *ev, int nonblock);
ssize_t  clear_readbuf(event_t *ev, char *data);
ssize_t  fill_readbuf(event_t *ev);
void     clobber_readbuf(event_t *ev, uint64_t buf);
