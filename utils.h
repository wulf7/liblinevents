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

#include <errno.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PEDANTIC_CHECKS 1

#define	EXPORT	__attribute__((visibility("default")))

#ifndef LOG_LEVEL
#define LOG_LEVEL -1
#endif

#define LOG(level, msg, ...) do {					\
	if (level < LOG_LEVEL) {					\
		if (level == 0 && errno != 0)				\
			fprintf(stderr, msg" %d(%s)\n", ##__VA_ARGS__,	\
			    errno, strerror(errno));			\
		else							\
			fprintf(stderr, msg"\n", ##__VA_ARGS__);	\
	}								\
} while (0)

/* Operations on timespecs */
typedef uint64_t ts64_t;
#define	timespecclear(tvp)	((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#define	timespecisset(tvp)	((tvp)->tv_sec || (tvp)->tv_nsec)
#define tstots64(tvp) ((uint64_t)(tvp).tv_sec * 1000000000 + (tvp).tv_nsec)
static __inline struct timespec
ts64tots(ts64_t ts64t)
{
	struct timespec ts;

	ts.tv_sec = ts64t / 1000000000;
	ts.tv_nsec = ts64t % 1000000000;
	return (ts);
}

static __inline ts64_t
ts64_gettime(clockid_t clock_id)
{
	struct timespec now;

	if (clock_gettime(clock_id, &now) == -1)
		return (0);
	return (tstots64(now));
}

int fionread(int fd);
int sem_value(sem_t *sem);
int fd_valid(int fd);
int mem_valid(const void *addr, size_t len);
int set_bufsize(int fd, int len);
int set_cloexec_flag(int fd, int value);
int set_nonblock_flag(int fd, int value);
