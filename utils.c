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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

/* Get the number of bytes stored in readbuf */
int
fionread(int fd)
{
	int len;

	if (ioctl(fd, FIONREAD, &len) < 0)
		return (-1);

	return (len);
}

int
sem_value(sem_t *sem)
{
	int sval;

	if (sem_getvalue(sem, &sval) == -1)
		return (-1);

	return (sval);
}

int
fd_valid(int fd)
{
#ifdef PEDANTIC_CHECKS
	return (fcntl(fd, F_GETFD, 0));
#else
	if (fd == -1) {
		errno = EBADF;
		return (-1);
	}
	return (0);
#endif
}

int
mem_valid (const void *addr, size_t len)
{
	int ret = 0;
#ifdef PEDANTIC_CHECKS
	char *vec, buf[256];
	long pagesize, npages;
	int save_errno;
	int count = 10;

	pagesize = sysconf(_SC_PAGESIZE);
	npages = (len + pagesize * 2 - 2) / pagesize;
	vec = npages > sizeof(buf) ? malloc(npages) : buf;
	if (vec == NULL)
		return (-1);

	/* XXX: Restart mincore several times as it sometimes fails
	 * on FreeBSD 11 being supplied with valid addr and len  */
	save_errno = errno;
	do
		ret = mincore(addr, len, vec);
	while (ret == -1 && --count);
	errno = (ret == -1) ? EFAULT : save_errno;

	if (npages > sizeof(buf))
		free(vec);
#else
	if (addr == NULL) {
		errno = EFAULT;
		ret = -1;
	}
#endif
	return (ret);
}

int
set_bufsize(int fd, int len)
{
	int ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &len, sizeof(len));
	if (ret == -1)
		LOG(0, "Failed to set buffer size");
	return (ret);
}

/**
 * Set the O_NONBLOCK flag of file descriptor fd if value is nonzero
 * clear the flag if value is 0.
 *
 * @param[in] fd    A file descriptor to modify.
 * @param[in] value A cloexec flag value to set.
 * @return 0 on success, or -1 on error with errno set.
 **/
int
set_nonblock_flag(int fd, int value)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return flags;

	if (value != 0)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	return (fcntl(fd, F_SETFL, flags));
}

/**
 * Set the FD_CLOEXEC flag of file descriptor fd if value is nonzero
 * clear the flag if value is 0.
 *
 * @param[in] fd    A file descriptor to modify.
 * @param[in] value A cloexec flag value to set.
 * @return 0 on success, or -1 on error with errno set.
 **/
int
set_cloexec_flag(int fd, int value)
{
	int flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0)
		return flags;

	if (value != 0)
		flags |= FD_CLOEXEC;
	else
		flags &= ~FD_CLOEXEC;

	return (fcntl(fd, F_SETFD, flags));
}
