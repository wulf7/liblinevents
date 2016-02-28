#ifndef	_SYS_EVENTFD_H
#define	_SYS_EVENTFD_H	1

#include <stdint.h>

#ifndef __THROW
#ifdef __cplusplus
#define __THROW throw()
#else
#define __THROW
#endif
#endif

#define	EFD_SEMAPHORE	00000001
#define	EFD_CLOEXEC	02000000
#define	EFD_NONBLOCK	00004000

typedef uint64_t eventfd_t;

__BEGIN_DECLS
int eventfd (unsigned int count, int flags) __THROW;
int eventfd_read (int fd, eventfd_t *value);
int eventfd_write (int fd, eventfd_t value);
__END_DECLS

#endif /* _SYS_EVENTFD_H */
