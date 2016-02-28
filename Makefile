PREFIX?=	/usr/local
INSTALL?=	install -c
MKDIR?=		install -c -d
#CFLAGS+=	-O0 -g -DDEBUG -DLOG_LEVEL=2
CFLAGS+=	-DNDEBUG
CFLAGS+=	-I. -Wall -Werror -fPIC -DPIC -fvisibility=hidden
LDFLAGS+=	-pthread

SRCS=		worker.c eventfd.c timerfd.c epoll.c signalfd.c utils.c
DEPS=		sys/eventfd.h sys/timerfd.h sys/epoll.h sys/signalfd.h \
		utils.h worker.h
OBJS=		$(SRCS:.c=.o)

TESTCXXFLAGS=	-Itests -std=c++11 ${CXXFLAGS}
TESTLDFLAGS=	-L. -Wl,-rpath,. -llinevents ${LDFLAGS}
TESTS=		tst-eventfd tst-epoll tst-timerfd

all:	liblinevents.so.1 liblinevents.so

.SUFFIX:	.o

.c.o:	$(DEPS)
	${CC} ${CFLAGS} -c $< -o $@

liblinevents.a:		$(OBJS)
	ar -rc $@ $(OBJS)

liblinevents.so.1:	$(OBJS)
	${CC} ${LDFLAGS} -shared -Wl,-soname,$@  ${OBJS} -o $@

liblinevents.so:	liblinevents.so.1
	ln -s liblinevents.so.1 liblinevents.so

.PHONY:	install clean test

install:
	$(MKDIR) $(DESTDIR)$(PREFIX)/include/sys
	$(INSTALL) -m 644 sys/eventfd.h sys/timerfd.h sys/epoll.h sys/signalfd.h \
		$(DESTDIR)$(PREFIX)/include/sys
	$(MKDIR) $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -l s liblinevents.so.1 $(DESTDIR)$(PREFIX)/lib/liblinevents.so
	$(INSTALL) -s -m 755 liblinevents.so.1 $(DESTDIR)$(PREFIX)/lib

clean:
	rm -f *.o $(TESTLIBDIR)/*.o *.a *.so *.so.1 $(TESTS)

$(TESTS):	liblinevents.so tests/$@.cc
	${CXX} ${TESTCXXFLAGS} ${TESTLDFLAGS} $< -o $@

test:	all $(TESTS)
	./tst-eventfd
	./tst-epoll
	./tst-timerfd
