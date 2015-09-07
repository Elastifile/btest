
TARGET:=btest
HDRS=btest.h sgio.h hdparm.h
SRCS:=btest.c ata.c sgio.c sg_read.c
LIBS:=pthread rt aio m
 
EXT_IMP?=

ifneq ($(EXT_IMP),)
SRCS += btest_ext_$(EXT_IMP).c
else
SRCS += btest_ext_default.c
endif

# check for git
GIT:=$(shell which git)
ifneq ($(GIT),)
commit=${shell echo `git rev-parse --short HEAD`:`git name-rev HEAD` | tr ' ' -}
endif

# check for package manager
PKG:=$(shell which rpm)

ifeq ($(PKG),)
PKG:=$(shell which dpkg-query)
ifeq ($(PKG),)
PKG=:$(error "no pkg manager found (rpm or dpkg-query)")
endif
# assume debian
LIBAIODEV=libaio-dev
PKGCHK="dpkg-query -s"
else
#assume redhat
LIBAIODEV=libaio-devel
PKGCHK="rpm -q"
endif

OBJS=$(SRCS:%.c=%.o)
_LIBS=${patsubst %,-l %, ${LIBS}}

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -g -O3 -D _LARGEFILE64_SOURCE -DCOMMIT="${commit}" -Wall -o $@ $(LDFLAGS) $^ ${_LIBS}

btest32:
	# requires glibc-devel.i686 libaio-devel.i686 libaio.i686 libgcc.i686
	CFLAGS=-m32 make

$(OBJS): $(HDRS) | checkpkgs

checkpkgs:
	@if [ -z $(GIT) ]; then echo git is required; exit 1; fi
	@if ! eval "$(PKGCHK) $(LIBAIODEV)" > /dev/null 2>&1; then echo "$(LIBAIODEV) is missing (PKG=$(PKG))"; exit 1; fi

doc:
	doxygen

test:
	@echo "Target: " ${TARGET} " commit: "${commit} " hdrs: " ${HDRS} " srcs: " ${SRCS} " libs: " ${LIBS} " objs: " ${OBJS}

clean:
	rm -f $(OBJS) $(TARGET) *.gz

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -g -O3 -D _LARGEFILE64_SOURCE -DCOMMIT="${commit}" -Wall -o $@ $<

tar: $(TARGET)
	rev=`./$(TARGET) -V | cut -f 3 -d " "` && echo $$rev && git archive --format=tar --prefix=btest-$$rev/ HEAD | gzip >btest-$$rev.tar.gz
