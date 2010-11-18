
TARGET:=btest
HDRS=btest.h sgio.h hdparm.h
SRCS:=btest.c ata.c sgio.c sg_read.c
LIBS:=pthread rt aio
CFLAGS+=-fms-extensions 

commit=${shell echo `git rev-parse --short HEAD`:`git name-rev HEAD` | tr ' ' -}
OBJS=$(SRCS:%.c=%.o)
_LIBS=${patsubst %,-l %, ${LIBS}}

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -g -O3 -D _LARGEFILE64_SOURCE -DCOMMIT="${commit}" -Wall -o $@ $(LDFLAGS) $^ ${_LIBS}

$(OBJS): checkrpms

checkrpms:
	@if ! rpm -q libaio-devel > /dev/null 2>&1; then echo "libaio-devel is missing"; exit 1; fi

doc:
	doxygen

test:
	@echo "Target: " ${TARGET} " commit: "${commit} " hdrs: " ${HDRS} " srcs: " ${SRCS} " libs: " ${LIBS} " objs: " ${OBJS}

clean:
	rm -f $(OBJS) $(TARGET)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -g -O3 -D _LARGEFILE64_SOURCE -DCOMMIT="${commit}" -Wall -o $@ $<
