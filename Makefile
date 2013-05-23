SRCS := b64.c server.c sha1.c sha1-test.c
OBJS := $(OBJS:.c=.o)
OUT  := server client

CFLAGS += -g -O2
override CFLAGS += -std=c99 -Wall

all: $(OUT)

tags: *.c *.h
	ctags -R

server: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -DTCPT_SERVER

client: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -DTCPT_CLIENT

clean: 
	$(RM) $(OBJS)

distclean: clean
	$(RM) $(OUT) tags

.PHONY: all clean distclean
