SRCS := b64.c sha1.c
OBJS := $(SRCS:.c=.o)
OUT  := server client

CFLAGS += -g -O2
override CFLAGS += -std=c99 -Wall

all: $(OUT)

tags: *.c *.h
	ctags -R

server: $(OBJS) server.c
	$(CC) $(CFLAGS) -o $@ $^ -DTCPT_SERVER

client: $(OBJS) server.c
	$(CC) $(CFLAGS) -o $@ $^ -DTCPT_CLIENT

$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean: 
	$(RM) $(OBJS)

distclean: clean
	$(RM) $(OUT) tags

.PHONY: all clean distclean
