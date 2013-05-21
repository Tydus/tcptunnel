


all: server


server: server.c
	@$(CC) -o server server.c

clean: 
	@- rm server


.PHONY: all clean
