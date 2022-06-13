CCFLAGS ?= -Wall -O0 -D_GNU_SOURCE -luring
all_targets = io_uring_reactor_server

.PHONY: liburing

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

io_uring_reactor_server:
	$(CC) io_uring_reactor_server.c -o ./io_uring_reactor_server  -g -I./liburing/src/include/ -L./liburing/src/  ${CCFLAGS}
