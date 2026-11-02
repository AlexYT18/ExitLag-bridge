CFLAGS ?= -O2 -Wall -Wextra
LDLIBS := -lmnl

exitlag-netd: exitlag-netd.c protocol.h ipc_transport.c ipc_transport.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ exitlag-netd.c ipc_transport.c $(LDLIBS)

check-ipc:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o ipc-transport-test ../tests/ipc-transport-test.c ipc_transport.c
	./ipc-transport-test

clean:
	rm -f exitlag-netd ipc-transport-test

.PHONY: clean check-ipc
