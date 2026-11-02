CFLAGS ?= -O2 -Wall -Wextra
LDLIBS := -lmnl

exitlag-netd: exitlag-netd.c protocol.h ipc_transport.c ipc_transport.h tcp_attribution.c tcp_attribution.h process_identity.c process_identity.h nfq_verdict.c nfq_verdict.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ exitlag-netd.c ipc_transport.c tcp_attribution.c process_identity.c nfq_verdict.c $(LDLIBS)

check-nfq-verdict:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o nfq-verdict-test ../tests/nfq-verdict-test.c nfq_verdict.c $(LDLIBS)
	./nfq-verdict-test

check-ipc:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o ipc-transport-test ../tests/ipc-transport-test.c ipc_transport.c
	./ipc-transport-test

check-tcp-attribution:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o tcp-attribution-test ../tests/tcp-attribution-test.c tcp_attribution.c
	./tcp-attribution-test

check-process-identity:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o process-identity-test ../tests/process-identity-test.c process_identity.c
	./process-identity-test

clean:
	rm -f exitlag-netd ipc-transport-test tcp-attribution-test process-identity-test nfq-verdict-test

.PHONY: clean check-ipc check-tcp-attribution check-process-identity check-nfq-verdict
