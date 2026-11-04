CFLAGS ?= -O2 -Wall -Wextra
LDLIBS := -lmnl

exitlag-netd: exitlag-netd.c protocol.h ipc_transport.c ipc_transport.h tcp_attribution.c tcp_attribution.h process_identity.c process_identity.h nfq_verdict.c nfq_verdict.h udp_attribution.c udp_attribution.h udp_packet.c udp_packet.h udp_peers.c udp_peers.h udp_lifecycle.c udp_lifecycle.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ exitlag-netd.c ipc_transport.c tcp_attribution.c process_identity.c nfq_verdict.c udp_attribution.c udp_packet.c udp_peers.c udp_lifecycle.c $(LDLIBS)

check-udp-attribution:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udp-attribution-test ../tests/udp-attribution-test.c udp_attribution.c
	./udp-attribution-test

check-udp-packet:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udp-packet-test ../tests/udp-packet-test.c udp_packet.c
	./udp-packet-test

check-udp-peers:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udp-peers-test ../tests/udp-peers-test.c udp_peers.c
	./udp-peers-test

check-udp-lifecycle:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udp-lifecycle-test ../tests/udp-lifecycle-test.c udp_lifecycle.c
	./udp-lifecycle-test

check-udp-maintenance:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o udp-maintenance-test ../tests/udp-maintenance-test.c ipc_transport.c tcp_attribution.c process_identity.c nfq_verdict.c udp_attribution.c udp_packet.c udp_peers.c udp_lifecycle.c $(LDLIBS)
	./udp-maintenance-test

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
	rm -f exitlag-netd ipc-transport-test tcp-attribution-test process-identity-test nfq-verdict-test udp-attribution-test udp-packet-test udp-peers-test udp-lifecycle-test udp-maintenance-test

.PHONY: clean check-ipc check-tcp-attribution check-process-identity check-nfq-verdict check-udp-attribution check-udp-packet check-udp-peers check-udp-lifecycle check-udp-maintenance
