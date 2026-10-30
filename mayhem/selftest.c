/*
 * Functional known-answer test for the usrsctp stack: two SCTP endpoints in one process,
 * joined by a datagram socketpair (AF_CONN), exchanging messages with known contents.
 * Prints "PASS <name>" / "FAIL <name>" per check; mayhem/test.sh turns that into CTRF.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <usrsctp.h>

#define MAX_PACKET_SIZE (1 << 16)
#define PORT_SERVER 5001
#define PORT_CLIENT 5002
#define NUM_ORDERED 10
#define BIG_LEN 150000

static int fds[2];
static struct socket *srv_listen, *srv_conn, *cli;
static int failures;

#define CHECK(name, cond) do { \
	if (cond) { printf("PASS %s\n", name); } else { printf("FAIL %s\n", name); failures++; } \
	fflush(stdout); \
} while (0)

static void *
reader(void *arg)
{
	int *fdp = arg;
	char buf[MAX_PACKET_SIZE];
	ssize_t n;

	for (;;) {
		n = recv(*fdp, buf, sizeof(buf), 0);
		if (n > 0) {
			usrsctp_conninput(fdp, buf, (size_t)n, 0);
		} else if (n < 0 && errno != EINTR) {
			break;
		}
	}
	return NULL;
}

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	int *fdp = addr;

	if (send(*fdp, buf, length, 0) < 0) {
		return errno;
	}
	return 0;
}

static struct sockaddr_conn
make_addr(int *fdp, uint16_t port)
{
	struct sockaddr_conn sc;

	memset(&sc, 0, sizeof(sc));
	sc.sconn_family = AF_CONN;
	sc.sconn_port = htons(port);
	sc.sconn_addr = fdp;
	return sc;
}

/* results the server thread gathers for the main thread to check */
static char first_msg[64];
static ssize_t first_len;
static uint16_t first_sid;
static uint32_t first_ppid;
static int ordered_ok, ordered_count;
static size_t big_len;
static uint32_t big_sum;
static uint16_t big_sid;

static uint32_t
checksum(const unsigned char *p, size_t n)
{
	uint32_t a = 1, b = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		a = (a + p[i]) % 65521;
		b = (b + a) % 65521;
	}
	return (b << 16) | a;
}

static ssize_t
recv_message(struct socket *s, unsigned char *buf, size_t cap, struct sctp_rcvinfo *info)
{
	size_t total = 0;
	struct sockaddr_storage from;
	socklen_t fromlen;
	socklen_t infolen;
	unsigned int infotype;
	int flags;
	ssize_t n;

	for (;;) {
		fromlen = sizeof(from);
		infolen = sizeof(*info);
		infotype = 0;
		flags = 0;
		n = usrsctp_recvv(s, buf + total, cap - total, (struct sockaddr *)&from, &fromlen,
		                  info, &infolen, &infotype, &flags);
		if (n <= 0) {
			return -1;
		}
		if (flags & MSG_NOTIFICATION) {
			continue;
		}
		total += (size_t)n;
		if (flags & MSG_EOR) {
			return (ssize_t)total;
		}
		if (total == cap) {
			return -1;
		}
	}
}

static void *
server(void *arg)
{
	static unsigned char buf[BIG_LEN + 16];
	struct sctp_rcvinfo info;
	ssize_t n;
	int i;

	srv_conn = usrsctp_accept(srv_listen, NULL, NULL);
	if (srv_conn == NULL) {
		return NULL;
	}

	n = recv_message(srv_conn, buf, sizeof(buf), &info);
	if (n > 0 && n < (ssize_t)sizeof(first_msg)) {
		memcpy(first_msg, buf, (size_t)n);
		first_len = n;
		first_sid = info.rcv_sid;
		first_ppid = ntohl(info.rcv_ppid);
	}

	ordered_ok = 1;
	for (i = 0; i < NUM_ORDERED; i++) {
		n = recv_message(srv_conn, buf, sizeof(buf), &info);
		if (n != 8 || memcmp(buf, "msg-000", 7) != 0 || buf[7] != (unsigned char)('0' + i) ||
		    info.rcv_sid != 0 || info.rcv_ssn != (uint16_t)i) {
			ordered_ok = 0;
		}
		ordered_count++;
	}

	n = recv_message(srv_conn, buf, sizeof(buf), &info);
	if (n > 0) {
		big_len = (size_t)n;
		big_sum = checksum(buf, (size_t)n);
		big_sid = info.rcv_sid;
	}
	return NULL;
}

static int
send_msg(struct socket *s, const void *data, size_t len, uint16_t sid, uint32_t ppid)
{
	struct sctp_sendv_spa spa;

	memset(&spa, 0, sizeof(spa));
	spa.sendv_sndinfo.snd_sid = sid;
	spa.sendv_sndinfo.snd_ppid = htonl(ppid);
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
	return (int)usrsctp_sendv(s, data, len, NULL, 0, &spa, (socklen_t)sizeof(spa),
	                          SCTP_SENDV_SPA, 0);
}

int
main(void)
{
	pthread_t tr[2], ts;
	struct sockaddr_conn sa;
	struct sctp_status status;
	socklen_t optlen;
	unsigned char *big;
	int i, rc, on;
	const char hello[] = "hello usrsctp";
	const char crc_in[] = "123456789";
	uint32_t crc;

	/* CRC-32C (Castagnoli) check value for "123456789" is 0xE3069283. */
	crc = usrsctp_crc32c((void *)crc_in, 9);
	CHECK("crc32c-known-answer", crc == htonl(0xE3069283u) || crc == 0xE3069283u);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0) {
		perror("socketpair");
		return 2;
	}
	usrsctp_init(0, conn_output, NULL);
	usrsctp_register_address(&fds[0]);
	usrsctp_register_address(&fds[1]);
	pthread_create(&tr[0], NULL, reader, &fds[0]);
	pthread_create(&tr[1], NULL, reader, &fds[1]);

	srv_listen = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
	cli = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
	CHECK("sockets-created", srv_listen != NULL && cli != NULL);
	if (srv_listen == NULL || cli == NULL) {
		return 1;
	}

	sa = make_addr(&fds[1], PORT_SERVER);
	rc = usrsctp_bind(srv_listen, (struct sockaddr *)&sa, sizeof(sa));
	CHECK("server-bind", rc == 0);
	on = 1;
	rc = usrsctp_setsockopt(srv_listen, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on));
	CHECK("server-rcvinfo-enabled", rc == 0);
	rc = usrsctp_listen(srv_listen, 1);
	CHECK("server-listen", rc == 0);
	pthread_create(&ts, NULL, server, NULL);

	sa = make_addr(&fds[0], PORT_CLIENT);
	rc = usrsctp_bind(cli, (struct sockaddr *)&sa, sizeof(sa));
	CHECK("client-bind", rc == 0);
	/* The "peer address" of an AF_CONN association is the channel its packets are sent on. */
	sa = make_addr(&fds[0], PORT_SERVER);
	rc = usrsctp_connect(cli, (struct sockaddr *)&sa, sizeof(sa));
	if (rc != 0) { fprintf(stderr, "connect: rc=%d errno=%d\n", rc, errno); }
	CHECK("association-established", rc == 0);

	memset(&status, 0, sizeof(status));
	optlen = sizeof(status);
	rc = usrsctp_getsockopt(cli, IPPROTO_SCTP, SCTP_STATUS, &status, &optlen);
	CHECK("client-status-established", rc == 0 && status.sstat_state == SCTP_ESTABLISHED);

	rc = send_msg(cli, hello, sizeof(hello) - 1, 3, 42);
	CHECK("send-first", rc == (int)(sizeof(hello) - 1));
	for (i = 0; i < NUM_ORDERED; i++) {
		char m[9];
		memcpy(m, "msg-000", 7);
		m[7] = (char)('0' + i);
		m[8] = 0;
		rc = send_msg(cli, m, 8, 0, 7);
		if (rc != 8) {
			break;
		}
	}
	CHECK("send-ordered", i == NUM_ORDERED);

	big = malloc(BIG_LEN);
	for (i = 0; i < BIG_LEN; i++) {
		big[i] = (unsigned char)((i * 31 + (i >> 8)) & 0xff);
	}
	rc = send_msg(cli, big, BIG_LEN, 1, 99);
	CHECK("send-fragmented", rc == BIG_LEN);

	pthread_join(ts, NULL);

	CHECK("first-message-bytes", first_len == (ssize_t)(sizeof(hello) - 1) &&
	      memcmp(first_msg, hello, sizeof(hello) - 1) == 0);
	CHECK("first-message-stream-and-ppid", first_sid == 3 && first_ppid == 42);
	CHECK("ordered-delivery", ordered_count == NUM_ORDERED && ordered_ok);
	CHECK("fragmented-message-length", big_len == BIG_LEN);
	CHECK("fragmented-message-checksum", big_len == BIG_LEN && big_sum == checksum(big, BIG_LEN));
	CHECK("fragmented-message-stream", big_sid == 1);
	free(big);

	if (srv_conn != NULL) {
		usrsctp_close(srv_conn);
	}
	usrsctp_close(cli);
	usrsctp_close(srv_listen);
	while (usrsctp_finish() != 0) {
		usleep(10000);
	}
	printf("DONE failures=%d\n", failures);
	return failures ? 1 : 0;
}
