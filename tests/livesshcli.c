/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH client half, driven against our own server over a loopback socket.
 *
 * This needs no network and no third party: it is our client talking to our
 * server, which is exactly what it does not prove. Both were written from the
 * same reading of the same RFCs, so a misunderstanding shared by the two of
 * them passes here -- the same limitation the packet layer had before a real
 * OpenSSH was pointed at it, and bug 22 is what that cost.
 *
 * What it does prove is that the client half exists and works at all, which
 * is worth having at a tier that runs without dialling anyone: the version
 * exchange, KEXINIT from the client's side, the signature check over the
 * exchange hash, both cipher directions with the client's key assignment --
 * c2s to send, s2c to receive, which is the one thing a client adapted from a
 * server gets backwards -- publickey authentication as the *offering* side,
 * and a subsystem channel carrying data both ways.
 *
 * The interoperability claim rests on `make live-ls`, where the far end is a
 * real Go tailcat.
 *
 * Usage: livesshcli <port> <user-seed-hex>
 */

#include "tc/ed25519.h"
#include "tc/sshclient.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int unhex1(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Nibble at a time, not sscanf("%2x") -- see bug 24. */
static int unhex(const char *s, uint8_t *out, size_t want)
{
	if (strlen(s) != want * 2)
		return -1;
	for (size_t i = 0; i < want; i++) {
		int hi = unhex1(s[i * 2]), lo = unhex1(s[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return 0;
}

static int sock_read(void *ctx, uint8_t *buf, size_t cap, size_t *nread)
{
	int fd = *(int *)ctx;
	ssize_t n = read(fd, buf, cap);
	if (n <= 0)
		return TC_ERR_CLOSED;
	*nread = (size_t)n;
	return TC_OK;
}

static int sock_write(void *ctx, const uint8_t *buf, size_t len)
{
	int fd = *(int *)ctx;
	size_t off = 0;
	while (off < len) {
		/* send with MSG_NOSIGNAL rather than write: a peer that has closed
		 * would otherwise kill this process with SIGPIPE before the error
		 * could be returned. Bug 15 is the same lesson, and the fix is the
		 * same -- per call, not by changing the signal disposition. */
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
		if (n <= 0)
			return TC_ERR_CLOSED;
		off += (size_t)n;
	}
	return TC_OK;
}

static int on_ready(void *ctx, tc_ssh_client *c)
{
	(void)ctx;
	static const char kMsg[] = "hello from the client half\n";
	int rc = tc_ssh_client_write(c, kMsg, sizeof kMsg - 1);
	if (rc != TC_OK)
		return rc;

	/* Say we are done sending. The far end reads until end of input, so
	 * without this both sides wait for the other to speak. */
	rc = tc_ssh_client_eof(c);
	if (rc != TC_OK)
		return rc;

	/* Read until the far end is done, and print it: the script checks what
	 * came back rather than merely that the session completed. */
	for (;;) {
		uint8_t buf[4096];
		size_t got = 0;
		rc = tc_ssh_client_read(c, buf, sizeof buf, &got);
		if (rc == TC_ERR_DONE || rc == TC_ERR_CLOSED)
			break;
		if (rc != TC_OK)
			return rc;
		fwrite(buf, 1, got, stdout);
	}
	fflush(stdout);
	return TC_OK;
}

int main(int argc, char **argv)
{
	/* `--pub <seed>` prints the matching public key, so a script can
	 * authorise the key it is about to use without a second tool. */
	if (argc == 3 && strcmp(argv[1], "--pub") == 0) {
		uint8_t seed[32], pub[32];
		if (unhex(argv[2], seed, sizeof seed) != 0 ||
		    tc_ed25519_public_from_seed(pub, seed) != TC_OK) {
			fprintf(stderr, "livesshcli: bad seed\n");
			return 2;
		}
		for (size_t i = 0; i < sizeof pub; i++)
			printf("%02x", pub[i]);
		printf("\n");
		return 0;
	}
	if (argc != 3) {
		fprintf(stderr, "usage: livesshcli <port> <user-seed-hex>\n"
		                "       livesshcli --pub <seed-hex>\n");
		return 2;
	}
	uint8_t seed[32];
	if (unhex(argv[2], seed, sizeof seed) != 0) {
		fprintf(stderr, "livesshcli: bad hex\n");
		return 2;
	}

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((uint16_t)atoi(argv[1]));
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
		perror("connect");
		return 1;
	}

	tc_ssh_client_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.user = "tester";
	opts.user_seed = seed;
	opts.subsystem = "sftp";
	opts.read = sock_read;
	opts.write = sock_write;
	opts.io_ctx = &fd;
	opts.on_ready = on_ready;

	int rc = tc_ssh_client_run(&opts);
	close(fd);
	if (rc != TC_OK && rc != TC_ERR_CLOSED && rc != TC_ERR_DONE) {
		fprintf(stderr, "livesshcli: %s\n", tc_strerror(rc));
		return 1;
	}
	fprintf(stderr, "livesshcli: session complete\n");
	return 0;
}
