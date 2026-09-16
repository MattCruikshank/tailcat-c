/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Live interoperability test against a real wireguard-go device.
 *
 * tools/wgpeer runs an actual wireguard-go Device with an in-memory TUN. This
 * program performs the Noise IKpsk2 handshake against it over UDP and then
 * sends one encrypted transport packet containing a valid IPv4 datagram. If
 * wireguard-go accepts the handshake, derives the same transport keys, and
 * the decrypted packet passes its allowed-IPs check, the packet appears on
 * its TUN and wgpeer exits 0.
 *
 * That chain is what makes this meaningful: agreeing with ourselves proves
 * nothing about the protocol, whereas a byte wireguard-go hands to its TUN
 * had to survive every step of the real implementation.
 *
 * Run via `make live-wg`, which starts wgpeer and this together.
 */

#include "tc/crypto.h"
#include "tc/noise.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decoded a nibble at a time rather than with sscanf("%2x"): the field width
 * is not reliably honoured everywhere, and a key that decodes to *almost* the
 * right bytes fails later as an opaque handshake rejection. */
static int unhex(uint8_t *out, size_t cap, const char *s)
{
	size_t n = strlen(s);
	if (n != cap * 2)
		return -1;
	for (size_t i = 0; i < n; i += 2) {
		int hi = hexval(s[i]), lo = hexval(s[i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i / 2] = (uint8_t)(hi << 4 | lo);
	}
	return 0;
}

/* ipv4_udp_packet builds a minimal well-formed IPv4+UDP datagram. It has to
 * be a real IP packet: wireguard-go parses the header and drops anything
 * whose source address is not in the peer's allowed IPs. */
static size_t ipv4_udp_packet(uint8_t *out, const char *src, const char *dst,
                              const void *payload, size_t payload_len)
{
	const size_t ip_hdr = 20, udp_hdr = 8;
	size_t total = ip_hdr + udp_hdr + payload_len;

	memset(out, 0, total);
	out[0] = 0x45; /* IPv4, 5 words of header */
	out[1] = 0;
	out[2] = (uint8_t)(total >> 8);
	out[3] = (uint8_t)total;
	out[8] = 64;   /* TTL */
	out[9] = 17;   /* UDP */
	(void)inet_pton(AF_INET, src, out + 12);
	(void)inet_pton(AF_INET, dst, out + 16);

	/* IPv4 header checksum. */
	uint32_t sum = 0;
	for (size_t i = 0; i < ip_hdr; i += 2)
		sum += (uint32_t)out[i] << 8 | out[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	uint16_t ck = (uint16_t)~sum;
	out[10] = (uint8_t)(ck >> 8);
	out[11] = (uint8_t)ck;

	/* UDP header; checksum 0 is legal for IPv4 and saves a pseudo-header. */
	uint8_t *udp = out + ip_hdr;
	udp[0] = 0x30; udp[1] = 0x39; /* src port 12345 */
	udp[2] = 0x1f; udp[3] = 0x90; /* dst port 8080 */
	size_t udp_len = udp_hdr + payload_len;
	udp[4] = (uint8_t)(udp_len >> 8);
	udp[5] = (uint8_t)udp_len;
	if (payload_len != 0)
		memcpy(udp + udp_hdr, payload, payload_len);

	return total;
}

int main(int argc, char **argv)
{
	const char *peer_hex = NULL, *priv_hex = NULL, *psk_hex = NULL;
	int port = 51820;
	int lport = 51830;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-peer") == 0 && i + 1 < argc)
			peer_hex = argv[++i];
		else if (strcmp(argv[i], "-private") == 0 && i + 1 < argc)
			priv_hex = argv[++i];
		else if (strcmp(argv[i], "-psk") == 0 && i + 1 < argc)
			psk_hex = argv[++i];
		else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc)
			port = atoi(argv[++i]);
		else if (strcmp(argv[i], "-lport") == 0 && i + 1 < argc)
			lport = atoi(argv[++i]);
	}
	if (peer_hex == NULL || priv_hex == NULL) {
		fprintf(stderr, "usage: livewg -private HEX -peer HEX [-psk HEX] "
		                "[-port N]\n");
		return 2;
	}

	uint8_t priv[32], peer_pub[32], psk[32];
	memset(psk, 0, sizeof psk);
	if (unhex(priv, sizeof priv, priv_hex) != 0 ||
	    unhex(peer_pub, sizeof peer_pub, peer_hex) != 0) {
		fprintf(stderr, "livewg: bad key hex\n");
		return 2;
	}
	if (psk_hex != NULL && unhex(psk, sizeof psk, psk_hex) != 0) {
		fprintf(stderr, "livewg: bad psk hex\n");
		return 2;
	}

	tc_wg_identity me;
	if (tc_wg_identity_from_private(&me, priv) != TC_OK) {
		fprintf(stderr, "livewg: could not derive our public key\n");
		return 1;
	}
	printf("our public key:  ");
	for (size_t i = 0; i < 32; i++)
		printf("%02x", me.public_key[i]);
	printf("\n");

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	/* Bind a known source port. wireguard-go learns a peer's endpoint from
	 * the packets it receives, but the test configures ours up front so the
	 * exchange does not depend on that discovery working -- and so a failure
	 * here is unambiguously ours. */
	if (lport != 0) {
		struct sockaddr_in from;
		memset(&from, 0, sizeof from);
		from.sin_family = AF_INET;
		from.sin_port = htons((uint16_t)lport);
		from.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(fd, (struct sockaddr *)&from, sizeof from) != 0) {
			perror("bind");
			close(fd);
			return 1;
		}
	}

	struct sockaddr_in to;
	memset(&to, 0, sizeof to);
	to.sin_family = AF_INET;
	to.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, "127.0.0.1", &to.sin_addr) != 1) {
		fprintf(stderr, "livewg: bad address\n");
		close(fd);
		return 1;
	}

	tc_wg_handshake hs;
	if (tc_wg_handshake_init(&hs, &me, peer_pub, psk) != TC_OK) {
		fprintf(stderr, "livewg: handshake init failed\n");
		close(fd);
		return 1;
	}

	printf("\n[1] sending handshake initiation (%d bytes)\n",
	       TC_WG_INITIATION_SIZE);
	uint8_t init[TC_WG_INITIATION_SIZE];
	if (tc_wg_create_initiation(init, &hs, &me, 0) != TC_OK) {
		fprintf(stderr, "livewg: create initiation failed\n");
		close(fd);
		return 1;
	}
	if (getenv("LIVEWG_DUMP_INIT") != NULL) {
		/* Lets scripts/live-wg.sh hand the exact bytes to wgpeer -mac1, so a
		 * handshake rejection can be localised to a field rather than
		 * guessed at. */
		printf("initiation: ");
		for (size_t i = 0; i < sizeof init; i++)
			printf("%02x", init[i]);
		printf("\n");
		fflush(stdout);
		close(fd);
		return 0;
	}

	if (sendto(fd, init, sizeof init, 0, (struct sockaddr *)&to,
	           sizeof to) != (ssize_t)sizeof init) {
		perror("sendto");
		close(fd);
		return 1;
	}

	printf("[2] waiting for wireguard-go's response\n");
	uint8_t resp[512];
	ssize_t n = recv(fd, resp, sizeof resp, 0);
	if (n < 0) {
		fprintf(stderr, "livewg: no response from wireguard-go (%s)\n",
		        strerror(errno));
		close(fd);
		return 1;
	}
	printf("     got %zd bytes, type %u\n", n, (unsigned)resp[0]);
	if (n != TC_WG_RESPONSE_SIZE || resp[0] != TC_WG_MSG_RESPONSE) {
		fprintf(stderr, "livewg: expected a %d byte response, got %zd\n",
		        TC_WG_RESPONSE_SIZE, n);
		close(fd);
		return 1;
	}

	/* If this verifies, wireguard-go performed the same three Diffie-Hellman
	 * operations, mixed the same transcript, and folded in the same
	 * pre-shared key. */
	if (tc_wg_consume_response(&hs, &me, resp) != TC_OK) {
		fprintf(stderr, "livewg: response failed to verify\n");
		close(fd);
		return 1;
	}
	printf("     response verified: the transcripts match\n");

	tc_wg_session s;
	if (tc_wg_begin_session(&s, &hs) != TC_OK) {
		fprintf(stderr, "livewg: could not derive session keys\n");
		close(fd);
		return 1;
	}
	printf("[3] session established (we are the initiator)\n");

	printf("[4] sending an encrypted IPv4 packet through the tunnel\n");
	static const char kPayload[] = "hello from tailcat-c";
	uint8_t inner[256];
	size_t inner_len = ipv4_udp_packet(inner, "10.99.0.2", "10.99.0.1",
	                                   kPayload, sizeof kPayload - 1);

	uint8_t pkt[512];
	size_t pkt_len = 0;
	if (tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &s, inner, inner_len) !=
	    TC_OK) {
		fprintf(stderr, "livewg: encrypt failed\n");
		close(fd);
		return 1;
	}
	if (sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)&to, sizeof to) !=
	    (ssize_t)pkt_len) {
		perror("sendto");
		close(fd);
		return 1;
	}
	printf("     sent %zu bytes (%zu byte inner packet)\n", pkt_len,
	       inner_len);

	close(fd);
	printf("\nok   livewg                   handshake and transport accepted "
	       "by wireguard-go\n");
	printf("     (wgpeer reports separately whether it reached the TUN)\n");
	return 0;
}
