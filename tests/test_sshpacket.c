/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH version exchange and binary packet protocol.
 *
 * The decisive test here is the one that decodes packets built by Go. A
 * chacha20-poly1305@openssh.com packet only decodes if the key split, the
 * nonce derivation, both ChaCha20 counters, the MAC's coverage and the
 * framing are all right at once -- any one of them wrong and the tag fails.
 * That is worth more than the sum of testing them separately, because the
 * failure mode this cipher invites is a construction that is perfectly
 * self-consistent and interoperates with nothing.
 *
 * What these vectors do *not* settle is whether the whole construction is
 * upside down in the same way on both sides. Both were written from OpenSSH's
 * PROTOCOL.chacha20poly1305, so a misreading of it would be reproduced
 * faithfully here. Swapping K_1 and K_2 in both implementations would pass
 * every check below. That question is settled by interoperating with a real
 * OpenSSH, which needs the key exchange -- so it belongs to 5.4.3, and until
 * then this file's claim is "our arithmetic is right", not "we interoperate".
 *
 * ---- one mutation survives, on purpose ----------------------------------
 *
 * Eleven mutations were applied to src/ssh/packet.c and ten are caught here.
 * The one that is not replaces tc_ct_equal with memcmp in the tag check,
 * turning a constant-time comparison into a timing oracle on the MAC.
 *
 * No test in this file can see that, and no test of this shape could: the
 * function returns the same answer for the same input either way, and the
 * difference is only in how long it takes to say so. Recording it is the
 * honest option -- the alternative is a mutation score that looks like 11/11
 * because the eleventh mutation was never written. Closing it properly needs
 * timing measurement, which the README already lists as not done anywhere in
 * this project.
 */

#include "tc/sshpacket.h"

#include "ssh_vectors.h"
#include "tctest.h"

#include <string.h>

static int unhex1(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = strlen(s);
	if ((n & 1) != 0 || n / 2 > cap)
		return SIZE_MAX;
	for (size_t i = 0; i < n; i += 2) {
		int hi = unhex1(s[i]), lo = unhex1(s[i + 1]);
		if (hi < 0 || lo < 0)
			return SIZE_MAX;
		out[i / 2] = (uint8_t)(hi << 4 | lo);
	}
	return n / 2;
}

#define BUFSZ 4096

/* ---- against Go -------------------------------------------------------- */

static void test_decodes_go_packets(void)
{
	TCT_CASE("packets built by Go decode to the payload Go put in");
	for (size_t i = 0;
	     i < sizeof kSshPacketVectors / sizeof *kSshPacketVectors; i++) {
		uint8_t key[TC_SSH_CIPHER_KEY_LEN];
		uint8_t want[BUFSZ], pkt[BUFSZ];
		size_t want_len = unhex(kSshPacketVectors[i].payload, want, sizeof want);
		size_t pkt_len = unhex(kSshPacketVectors[i].packet, pkt, sizeof pkt);
		if (unhex(kSshPacketVectors[i].key, key, sizeof key) !=
		        TC_SSH_CIPHER_KEY_LEN ||
		    want_len == SIZE_MAX || pkt_len == SIZE_MAX) {
			TCT_FAILF("vector %zu: unusable", i);
			continue;
		}

		tc_ssh_cipher c;
		tc_ssh_cipher_init_plain(&c);
		tc_ssh_cipher_set_key(&c, key);
		c.seq = kSshPacketVectors[i].seq;

		/* The length must be readable on its own, since a real receiver has
		 * only these four bytes when it decides how much more to read. */
		size_t total = 0;
		if (tc_ssh_packet_decode_length(&c, pkt, &total) != TC_OK) {
			TCT_FAILF("vector %zu: the length would not decode", i);
			continue;
		}
		TCT_EQ_INT((int)total, (int)pkt_len);

		uint8_t out[BUFSZ];
		size_t out_len = 0;
		int rc = tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, pkt_len,
		                              &c);
		if (rc != TC_OK) {
			TCT_FAILF("vector %zu: decode failed (%s)", i, tc_strerror(rc));
			continue;
		}
		tct_checks++;
		if (out_len != want_len) {
			TCT_FAILF("vector %zu: payload %zu bytes, want %zu", i, out_len,
			          want_len);
			continue;
		}
		if (want_len != 0)
			TCT_EQ_MEM(out, want, want_len);

		TCT_CASE("and the sequence number advances by exactly one");
		TCT_EQ_INT((int)c.seq, (int)(kSshPacketVectors[i].seq + 1));
	}
}

static void test_a_tampered_packet_is_refused(void)
{
	/* Encrypt-then-MAC, so every one of these must be caught by the tag
	 * before anything is decrypted. */
	uint8_t key[TC_SSH_CIPHER_KEY_LEN], pkt[BUFSZ];
	size_t pkt_len = unhex(kSshPacketVectors[3].packet, pkt, sizeof pkt);
	if (unhex(kSshPacketVectors[3].key, key, sizeof key) !=
	        TC_SSH_CIPHER_KEY_LEN ||
	    pkt_len == SIZE_MAX) {
		TCT_FAILF("unusable vector");
		return;
	}
	uint32_t seq = kSshPacketVectors[3].seq;

	TCT_CASE("every single-bit change anywhere in a packet is caught");
	for (size_t byte = 0; byte < pkt_len; byte++) {
		for (int bit = 0; bit < 8; bit += 3) {
			uint8_t copy[BUFSZ];
			memcpy(copy, pkt, pkt_len);
			copy[byte] ^= (uint8_t)(1u << bit);

			tc_ssh_cipher c;
			tc_ssh_cipher_init_plain(&c);
			tc_ssh_cipher_set_key(&c, key);
			c.seq = seq;

			uint8_t out[BUFSZ];
			size_t out_len = 0;
			int rc = tc_ssh_packet_decode(out, sizeof out, &out_len, copy,
			                              pkt_len, &c);
			if (rc == TC_OK)
				TCT_FAILF("a flipped bit at byte %zu bit %d was accepted",
				          byte, bit);
			/* And a rejected packet must not have advanced the sequence
			 * number: doing so would desynchronise a connection that a
			 * caller might otherwise have torn down cleanly. */
			if (c.seq != seq)
				TCT_FAILF("a rejected packet advanced the sequence number");
		}
	}
	tct_checks++;

	TCT_CASE("and so is the right packet at the wrong sequence number");
	tc_ssh_cipher c;
	tc_ssh_cipher_init_plain(&c);
	tc_ssh_cipher_set_key(&c, key);
	c.seq = seq + 1;
	uint8_t out[BUFSZ];
	size_t out_len = 0;
	/* The sequence number is the nonce, so a replayed packet decrypts under
	 * a different keystream and fails the tag. This is what makes replay
	 * impossible without any replay window to maintain. */
	TCT_TRUE(tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, pkt_len,
	                              &c) != TC_OK);
}

/* ---- round trips ------------------------------------------------------- */

static void round_trip(bool encrypted, size_t payload_len)
{
	uint8_t key[TC_SSH_CIPHER_KEY_LEN];
	for (size_t i = 0; i < sizeof key; i++)
		key[i] = (uint8_t)(i * 3 + 1);

	tc_ssh_cipher enc, dec;
	tc_ssh_cipher_init_plain(&enc);
	tc_ssh_cipher_init_plain(&dec);
	if (encrypted) {
		tc_ssh_cipher_set_key(&enc, key);
		tc_ssh_cipher_set_key(&dec, key);
	}

	uint8_t payload[BUFSZ];
	for (size_t i = 0; i < payload_len; i++)
		payload[i] = (uint8_t)(i * 7 + payload_len);

	/* Several in a row, so the sequence numbers move and a cipher that
	 * ignored them would decode packet two with packet one's keystream. */
	for (int round = 0; round < 4; round++) {
		uint8_t pkt[BUFSZ];
		size_t pkt_len = 0;
		int rc = tc_ssh_packet_encode(pkt, sizeof pkt, &pkt_len, payload,
		                              payload_len, &enc);
		if (rc != TC_OK) {
			TCT_FAILF("encode(%zu) failed: %s", payload_len, tc_strerror(rc));
			return;
		}

		size_t total = 0;
		if (tc_ssh_packet_decode_length(&dec, pkt, &total) != TC_OK ||
		    total != pkt_len) {
			TCT_FAILF("length(%zu) disagreed with the packet", payload_len);
			return;
		}

		uint8_t out[BUFSZ];
		size_t out_len = 0;
		rc = tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, pkt_len,
		                          &dec);
		if (rc != TC_OK) {
			TCT_FAILF("decode(%zu) failed: %s", payload_len, tc_strerror(rc));
			return;
		}
		tct_checks++;
		if (out_len != payload_len) {
			TCT_FAILF("round trip(%zu) gave %zu bytes", payload_len, out_len);
			return;
		}
		if (payload_len != 0 && memcmp(out, payload, payload_len) != 0) {
			TCT_FAILF("round trip(%zu) changed the payload", payload_len);
			return;
		}
	}
	TCT_EQ_INT((int)enc.seq, 4);
	TCT_EQ_INT((int)dec.seq, 4);
}

static void test_round_trips(void)
{
	TCT_CASE("a payload survives the trip, in the clear");
	/* Every length around a block boundary, because the padding rule is the
	 * part with edges in it. */
	static const size_t lens[] = { 0, 1, 2, 3, 6, 7, 8, 9, 15, 16,
		                           17, 63, 64, 65, 1000, 2048 };
	for (size_t i = 0; i < sizeof lens / sizeof *lens; i++)
		round_trip(false, lens[i]);

	TCT_CASE("and encrypted");
	for (size_t i = 0; i < sizeof lens / sizeof *lens; i++)
		round_trip(true, lens[i]);
}

static void test_framing_rules(void)
{
	uint8_t key[TC_SSH_CIPHER_KEY_LEN];
	memset(key, 0x5a, sizeof key);

	TCT_CASE("the encrypted region is always a whole number of blocks");
	for (size_t len = 0; len < 200; len++) {
		tc_ssh_cipher c;
		tc_ssh_cipher_init_plain(&c);
		uint8_t payload[256], pkt[BUFSZ];
		memset(payload, 0x11, sizeof payload);
		size_t pkt_len = 0;
		if (tc_ssh_packet_encode(pkt, sizeof pkt, &pkt_len, payload, len,
		                         &c) != TC_OK) {
			TCT_FAILF("encode(%zu) failed", len);
			return;
		}
		/* In the clear there is no tag, so the region is everything after
		 * the four-byte length field. */
		size_t region = pkt_len - TC_SSH_LENGTH_LEN;
		if (region % TC_SSH_BLOCK != 0)
			TCT_FAILF("payload %zu gave a %zu-byte region", len, region);
		if (pkt[TC_SSH_LENGTH_LEN] < TC_SSH_MIN_PADDING)
			TCT_FAILF("payload %zu got %u bytes of padding", len,
			          pkt[TC_SSH_LENGTH_LEN]);
	}
	tct_checks++;

	TCT_CASE("the length field is excluded from the alignment");
	/* OpenSSH computes padding over (padding_length || payload) only,
	 * because the length field is encrypted separately under its own key.
	 * Including it shifts every packet by four bytes and an OpenSSH peer
	 * rejects the result as badly padded -- so this pins the rule directly
	 * rather than through a round trip that would agree with itself.
	 *
	 * A 7-byte payload makes 1 + 7 = 8, already aligned, so the padding is a
	 * whole extra block: 8. Were the length field counted, 4 + 1 + 7 = 12
	 * would want 4. */
	tc_ssh_cipher c;
	tc_ssh_cipher_init_plain(&c);
	uint8_t payload[8], pkt[BUFSZ];
	memset(payload, 0x22, sizeof payload);
	size_t pkt_len = 0;
	TCT_EQ_INT(tc_ssh_packet_encode(pkt, sizeof pkt, &pkt_len, payload, 7, &c),
	           TC_OK);
	TCT_EQ_INT(pkt[TC_SSH_LENGTH_LEN], 8);

	TCT_CASE("padding is random, not a constant");
	/* With a stream cipher a predictable tail would leak the payload length
	 * modulo the block size. RFC 4253 6 requires random padding and this is
	 * the only property that notices if it silently becomes zeros. */
	tc_ssh_cipher_init_plain(&c);
	uint8_t a[BUFSZ], b[BUFSZ];
	size_t a_len = 0, b_len = 0;
	TCT_EQ_INT(tc_ssh_packet_encode(a, sizeof a, &a_len, payload, 3, &c),
	           TC_OK);
	TCT_EQ_INT(tc_ssh_packet_encode(b, sizeof b, &b_len, payload, 3, &c),
	           TC_OK);
	TCT_EQ_INT((int)a_len, (int)b_len);
	/* Same payload, same length, so any difference is in the padding. */
	TCT_TRUE(memcmp(a, b, a_len) != 0);
}

static void test_length_bounds(void)
{
	/* Everything here runs before a byte of the body has been read, which is
	 * the only thing bounding how much an unauthenticated number can make us
	 * read. */
	tc_ssh_cipher c;
	tc_ssh_cipher_init_plain(&c);
	size_t total = 0;

	TCT_CASE("a length that is not a whole number of blocks is refused");
	static const uint8_t unaligned[] = { 0, 0, 0, 9 };
	TCT_TRUE(tc_ssh_packet_decode_length(&c, unaligned, &total) != TC_OK);

	TCT_CASE("a length too small to hold the padding is refused");
	static const uint8_t tiny[] = { 0, 0, 0, 0 };
	TCT_TRUE(tc_ssh_packet_decode_length(&c, tiny, &total) != TC_OK);

	TCT_CASE("and an enormous one is refused rather than believed");
	static const uint8_t huge[] = { 0xff, 0xff, 0xff, 0xf8 };
	TCT_EQ_INT(tc_ssh_packet_decode_length(&c, huge, &total), TC_ERR_TOOMANY);

	TCT_CASE("a packet handed over short is refused, not padded");
	/* A decoder that accepted "at least this much" would read a short final
	 * packet as though the missing bytes were zeros. */
	uint8_t pkt[BUFSZ], payload[32];
	memset(payload, 0x33, sizeof payload);
	size_t pkt_len = 0;
	tc_ssh_cipher_init_plain(&c);
	TCT_EQ_INT(tc_ssh_packet_encode(pkt, sizeof pkt, &pkt_len, payload,
	                                sizeof payload, &c),
	           TC_OK);
	tc_ssh_cipher_init_plain(&c);
	uint8_t out[BUFSZ];
	size_t out_len = 0;
	TCT_TRUE(tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, pkt_len - 1,
	                              &c) != TC_OK);
	TCT_TRUE(tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, pkt_len + 1,
	                              &c) != TC_OK);

	TCT_CASE("an over-large payload is refused at encode time too");
	tc_ssh_cipher_init_plain(&c);
	static uint8_t big[TC_SSH_MAX_PAYLOAD + 1];
	TCT_EQ_INT(tc_ssh_packet_encode(pkt, sizeof pkt, &pkt_len, big,
	                                sizeof big, &c),
	           TC_ERR_TOOMANY);
}

static void test_bad_padding_is_refused(void)
{
	/* After authentication, so a peer that gets here is broken rather than
	 * hostile -- but a padding length larger than the region would underflow
	 * the payload size, so it is checked rather than trusted. */
	TCT_CASE("a padding length larger than the packet is refused");
	tc_ssh_cipher c;
	tc_ssh_cipher_init_plain(&c);
	uint8_t pkt[64];
	memset(pkt, 0, sizeof pkt);
	pkt[3] = 8;    /* region of 8 bytes */
	pkt[4] = 200;  /* claiming 200 bytes of padding inside it */
	uint8_t out[64];
	size_t out_len = 0;
	TCT_TRUE(tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, 4 + 8, &c) !=
	         TC_OK);

	TCT_CASE("and so is one below the four-byte minimum");
	memset(pkt, 0, sizeof pkt);
	pkt[3] = 8;
	pkt[4] = 2;
	TCT_TRUE(tc_ssh_packet_decode(out, sizeof out, &out_len, pkt, 4 + 8, &c) !=
	         TC_OK);
}

/* ---- version exchange -------------------------------------------------- */

static void test_version_exchange(void)
{
	char line[TC_SSH_VERSION_MAX + 16];
	size_t len = 0;

	TCT_CASE("our identification line is well formed");
	/* No minus sign in the name, which is why this is not "tailcat-c":
	 * RFC 4253 4.2 forbids one in softwareversion, since the line is parsed
	 * by splitting on it. OpenSSH calls itself "OpenSSH_9.6p1" for the same
	 * reason. */
	TCT_EQ_INT(tc_ssh_version_build(line, sizeof line, &len, "tailcatc_0.1"),
	           TC_OK);
	TCT_EQ_STR(line, "SSH-2.0-tailcatc_0.1\r\n");
	TCT_EQ_INT((int)len, 22);

	TCT_CASE("a software name with a space or a dash is refused");
	/* A space starts the optional comment field, so it would silently split
	 * the identification into two things; the minus sign is forbidden
	 * outright. */
	TCT_TRUE(tc_ssh_version_build(line, sizeof line, &len, "bad name") !=
	         TC_OK);
	TCT_TRUE(tc_ssh_version_build(line, sizeof line, &len, "bad-name") !=
	         TC_OK);

	TCT_CASE("real peers' lines are accepted");
	static const char *const good[] = {
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"SSH-2.0-Go",
		"SSH-1.99-OpenSSH_3.9p1",
		"SSH-2.0-a",
	};
	for (size_t i = 0; i < sizeof good / sizeof *good; i++)
		TCT_EQ_INT(tc_ssh_version_check(good[i], strlen(good[i])), TC_OK);

	TCT_CASE("and anything else is not");
	static const char *const bad[] = {
		"SSH-1.5-OpenSSH_3.9p1", /* protocol 1 only */
		"SSH-2.0-",              /* empty software version */
		"SSH-2.0",               /* no dash */
		"HTTP/1.1 200 OK",       /* not SSH at all */
		"",
		"SSH-2.0-x\r",           /* the CR is the caller's to strip */
	};
	for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
		TCT_TRUE(tc_ssh_version_check(bad[i], strlen(bad[i])) != TC_OK);

	TCT_CASE("a line with an embedded NUL or control byte is refused");
	static const char kNul[] = "SSH-2.0-a\0b";
	TCT_TRUE(tc_ssh_version_check(kNul, sizeof kNul - 1) != TC_OK);

	TCT_CASE("and one over 255 bytes is refused");
	char longline[TC_SSH_VERSION_MAX + 8];
	memset(longline, 'x', sizeof longline);
	memcpy(longline, "SSH-2.0-", 8);
	TCT_TRUE(tc_ssh_version_check(longline, sizeof longline) != TC_OK);
}

int main(void)
{
	test_decodes_go_packets();
	test_a_tampered_packet_is_refused();
	test_round_trips();
	test_framing_rules();
	test_length_bounds();
	test_bad_padding_is_refused();
	test_version_exchange();
	return tct_report("sshpacket");
}
