/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for the DERP frame codec.
 *
 * This is the first thing in the program to touch bytes off the relay
 * socket, and the shape that produced bugs 20 and 21: a length field chosen
 * by whoever is on the other end, used to size a read. The relay is
 * TLS-authenticated, which means the bytes come from Tailscale's server
 * rather than from anyone on the path -- but "the operator of a public
 * rate-limited relay" is not the same trust level as "this process", and a
 * frame parser that trusts its length is one compromised or buggy relay away
 * from being the whole story.
 *
 * Properties checked:
 *   1. Nothing crashes, whatever arrives.
 *   2. A header the decoder accepts has a payload length within the codec's
 *      own bound -- the check that stops one frame asking to buffer 4GB --
 *      and re-encodes to the same five bytes.
 *   3. A RECV_PACKET the parser accepts yields a packet that lies entirely
 *      inside the payload it was given, with the length the header implies.
 *      *pkt points into the caller's buffer, so an off-by-one here is a read
 *      past the end of a network buffer at every call site.
 *   4. A SERVER_KEY the parser accepts really did carry the key it returned.
 *   5. SERVER_INFO, which is a NaCl box, is never opened by chance, and
 *      never writes more than the caller allowed.
 */

#include "tc/derp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *what)
{
	fprintf(stderr, "FUZZ: %s\n", what);
	abort();
}

static uint64_t rng_state = 0x243f6a8885a308d3ULL;

static uint64_t rng_next(void)
{
	uint64_t x = rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static size_t rng_below(size_t n) { return n ? (size_t)(rng_next() % n) : 0; }

/* ---- the properties ---------------------------------------------------- */

static void check_header(const uint8_t *buf, size_t len)
{
	uint8_t type = 0;
	uint32_t plen = 0;

	if (len < TC_DERP_FRAME_HEADER_LEN)
		return;
	if (tc_derp_frame_header_decode(buf, &type, &plen) != TC_OK)
		return; /* refusing a bad header is the expected outcome */

	if (plen > TC_DERP_MAX_FRAME_LEN)
		fail("a header was accepted with a payload length over the bound");

	/* Round trip: whatever was accepted must re-encode to the same bytes, or
	 * the two halves of this codec disagree about the wire and one of them
	 * is talking to the relay. */
	uint8_t again[TC_DERP_FRAME_HEADER_LEN];
	tc_derp_frame_header_encode(again, type, plen);
	if (memcmp(again, buf, TC_DERP_FRAME_HEADER_LEN) != 0)
		fail("an accepted header did not re-encode to itself");

	/* Naming a type must never read off the end of its own table. */
	if (tc_derp_frame_name(type) == NULL)
		fail("a frame type had no name");
}

static void check_recv_packet(const uint8_t *buf, size_t len)
{
	uint8_t src[TC_DERP_KEY_LEN];
	const uint8_t *pkt = NULL;
	size_t pkt_len = 0;

	if (tc_derp_parse_recv_packet(src, &pkt, &pkt_len, buf, len) != TC_OK)
		return;

	if (pkt == NULL)
		fail("an accepted packet had a NULL body");
	if (pkt < buf || pkt > buf + len)
		fail("an accepted packet pointed outside the payload");
	if ((size_t)(pkt - buf) + pkt_len > len)
		fail("an accepted packet ran past the end of the payload");
	if (pkt_len != len - TC_DERP_KEY_LEN)
		fail("an accepted packet had a length the header does not imply");
	if (memcmp(src, buf, TC_DERP_KEY_LEN) != 0)
		fail("the source key is not the one in the payload");
	/* Touch every byte it handed back, so a sanitizer sees any overrun the
	 * arithmetic above did not. */
	volatile uint8_t sink = 0;
	for (size_t i = 0; i < pkt_len; i++)
		sink = (uint8_t)(sink ^ pkt[i]);
	(void)sink;
}

static void check_server_key(const uint8_t *buf, size_t len)
{
	uint8_t key[TC_DERP_KEY_LEN];

	if (tc_derp_parse_server_key(key, buf, len) != TC_OK)
		return;
	if (len < TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN)
		fail("a server key was parsed out of a payload too short to hold one");
	if (memcmp(buf, TC_DERP_MAGIC, TC_DERP_MAGIC_LEN) != 0)
		fail("a greeting was accepted without the magic");
	/* The key sits immediately after the magic, and a longer greeting is
	 * allowed -- upstream leaves room for fields it has not added yet -- so
	 * it is that slice and not the tail of the payload. Asserting the tail
	 * is what the first version of this did, and it failed in seconds. */
	if (memcmp(key, buf + TC_DERP_MAGIC_LEN, TC_DERP_KEY_LEN) != 0)
		fail("the parsed key is not the one after the magic");
}

static void check_server_info(const uint8_t *buf, size_t len,
                              const uint8_t priv[TC_DERP_KEY_LEN],
                              const uint8_t pub[TC_DERP_KEY_LEN])
{
	static uint8_t out[4096];
	size_t out_len = 12345;

	/* A guard byte after the region the callee may use, so a write of one
	 * byte too many is caught here rather than three layers away. */
	size_t cap = 256;
	out[cap] = 0xa5;
	int rc = tc_derp_open_server_info(out, cap, &out_len, buf, len, priv, pub);
	if (out[cap] != 0xa5)
		fail("open_server_info wrote past the buffer it was given");
	if (rc != TC_OK)
		return;
	/* Opening a box we did not seal should be impossible; if it ever
	 * happens, the authentication is not doing anything. */
	fail("a random payload authenticated as a sealed server info");
}

/* ---- the corpus -------------------------------------------------------- */

/* Real frames, so that mutation starts from something the parsers accept
 * rather than from noise they all reject in the first byte. */
typedef struct {
	uint8_t b[1024];
	size_t n;
} frame;

static void seed_frame(frame *f, unsigned which)
{
	memset(f->b, 0, sizeof f->b);
	switch (which % 5u) {
	case 0: /* a well-formed header for a small packet */
		tc_derp_frame_header_encode(f->b, TC_DERP_FRAME_RECV_PACKET, 64);
		f->n = TC_DERP_FRAME_HEADER_LEN;
		break;
	case 1: /* a header claiming the largest allowed payload */
		tc_derp_frame_header_encode(f->b, TC_DERP_FRAME_SEND_PACKET,
		                            TC_DERP_MAX_FRAME_LEN);
		f->n = TC_DERP_FRAME_HEADER_LEN;
		break;
	case 2: /* a RECV_PACKET payload: 32-byte key then a packet */
		for (size_t i = 0; i < TC_DERP_KEY_LEN; i++)
			f->b[i] = (uint8_t)(i * 7u + 1u);
		memcpy(f->b + TC_DERP_KEY_LEN, "wireguard-ish payload", 21);
		f->n = TC_DERP_KEY_LEN + 21;
		break;
	case 3: /* a SERVER_KEY greeting */
		memcpy(f->b, "DERP\xf0\x9f\x94\x91", 8);
		for (size_t i = 0; i < TC_DERP_KEY_LEN; i++)
			f->b[8 + i] = (uint8_t)(0xc0u ^ i);
		f->n = 8 + TC_DERP_KEY_LEN;
		break;
	default: /* a SERVER_INFO shape: nonce then a box */
		f->n = 24 + 16 + 40;
		for (size_t i = 0; i < f->n; i++)
			f->b[i] = (uint8_t)(i * 31u);
		break;
	}
}

int main(int argc, char **argv)
{
	unsigned long iters = 200000;
	if (argc > 1)
		iters = strtoul(argv[1], NULL, 10);
	if (argc > 2)
		/* Mixed rather than used raw: `seed | 1` maps 2 and 3 to the same
		 * state, so half of every seed sweep repeated the run before it. */
		rng_state = strtoull(argv[2], NULL, 10) * 0x9e3779b97f4a7c15ull |
		            1u;

	/* A real keypair, so that open_server_info is doing real work rather
	 * than failing on a malformed key before it reaches the box. */
	uint8_t priv[TC_DERP_KEY_LEN], pub[TC_DERP_KEY_LEN];
	for (size_t i = 0; i < TC_DERP_KEY_LEN; i++) {
		priv[i] = (uint8_t)(i + 1u);
		pub[i] = (uint8_t)(0xffu - i);
	}

	static frame f;
	unsigned long headers_ok = 0, packets_ok = 0, keys_ok = 0;

	for (unsigned long i = 0; i < iters; i++) {
		seed_frame(&f, (unsigned)rng_next());

		unsigned rounds = 1u + (unsigned)(rng_next() % 8u);
		for (unsigned k = 0; k < rounds; k++) {
			switch (rng_next() % 5u) {
			case 0: /* an arbitrary byte anywhere */
				if (f.n > 0)
					f.b[rng_below(f.n)] = (uint8_t)(rng_next() & 0xff);
				break;
			case 1: /* a length field's worth of 0xff, the classic */
				if (f.n >= 4) {
					size_t at = rng_below(f.n - 3);
					memset(f.b + at, 0xff, 4);
				}
				break;
			case 2: /* grow, since a longer payload is a different path */
				if (f.n + 1 < sizeof f.b) {
					f.b[f.n] = (uint8_t)(rng_next() & 0xff);
					f.n++;
				}
				break;
			case 3: /* truncate, which is what a short read looks like */
				if (f.n > 0)
					f.n = rng_below(f.n);
				break;
			default: /* zero a stretch */
				if (f.n > 0) {
					size_t at = rng_below(f.n);
					size_t n = rng_below(f.n - at);
					memset(f.b + at, 0, n);
				}
				break;
			}
		}

		check_header(f.b, f.n);
		check_recv_packet(f.b, f.n);
		check_server_key(f.b, f.n);
		check_server_info(f.b, f.n, priv, pub);

		/* Reach, counted rather than assumed: a run where nothing parses is
		 * a run that tested the rejection path and nothing else, and it
		 * looks exactly like a passing run. Bug 20 hid behind that. */
		uint8_t type;
		uint32_t plen;
		if (f.n >= TC_DERP_FRAME_HEADER_LEN &&
		    tc_derp_frame_header_decode(f.b, &type, &plen) == TC_OK)
			headers_ok++;
		{
			uint8_t src[TC_DERP_KEY_LEN];
			const uint8_t *pkt;
			size_t pl;
			if (tc_derp_parse_recv_packet(src, &pkt, &pl, f.b, f.n) == TC_OK)
				packets_ok++;
			uint8_t key[TC_DERP_KEY_LEN];
			if (tc_derp_parse_server_key(key, f.b, f.n) == TC_OK)
				keys_ok++;
		}
	}

	if (headers_ok == 0 || packets_ok == 0 || keys_ok == 0) {
		fprintf(stderr,
		        "FUZZ: the corpus stopped reaching the parsers "
		        "(%lu headers, %lu packets, %lu keys accepted)\n",
		        headers_ok, packets_ok, keys_ok);
		return 1;
	}

	printf("ok   fuzz_derp                %lu iterations, no crashes "
	       "(%lu headers, %lu packets, %lu greetings accepted)\n",
	       iters, headers_ok, packets_ok, keys_ok);
	return 0;
}
