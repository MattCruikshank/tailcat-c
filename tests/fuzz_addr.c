/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for the address parser, which is the only part of tailcat-c
 * that consumes wholly attacker-controlled bytes before any authentication
 * has happened.
 *
 * Builds two ways:
 *
 *   - With libFuzzer (clang -fsanitize=fuzzer), via LLVMFuzzerTestOneInput.
 *   - Standalone, as a deterministic mutation fuzzer over a seed corpus.
 *     This is what "make fuzz" runs, because the cosmocc toolchain has no
 *     libFuzzer and it keeps the target useful with only gcc available.
 *
 * The properties checked are:
 *   1. Parsing never crashes, however malformed the input.
 *   2. A successful parse produces a structure that re-encodes, and that
 *      re-encoded address parses again to the identical structure. That
 *      round-trip invariant is what catches elide/restore drift.
 */

#include "tc/addr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check_one(const uint8_t *data, size_t size)
{
	/* tc_conn_info is several KB, so keep it off the stack. */
	static tc_conn_info a, b;
	char addr[TC_ADDR_STR_MAX];
	char again[TC_ADDR_STR_MAX];

	if (size > TC_ADDR_STR_MAX - 1)
		size = TC_ADDR_STR_MAX - 1;

	if (tc_addr_parse(&a, (const char *)data, size) != TC_OK)
		return; /* rejecting garbage is the expected outcome */

	/* Property 2: a parsed address must survive an encode/parse round trip
	 * unchanged. */
	if (tc_addr_encode(addr, sizeof addr, &a, NULL) != TC_OK) {
		fprintf(stderr, "FUZZ: parsed address failed to re-encode\n");
		abort();
	}
	if (tc_addr_parse(&b, addr, strlen(addr)) != TC_OK) {
		fprintf(stderr, "FUZZ: re-encoded address failed to parse: %s\n",
		        addr);
		abort();
	}
	if (tc_addr_encode(again, sizeof again, &b, NULL) != TC_OK ||
	    strcmp(addr, again) != 0) {
		fprintf(stderr, "FUZZ: encoding is not stable:\n  %s\n  %s\n", addr,
		        again);
		abort();
	}
	if (memcmp(&a, &b, sizeof a) != 0) {
		fprintf(stderr, "FUZZ: round trip changed the parsed structure\n");
		abort();
	}
}

#if defined(TC_FUZZ_LIBFUZZER)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	check_one(data, size);
	return 0;
}

#else /* standalone mutation fuzzer */

/* xorshift64*, so runs are reproducible from a seed. */
static uint64_t rng_state = 0x2545f4914f6cdd1dULL;

static uint64_t rng_next(void)
{
	uint64_t x = rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static size_t rng_below(size_t n)
{
	return (n == 0) ? 0 : (size_t)(rng_next() % n);
}

/* Seeds: valid addresses from upstream's tests, plus shapes that exercise
 * the interesting branches. */
static const char *const kSeeds[] = {
	"tcoWFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHw",
	"tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg",
	"tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu",
	"tc",
	"",
};

static const char kAlphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void mutate(char *buf, size_t *len, size_t cap)
{
	switch (rng_next() % 5u) {
	case 0: /* flip a character to another alphabet character */
		if (*len > 0)
			buf[rng_below(*len)] = kAlphabet[rng_below(sizeof kAlphabet - 1)];
		break;
	case 1: /* insert */
		if (*len + 1 < cap) {
			size_t at = rng_below(*len + 1);
			memmove(buf + at + 1, buf + at, *len - at);
			buf[at] = kAlphabet[rng_below(sizeof kAlphabet - 1)];
			(*len)++;
		}
		break;
	case 2: /* delete */
		if (*len > 0) {
			size_t at = rng_below(*len);
			memmove(buf + at, buf + at + 1, *len - at - 1);
			(*len)--;
		}
		break;
	case 3: /* truncate */
		if (*len > 0)
			*len = rng_below(*len);
		break;
	case 4: /* splice in a raw byte, including non-alphabet ones */
		if (*len > 0)
			buf[rng_below(*len)] = (char)(rng_next() & 0xff);
		break;
	default:
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
		 * state, so half of every seed sweep repeated the run before it
		 * -- which looked like twice the coverage and was not. The odd
		 * bit is forced last because xorshift64 is stuck at zero. */
		rng_state = strtoull(argv[2], NULL, 10) * 0x9e3779b97f4a7c15ull |
		            1u;

	static char buf[TC_ADDR_STR_MAX];

	for (unsigned long i = 0; i < iters; i++) {
		const char *seed = kSeeds[rng_below(sizeof kSeeds / sizeof kSeeds[0])];
		size_t len = strlen(seed);
		if (len >= sizeof buf)
			len = sizeof buf - 1;
		memcpy(buf, seed, len);

		unsigned rounds = 1u + (unsigned)(rng_next() % 6u);
		for (unsigned r = 0; r < rounds; r++)
			mutate(buf, &len, sizeof buf);

		check_one((const uint8_t *)buf, len);
	}

	printf("ok   fuzz_addr                %lu iterations, no crashes\n", iters);
	return 0;
}

#endif
