/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for the JSON reader and the DERP map parser.
 *
 * These parse a document fetched over the network from a host we do not
 * control, which puts them in the same category as the address parser: the
 * first thing to touch attacker-influenced bytes.
 *
 * Properties checked:
 *   1. Neither parser ever crashes, however malformed the input.
 *   2. A document the reader accepts is balanced -- every object and array
 *      that opened was closed -- and never reports a depth outside its own
 *      bounds.
 *   3. tc_json_skip_value leaves the reader exactly where reading the value
 *      normally would, so a parser that ignores a member stays in sync.
 */

#include "tc/derpmap.h"
#include "tc/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *what)
{
	fprintf(stderr, "FUZZ: %s\n", what);
	abort();
}

static void check_reader(const char *doc, size_t len)
{
	tc_json_reader r;
	tc_json_event ev;
	long open_objects = 0, open_arrays = 0;

	tc_json_reader_init(&r, doc, len);
	for (;;) {
		int rc = tc_json_next(&r, &ev);
		if (rc != TC_OK)
			return; /* rejecting garbage is the expected outcome */
		if (ev.type == TC_JSON_END)
			break;

		switch (ev.type) {
		case TC_JSON_OBJECT_BEGIN: open_objects++; break;
		case TC_JSON_ARRAY_BEGIN:  open_arrays++;  break;
		case TC_JSON_OBJECT_END:   open_objects--; break;
		case TC_JSON_ARRAY_END:    open_arrays--;  break;
		default: break;
		}
		if (open_objects < 0 || open_arrays < 0)
			fail("a container closed that was never opened");
		if (r.depth > TC_JSON_MAX_DEPTH)
			fail("depth exceeded its own limit");

		/* A string event must always be copyable or cleanly refused. */
		if (ev.type == TC_JSON_STRING || ev.type == TC_JSON_KEY) {
			char buf[512];
			(void)tc_json_string_copy(&ev, buf, sizeof buf);
		}
	}

	if (open_objects != 0 || open_arrays != 0)
		fail("accepted a document with unbalanced containers");
}

/* Property 3: skipping a value must land where reading it would. */
static void check_skip(const char *doc, size_t len)
{
	tc_json_reader a, b;
	tc_json_event ev;

	tc_json_reader_init(&a, doc, len);
	if (tc_json_next(&a, &ev) != TC_OK)
		return;
	if (ev.type != TC_JSON_OBJECT_BEGIN && ev.type != TC_JSON_ARRAY_BEGIN)
		return;

	/* One reader skips the container; the other walks it to its end. */
	b = a;
	tc_json_reader_init(&a, doc, len);
	if (tc_json_skip_value(&a) != TC_OK)
		return;

	unsigned target = b.depth - 1;
	for (;;) {
		if (tc_json_next(&b, &ev) != TC_OK)
			return;
		if (ev.type == TC_JSON_END)
			return;
		if (b.depth == target)
			break;
	}

	if (a.pos != b.pos)
		fail("skip_value landed somewhere other than the end of the value");
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

static const char *const kSeeds[] = {
	"{\"Regions\":{\"301\":{\"RegionID\":301,\"RegionCode\":\"nyc\","
	"\"Latitude\":40.7,\"Nodes\":[{\"HostName\":\"a.example\","
	"\"IPv4\":\"1.2.3.4\",\"DERPPort\":443,\"CanPort80\":true}]}}}",
	"{\"a\":[1,2,{\"b\":null}],\"c\":\"\\u00e9\\ud83d\\udc08\"}",
	"[[[[[[1]]]]]]",
	"{}",
	"[]",
	"null",
	"-1.5e-3",
	"\"\\\\\\\"\\/\\b\\f\\n\\r\\t\"",
};

/* The interesting bytes are the ones with syntactic meaning. */
static const char kInteresting[] = "{}[]\",:\\/ \t\n0123456789.-+eE"
                                   "truefalsnul\xc3\xa9\x01\x7f";

int main(int argc, char **argv)
{
	unsigned long iters = 200000;
	if (argc > 1)
		iters = strtoul(argv[1], NULL, 10);
	if (argc > 2)
		rng_state = strtoull(argv[2], NULL, 10) | 1u;

	static char buf[8192];
	static tc_derp_map map;

	for (unsigned long i = 0; i < iters; i++) {
		const char *seed = kSeeds[rng_below(sizeof kSeeds / sizeof kSeeds[0])];
		size_t len = strlen(seed);
		if (len >= sizeof buf)
			len = sizeof buf - 1;
		memcpy(buf, seed, len);

		unsigned rounds = 1u + (unsigned)(rng_next() % 8u);
		for (unsigned k = 0; k < rounds; k++) {
			switch (rng_next() % 5u) {
			case 0: /* replace a byte with a syntactically interesting one */
				if (len > 0)
					buf[rng_below(len)] =
					    kInteresting[rng_below(sizeof kInteresting - 1)];
				break;
			case 1: /* insert */
				if (len + 1 < sizeof buf) {
					size_t at = rng_below(len + 1);
					memmove(buf + at + 1, buf + at, len - at);
					buf[at] = kInteresting[rng_below(sizeof kInteresting - 1)];
					len++;
				}
				break;
			case 2: /* delete */
				if (len > 0) {
					size_t at = rng_below(len);
					memmove(buf + at, buf + at + 1, len - at - 1);
					len--;
				}
				break;
			case 3: /* truncate */
				if (len > 0)
					len = rng_below(len);
				break;
			case 4: /* an arbitrary byte, including NUL and high bits */
				if (len > 0)
					buf[rng_below(len)] = (char)(rng_next() & 0xff);
				break;
			default:
				break;
			}
		}

		check_reader(buf, len);
		check_skip(buf, len);
		/* The DERP map parser runs over the same bytes: it must reject them
		 * without crashing, whatever the reader made of them. */
		(void)tc_derpmap_parse(&map, buf, len);
	}

	printf("ok   fuzz_json                %lu iterations, all properties held\n",
	       iters);
	return 0;
}
