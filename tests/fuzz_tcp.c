/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for the userspace TCP stack and the demultiplexer.
 *
 * This is about 900 lines of sequence arithmetic, a reassembly queue and a
 * state machine, fed by whatever arrives through the tunnel. Everything that
 * reaches it has been authenticated by WireGuard, so it is not open to the
 * internet -- but "the peer is authenticated" is not "the peer is correct",
 * and a peer that is buggy, hostile, or simply a different implementation can
 * send anything at all. The reassembly queue in particular takes
 * attacker-chosen sequence numbers and lengths and decides where in a buffer
 * they land, which is the shape of bug worth looking for with a fuzzer rather
 * than by reading.
 *
 * ---- fuzzing on top of a working connection -----------------------------
 *
 * The obvious harness -- generate random packets, feed them in -- was the
 * first version of this file, and it was nearly useless: over 200,000
 * iterations it got 76 connections open, because a packet has to survive a
 * checksum, a port lookup and a state check before it reaches anything
 * interesting. It fuzzed the length checks thoroughly and the state machine
 * hardly at all.
 *
 * So this runs two real stacks against each other, exchanging real data, and
 * corrupts a fraction of the packets in flight. The connections reach
 * ESTABLISHED, fill their windows, retransmit and close, and the damage lands
 * in the middle of all of that -- which is where reassembly actually lives.
 *
 * The connections also have to *finish*. The first version of this churn
 * opened them and never closed any, so both tables filled to
 * TC_TCP_MAX_CONNS and stayed there: every later connect was refused, the
 * reaper had nothing to free, and 200,000 iterations did exactly as much work
 * as 40,000 -- the same 64 accepts either way. That is the same failure this
 * file was written to escape, one level up, which is why the counters below
 * are printed and the turnover is asserted rather than assumed.
 *
 * Properties checked:
 *   1. No input crashes either stack, and none trips ASan or UBSan.
 *   2. A read never reports more bytes than the caller's buffer holds.
 *   3. Bytes that do arrive on an uncorrupted connection arrive in order and
 *      unaltered: a reassembly bug that silently reordered or duplicated data
 *      would otherwise pass every crash-based check.
 *   4. Neither stack ever emits a packet that is not a well-formed IPv6+TCP
 *      packet of the length it claims -- answering malformed input with
 *      malformed output is how one peer's bug becomes another's.
 */

#include "tc/tcpmux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *what)
{
	fprintf(stderr, "FUZZ: %s\n", what);
	abort();
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rng_next(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static size_t rng_below(size_t n)
{
	return n == 0 ? 0 : (size_t)(rng_next() % n);
}

static const uint8_t kIpA[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 1 };
static const uint8_t kIpB[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 2 };

#define QUEUE 256
#define MAXPKT 1600

static struct {
	bool used;
	bool to_b;
	size_t len;
	uint8_t data[MAXPKT];
} q[QUEUE];

static unsigned long corrupted;
static unsigned long delivered;

/* check_emitted inspects every packet either stack produces. */
static void check_emitted(const uint8_t *pkt, size_t len)
{
	if (pkt == NULL)
		fail("emitted a null packet");
	if (len < 40 + 20)
		fail("emitted a packet too short to be IPv6+TCP");
	if ((pkt[0] >> 4) != 6)
		fail("emitted a packet that is not IPv6");
	if (pkt[6] != 6)
		fail("emitted a packet whose next header is not TCP");
	size_t payload = (size_t)pkt[4] << 8 | pkt[5];
	if (payload + 40 != len)
		fail("emitted a packet whose length field disagrees with its size");
	size_t doff = (size_t)(pkt[40 + 12] >> 4) * 4;
	if (doff < 20 || doff > payload)
		fail("emitted a packet with an impossible data offset");
}

static void enqueue(const uint8_t *pkt, size_t len, bool to_b)
{
	check_emitted(pkt, len);
	if (len > MAXPKT)
		return;
	for (size_t i = 0; i < QUEUE; i++) {
		if (q[i].used)
			continue;
		q[i].used = true;
		q[i].to_b = to_b;
		q[i].len = len;
		memcpy(q[i].data, pkt, len);
		return;
	}
}

static int out_a(void *ctx, const uint8_t *pkt, size_t len)
{
	(void)ctx;
	enqueue(pkt, len, true);
	return TC_OK;
}

static int out_b(void *ctx, const uint8_t *pkt, size_t len)
{
	(void)ctx;
	enqueue(pkt, len, false);
	return TC_OK;
}

/* damage corrupts a packet in flight, in ways a broken or hostile peer could
 * plausibly produce. The header fields are hit far more often than the
 * payload, because that is where the arithmetic is. */
static void damage(uint8_t *pkt, size_t *len)
{
	corrupted++;
	uint8_t *th = pkt + 40;
	switch (rng_next() % 8u) {
	case 0: /* a wild sequence number */
		for (int i = 0; i < 4; i++)
			th[4 + i] = (uint8_t)rng_next();
		break;
	case 1: /* a sequence number just off the expected one */
		th[7] = (uint8_t)(th[7] + 1 + rng_below(4));
		break;
	case 2: /* a wild acknowledgement */
		for (int i = 0; i < 4; i++)
			th[8 + i] = (uint8_t)rng_next();
		break;
	case 3: /* arbitrary flags, including nonsense combinations */
		th[13] = (uint8_t)(rng_next() & 0x3f);
		break;
	case 4: /* a window that claims far more or nothing at all */
		th[14] = (uint8_t)rng_next();
		th[15] = (uint8_t)rng_next();
		break;
	case 5: /* an impossible data offset */
		th[12] = (uint8_t)(rng_next() & 0xf0);
		break;
	case 6: /* truncate, so the length checks see a short packet */
		if (*len > 41)
			*len -= 1 + rng_below(*len - 41);
		break;
	default: /* flip a byte anywhere */
		pkt[rng_below(*len)] ^= (uint8_t)(1u << rng_below(8));
		break;
	}
}

/* still_present re-finds a connection after a reap, or reports that it went. */
static tc_tcp_conn *still_present(tc_tcp_mux *m, tc_tcp_conn *c)
{
	if (c == NULL)
		return NULL;
	for (size_t i = 0, n = tc_tcp_mux_count(m); i < n; i++)
		if (tc_tcp_mux_at(m, i) == c)
			return c;
	return NULL;
}

/* churn_service reads from every churn connection and answers a FIN with one,
 * which is what lets a close actually complete. The clean pair is left alone:
 * its bytes are the integrity oracle and are read in the main loop. */
static void churn_service(tc_tcp_mux *m, tc_tcp_conn *keep1, tc_tcp_conn *keep2,
                          uint64_t now)
{
	for (size_t i = 0, n = tc_tcp_mux_count(m); i < n; i++) {
		tc_tcp_conn *c = tc_tcp_mux_at(m, i);
		if (c == NULL || c == keep1 || c == keep2)
			continue;
		uint8_t buf[128];
		size_t got = 0;
		if (tc_tcp_read(c, buf, sizeof buf, &got) == TC_OK && got > sizeof buf)
			fail("read reported more bytes than the buffer holds");
		if (tc_tcp_read_closed(c))
			(void)tc_tcp_shutdown_write(c, now);
	}
}

/* churn_pick closes one arbitrary churn connection, gracefully or not. */
static void churn_pick(tc_tcp_mux *m, tc_tcp_conn *keep1, tc_tcp_conn *keep2,
                       bool hard, uint64_t now)
{
	size_t n = tc_tcp_mux_count(m);
	for (size_t t = 0; t < n; t++) {
		tc_tcp_conn *c = tc_tcp_mux_at(m, rng_below(n));
		if (c == NULL || c == keep1 || c == keep2)
			continue;
		if (hard)
			tc_tcp_mux_close(m, c, now);
		else
			(void)tc_tcp_shutdown_write(c, now);
		return;
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

	/* One pair is left undamaged so data integrity can be asserted; the
	 * other carries the corruption. A single pair could not distinguish
	 * "reassembly is broken" from "we corrupted that packet ourselves". */
	tc_tcp_mux *a = tc_tcp_mux_new(kIpA, kIpB, out_a, NULL);
	tc_tcp_mux *b = tc_tcp_mux_new(kIpB, kIpA, out_b, NULL);
	if (a == NULL || b == NULL)
		fail("could not create the muxes");
	for (uint16_t p = 1; p <= 4; p++)
		(void)tc_tcp_mux_listen(b, p);

	tc_tcp_conn *clean = NULL;
	tc_tcp_conn *clean_srv = NULL;
	uint64_t now = 1000;
	uint8_t next_write = 0, next_read = 0;
	unsigned long bytes_verified = 0;

	(void)tc_tcp_mux_connect(a, 1, now, &clean);
	uint16_t clean_port = (clean != NULL) ? tc_tcp_local_port(clean) : 0;

	for (unsigned long i = 0; i < iters; i++) {
		now += 1 + rng_below(32);

		/* Deliver a packet, damaging it unless it belongs to the clean
		 * connection. */
		for (size_t k = 0; k < QUEUE; k++) {
			if (!q[k].used)
				continue;
			q[k].used = false;
			uint8_t pkt[MAXPKT];
			size_t len = q[k].len;
			memcpy(pkt, q[k].data, len);

			uint16_t sport = (uint16_t)((uint16_t)pkt[40] << 8 | pkt[41]);
			uint16_t dport = (uint16_t)((uint16_t)pkt[42] << 8 | pkt[43]);
			bool is_clean = (sport == clean_port || dport == clean_port);
			if (!is_clean && (rng_next() % 3u) == 0)
				damage(pkt, &len);

			delivered++;
			(void)tc_tcp_mux_input(q[k].to_b ? b : a, pkt, len, now);
			break; /* one per iteration, so time advances between them */
		}

		tc_tcp_mux_tick(a, now);
		tc_tcp_mux_tick(b, now);

		/* Accept whatever arrived on B. */
		tc_tcp_conn *acc;
		while ((acc = tc_tcp_mux_accept(b)) != NULL) {
			if (tc_tcp_local_port(acc) == 1 && clean_srv == NULL &&
			    tc_tcp_remote_port(acc) == clean_port)
				clean_srv = acc;
		}

		/* Ordinary traffic on the clean connection, whose bytes are a
		 * counter -- so a reassembly bug that reordered or duplicated them
		 * is caught even though nothing crashed. */
		if (clean != NULL && tc_tcp_is_established(clean) &&
		    (rng_next() % 4u) == 0) {
			uint8_t buf[64];
			size_t want = 1 + rng_below(sizeof buf);
			for (size_t j = 0; j < want; j++)
				buf[j] = next_write++;
			size_t wrote = 0;
			if (tc_tcp_write(clean, buf, want, &wrote, now) == TC_OK)
				next_write = (uint8_t)(next_write - (want - wrote));
		}
		if (clean_srv != NULL) {
			uint8_t buf[256];
			size_t got = 0;
			if (tc_tcp_read(clean_srv, buf, sizeof buf, &got) == TC_OK) {
				if (got > sizeof buf)
					fail("read reported more bytes than the buffer holds");
				for (size_t j = 0; j < got; j++) {
					if (buf[j] != next_read)
						fail("the clean connection delivered the wrong byte: "
						     "reassembly reordered or duplicated data");
					next_read++;
					bytes_verified++;
				}
			}
		}

		/* Drain the churn connections and answer their FINs. Without this
		 * they sit in ESTABLISHED for ever and the tables never turn over. */
		churn_service(a, clean, clean_srv, now);
		churn_service(b, clean, clean_srv, now);

		/* And a churn of short-lived connections, so the table, the accept
		 * queue and the reaper stay busy while the damage lands. */
		switch (rng_next() % 16u) {
		case 0: {
			tc_tcp_conn *c = NULL;
			(void)tc_tcp_mux_connect(a, (uint16_t)(1 + rng_below(6)), now, &c);
			break;
		}
		case 1:
			/* Reaping frees connections, so every pointer held across it has
			 * to be re-checked -- including the clean pair, which a stray
			 * reset could have closed. Skipping that is a use-after-free in
			 * the harness, and it would be reported against the stack. */
			tc_tcp_mux_reap(a);
			tc_tcp_mux_reap(b);
			clean = still_present(a, clean);
			clean_srv = still_present(b, clean_srv);
			break;
		case 2: /* a graceful close: FIN, the wait states, then reaped */
			churn_pick(a, clean, clean_srv, false, now);
			break;
		case 3: /* and an abrupt one: reset mid-stream */
			churn_pick(a, clean, clean_srv, true, now);
			break;
		default:
			break;
		}
	}

	tc_tcp_mux_stats sa, sb;
	tc_tcp_mux_get_stats(a, &sa);
	tc_tcp_mux_get_stats(b, &sb);

	/* Assertions about the harness itself, not the code under test. A fuzzer
	 * that stopped reaching ESTABLISHED would look exactly like one that
	 * found no bugs. */
	if (sb.accepted == 0)
		fail("no connection was ever accepted: the fuzzer never reached the "
		     "state machine, so it proved nothing");
	if (bytes_verified == 0)
		fail("no bytes were ever carried end to end: the integrity check "
		     "never ran");
	if (corrupted == 0)
		fail("nothing was ever corrupted: this was not a fuzz run");
	if (sa.reaped == 0 || sb.reaped == 0)
		fail("no connection was ever reaped: nothing closed, so the tables "
		     "filled once and the close paths went unexercised");
	if (sb.accepted <= TC_TCP_MAX_CONNS)
		fail("the connection table never turned over: every accept fitted in "
		     "one tableful, so a long run covered no more than a short one");

	tc_tcp_mux_free(a);
	tc_tcp_mux_free(b);
	printf("ok   fuzz_tcp                 %lu iterations, no crashes "
	       "(%llu accepted, %llu reaped, %lu of %lu packets corrupted, "
	       "%lu bytes "
	       "verified)\n",
	       iters, (unsigned long long)sb.accepted,
	       (unsigned long long)(sa.reaped + sb.reaped), corrupted, delivered,
	       bytes_verified);
	return 0;
}
