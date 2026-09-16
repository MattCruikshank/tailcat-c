/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Minimal userspace TCP over IPv6. See tcp.h for the scope.
 *
 * Sequence arithmetic is the thing to be careful about here. TCP sequence
 * numbers wrap, so every comparison has to be done modulo 2^32 -- writing
 * `a < b` on raw sequence numbers works right up until a connection crosses
 * the wrap point, and then silently corrupts the stream. seq_le(), seq_gt()
 * and seq_ge() exist so that no comparison in this file is ever written
 * directly on raw sequence numbers.
 */

#include "tc/tcp.h"

#include "tc/crypto.h"

#include <stdlib.h>
#include <string.h>

/* ---- sequence arithmetic --------------------------------------------- */

/* All comparisons are modulo 2^32: the difference is taken as a signed
 * 32-bit value, so it stays correct across the wrap. */
static bool seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static bool seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
static bool seq_ge(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }

/* ---- header field access --------------------------------------------- */

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* TCP flags. */
enum {
	TH_FIN = 0x01,
	TH_SYN = 0x02,
	TH_RST = 0x04,
	TH_PSH = 0x08,
	TH_ACK = 0x10
};

/* ---- connection state ------------------------------------------------ */

typedef struct {
	uint32_t seq;  /* sequence of the first byte */
	uint16_t len;  /* payload length */
	bool used;
	uint8_t data[TC_TCP_MSS];
} ooo_seg;

struct tc_tcp_conn {
	uint8_t local_ip[TC_IPV6_ADDR_LEN];
	uint8_t remote_ip[TC_IPV6_ADDR_LEN];
	uint16_t local_port;
	uint16_t remote_port;

	tc_tcp_output_fn out;
	void *out_ctx;

	tc_tcp_state state;

	/* Send sequence space (RFC 793 terms). */
	uint32_t snd_una; /* oldest unacknowledged */
	uint32_t snd_nxt; /* next to send */
	uint32_t iss;     /* initial send sequence */
	uint32_t snd_wnd; /* the peer's advertised window */

	/* Receive sequence space. */
	uint32_t rcv_nxt; /* next expected */
	uint32_t irs;     /* initial receive sequence */

	/* Send buffer: bytes queued but not yet acknowledged, plus bytes not yet
	 * sent. snd_una corresponds to sndbuf[snd_off]. */
	uint8_t *sndbuf;
	size_t snd_len; /* bytes held, from snd_una forward */
	size_t snd_off; /* ring start */

	/* Receive buffer: in-order bytes waiting for the caller. */
	uint8_t *rcvbuf;
	size_t rcv_len;
	size_t rcv_off;

	ooo_seg *ooo;

	/* Congestion control. */
	uint32_t cwnd;
	uint32_t ssthresh;
	uint32_t dupacks;

	/* Round-trip estimation, in milliseconds, per Jacobson/Karels. */
	int32_t srtt;
	int32_t rttvar;
	uint32_t rto;
	/* The segment being timed, and when it went out. Karn's algorithm: a
	 * retransmitted segment is never used for a sample, because there is no
	 * way to tell which transmission the ACK refers to. */
	bool rtt_timing;
	uint32_t rtt_seq;
	uint64_t rtt_start;

	uint64_t rto_deadline;  /* 0 = no retransmission timer */
	uint64_t delack_deadline;
	uint64_t timewait_deadline;
	unsigned rto_backoff;

	bool fin_queued;   /* the caller has asked to close the write side */
	bool fin_sent;     /* our FIN has gone out */
	bool fin_received; /* the peer's FIN has arrived in order */
	bool reset;

	/* The most recent time any entry point was given. tc_tcp_read has no
	 * clock of its own but may need to emit a window update. */
	uint64_t last_now;

	tc_tcp_stats stats;
};

/* Initial retransmission timeout before any RTT sample, per RFC 6298. */
#define RTO_INITIAL 1000u
#define RTO_MIN 200u
#define RTO_MAX 60000u
#define DELACK_MS 40u
#define TIMEWAIT_MS 10000u
#define MAX_RETRIES 12

const char *tc_tcp_state_name(tc_tcp_state s)
{
	switch (s) {
	case TC_TCP_CLOSED:       return "CLOSED";
	case TC_TCP_LISTEN:       return "LISTEN";
	case TC_TCP_SYN_SENT:     return "SYN_SENT";
	case TC_TCP_SYN_RECEIVED: return "SYN_RECEIVED";
	case TC_TCP_ESTABLISHED:  return "ESTABLISHED";
	case TC_TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
	case TC_TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
	case TC_TCP_CLOSING:      return "CLOSING";
	case TC_TCP_TIME_WAIT:    return "TIME_WAIT";
	case TC_TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
	case TC_TCP_LAST_ACK:     return "LAST_ACK";
	default:                  return "?";
	}
}

/* ---- checksum -------------------------------------------------------- */

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
	size_t i = 0;
	for (; i + 1 < n; i += 2)
		sum += (uint32_t)p[i] << 8 | p[i + 1];
	if (i < n)
		sum += (uint32_t)p[i] << 8; /* odd trailing byte, zero-padded */
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* tcp_checksum computes the TCP checksum over the IPv6 pseudo-header and the
 * segment. The pseudo-header binds the segment to its addresses, so a packet
 * delivered to the wrong peer fails the check rather than being accepted. */
static uint16_t tcp_checksum(const uint8_t *src, const uint8_t *dst,
                             const uint8_t *seg, size_t seg_len)
{
	uint32_t sum = 0;
	uint8_t pseudo[8];

	sum = csum_add(sum, src, TC_IPV6_ADDR_LEN);
	sum = csum_add(sum, dst, TC_IPV6_ADDR_LEN);
	wr32(pseudo, (uint32_t)seg_len);
	pseudo[4] = 0;
	pseudo[5] = 0;
	pseudo[6] = 0;
	pseudo[7] = 6; /* next header: TCP */
	sum = csum_add(sum, pseudo, sizeof pseudo);
	sum = csum_add(sum, seg, seg_len);

	return csum_fold(sum);
}

/* ---- buffers --------------------------------------------------------- */

static size_t snd_space(const tc_tcp_conn *c)
{
	return TC_TCP_SNDBUF - c->snd_len;
}

static void snd_push(tc_tcp_conn *c, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		c->sndbuf[(c->snd_off + c->snd_len + i) % TC_TCP_SNDBUF] = p[i];
	c->snd_len += n;
}

static uint8_t snd_at(const tc_tcp_conn *c, size_t idx)
{
	return c->sndbuf[(c->snd_off + idx) % TC_TCP_SNDBUF];
}

static void snd_drop(tc_tcp_conn *c, size_t n)
{
	if (n > c->snd_len)
		n = c->snd_len;
	c->snd_off = (c->snd_off + n) % TC_TCP_SNDBUF;
	c->snd_len -= n;
}

static size_t rcv_space(const tc_tcp_conn *c)
{
	return TC_TCP_RCVBUF - c->rcv_len;
}

static void rcv_push(tc_tcp_conn *c, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		c->rcvbuf[(c->rcv_off + c->rcv_len + i) % TC_TCP_RCVBUF] = p[i];
	c->rcv_len += n;
}

/* ---- transmission ---------------------------------------------------- */

static void update_rto(tc_tcp_conn *c, int32_t sample)
{
	if (sample < 1)
		sample = 1;
	if (c->srtt < 0) {
		c->srtt = sample;
		c->rttvar = sample / 2;
	} else {
		int32_t delta = sample - c->srtt;
		if (delta < 0)
			delta = -delta;
		c->rttvar = (3 * c->rttvar + delta) / 4;
		c->srtt = (7 * c->srtt + sample) / 8;
	}
	int32_t rto = c->srtt + 4 * c->rttvar;
	if (rto < (int32_t)RTO_MIN)
		rto = (int32_t)RTO_MIN;
	if (rto > (int32_t)RTO_MAX)
		rto = (int32_t)RTO_MAX;
	c->rto = (uint32_t)rto;
}

static uint32_t current_rto(const tc_tcp_conn *c)
{
	uint64_t r = (uint64_t)c->rto << c->rto_backoff;
	if (r > RTO_MAX)
		r = RTO_MAX;
	return (uint32_t)r;
}

static void arm_rto(tc_tcp_conn *c, uint64_t now)
{
	c->rto_deadline = now + current_rto(c);
}

/* send_segment builds and emits one IPv6+TCP packet. */
static void send_segment(tc_tcp_conn *c, uint32_t seq, uint8_t flags,
                         const uint8_t *payload, size_t payload_len,
                         uint64_t now)
{
	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN + TC_TCP_MSS];
	size_t seg_len = TC_TCP_HEADER_LEN + payload_len;

	memset(pkt, 0, TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN);

	/* IPv6 header. */
	pkt[0] = 0x60; /* version 6, traffic class 0 */
	wr16(pkt + 4, (uint16_t)seg_len);
	pkt[6] = 6;  /* next header: TCP */
	pkt[7] = 64; /* hop limit */
	memcpy(pkt + 8, c->local_ip, TC_IPV6_ADDR_LEN);
	memcpy(pkt + 24, c->remote_ip, TC_IPV6_ADDR_LEN);

	/* TCP header. */
	uint8_t *th = pkt + TC_IPV6_HEADER_LEN;
	wr16(th + 0, c->local_port);
	wr16(th + 2, c->remote_port);
	wr32(th + 4, seq);
	wr32(th + 8, (flags & TH_ACK) ? c->rcv_nxt : 0);
	th[12] = 5 << 4; /* data offset: 5 words, no options */
	th[13] = flags;
	/* Advertise what the receive buffer can still take, which is the whole
	 * of our flow control. */
	size_t win = rcv_space(c);
	if (win > 65535)
		win = 65535;
	wr16(th + 14, (uint16_t)win);

	if (payload_len != 0)
		memcpy(th + TC_TCP_HEADER_LEN, payload, payload_len);

	wr16(th + 16, 0);
	uint16_t ck = tcp_checksum(c->local_ip, c->remote_ip, th, seg_len);
	wr16(th + 16, ck);

	c->stats.segs_sent++;
	c->stats.bytes_sent += payload_len;
	(void)c->out(c->out_ctx, pkt, TC_IPV6_HEADER_LEN + seg_len);

	/* Start an RTT sample if one is not already in flight. Karn: never time
	 * a retransmission, so only sample when this seq is newly sent. */
	if (payload_len != 0 && !c->rtt_timing && seq_ge(seq, c->snd_nxt)) {
		c->rtt_timing = true;
		c->rtt_seq = seq + (uint32_t)payload_len;
		c->rtt_start = now;
	}
}

/* in_flight is how much data has been sent but not acknowledged. */
static uint32_t in_flight(const tc_tcp_conn *c)
{
	return c->snd_nxt - c->snd_una;
}

/* try_send pushes out as much queued data as the windows allow. */
static void try_send(tc_tcp_conn *c, uint64_t now)
{
	/* Not SYN_RECEIVED: payload cannot be sent until the handshake finishes,
	 * and in that state the SYN already occupies a sequence number that no
	 * buffered byte corresponds to. */
	if (c->state != TC_TCP_ESTABLISHED && c->state != TC_TCP_CLOSE_WAIT &&
	    c->state != TC_TCP_FIN_WAIT_1)
		return;

	for (;;) {
		uint32_t flight = in_flight(c);
		uint32_t window = c->snd_wnd < c->cwnd ? c->snd_wnd : c->cwnd;
		if (flight >= window)
			break;

		uint32_t usable = window - flight;

		/* in_flight() counts sequence space, snd_len counts buffered bytes,
		 * and they are not the same: SYN and FIN each consume a sequence
		 * number without occupying the buffer. So flight can legitimately
		 * exceed snd_len, and subtracting blind underflows a size_t --
		 * which previously sent a whole MSS of uninitialised send buffer. */
		size_t unsent = (flight <= c->snd_len) ? c->snd_len - flight : 0;
		if (unsent == 0)
			break;

		size_t n = unsent;
		if (n > usable)
			n = usable;
		if (n > TC_TCP_MSS)
			n = TC_TCP_MSS;
		if (n == 0)
			break;

		uint8_t seg[TC_TCP_MSS];
		for (size_t i = 0; i < n; i++)
			seg[i] = snd_at(c, flight + i);

		uint8_t flags = TH_ACK | TH_PSH;
		send_segment(c, c->snd_nxt, flags, seg, n, now);
		c->snd_nxt += (uint32_t)n;

		if (c->rto_deadline == 0)
			arm_rto(c, now);
	}

	/* FIN goes out once everything queued has been sent. */
	if (c->fin_queued && !c->fin_sent && c->snd_len == in_flight(c)) {
		send_segment(c, c->snd_nxt, TH_ACK | TH_FIN, NULL, 0, now);
		c->snd_nxt++;
		c->fin_sent = true;
		if (c->rto_deadline == 0)
			arm_rto(c, now);
		if (c->state == TC_TCP_ESTABLISHED)
			c->state = TC_TCP_FIN_WAIT_1;
		else if (c->state == TC_TCP_CLOSE_WAIT)
			c->state = TC_TCP_LAST_ACK;
	}
}

static void send_ack(tc_tcp_conn *c, uint64_t now)
{
	send_segment(c, c->snd_nxt, TH_ACK, NULL, 0, now);
	c->delack_deadline = 0;
}

static void send_rst(tc_tcp_conn *c, uint32_t seq, uint64_t now)
{
	send_segment(c, seq, TH_RST | TH_ACK, NULL, 0, now);
}

/* ---- reassembly ------------------------------------------------------ */

static void ooo_insert(tc_tcp_conn *c, uint32_t seq, const uint8_t *p,
                       size_t n)
{
	if (n == 0 || n > TC_TCP_MSS)
		return;
	for (size_t i = 0; i < TC_TCP_OOO_SEGS; i++) {
		if (c->ooo[i].used && c->ooo[i].seq == seq)
			return; /* already held */
	}
	for (size_t i = 0; i < TC_TCP_OOO_SEGS; i++) {
		if (!c->ooo[i].used) {
			c->ooo[i].used = true;
			c->ooo[i].seq = seq;
			c->ooo[i].len = (uint16_t)n;
			memcpy(c->ooo[i].data, p, n);
			c->stats.ooo_queued++;
			return;
		}
	}
	/* Full. Dropping is safe: the peer will retransmit. */
	c->stats.ooo_dropped++;
}

/* ooo_drain moves any queued segments that now sit at rcv_nxt into the
 * receive buffer, repeating until the next gap. */
static void ooo_drain(tc_tcp_conn *c)
{
	bool progress = true;
	while (progress) {
		progress = false;
		for (size_t i = 0; i < TC_TCP_OOO_SEGS; i++) {
			if (!c->ooo[i].used)
				continue;
			uint32_t s = c->ooo[i].seq;
			uint32_t e = s + c->ooo[i].len;
			if (seq_gt(s, c->rcv_nxt))
				continue; /* still a gap before it */
			c->ooo[i].used = false;
			if (seq_le(e, c->rcv_nxt))
				continue; /* entirely old */

			/* Trim whatever we already have. */
			uint32_t skip = c->rcv_nxt - s;
			size_t n = c->ooo[i].len - skip;
			if (n > rcv_space(c))
				n = rcv_space(c);
			if (n == 0)
				continue;
			rcv_push(c, c->ooo[i].data + skip, n);
			c->rcv_nxt += (uint32_t)n;
			progress = true;
		}
	}
}

/* ---- lifecycle ------------------------------------------------------- */

tc_tcp_conn *tc_tcp_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                        const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                        tc_tcp_output_fn out, void *out_ctx)
{
	if (local_ip == NULL || remote_ip == NULL || out == NULL)
		return NULL;

	tc_tcp_conn *c = (tc_tcp_conn *)calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;
	c->sndbuf = (uint8_t *)malloc(TC_TCP_SNDBUF);
	c->rcvbuf = (uint8_t *)malloc(TC_TCP_RCVBUF);
	c->ooo = (ooo_seg *)calloc(TC_TCP_OOO_SEGS, sizeof *c->ooo);
	if (c->sndbuf == NULL || c->rcvbuf == NULL || c->ooo == NULL) {
		tc_tcp_free(c);
		return NULL;
	}

	memcpy(c->local_ip, local_ip, TC_IPV6_ADDR_LEN);
	memcpy(c->remote_ip, remote_ip, TC_IPV6_ADDR_LEN);
	c->out = out;
	c->out_ctx = out_ctx;
	c->state = TC_TCP_CLOSED;
	c->srtt = -1;
	c->rto = RTO_INITIAL;
	c->cwnd = 2 * TC_TCP_MSS;
	c->ssthresh = 64 * 1024;
	c->snd_wnd = TC_TCP_MSS;
	return c;
}

void tc_tcp_free(tc_tcp_conn *c)
{
	if (c == NULL)
		return;
	free(c->sndbuf);
	free(c->rcvbuf);
	free(c->ooo);
	free(c);
}

/* pick_iss chooses an initial sequence number. Randomising it is what makes
 * blind injection into the stream impractical for an off-path attacker. */
/* Set by tc_tcp_force_next_iss for the next connection only. */
static uint32_t g_forced_iss;
static bool g_forced_iss_set;

void tc_tcp_force_next_iss(uint32_t iss)
{
	g_forced_iss = iss;
	g_forced_iss_set = true;
}

static uint32_t pick_iss(void)
{
	uint32_t v = 0;
	if (g_forced_iss_set) {
		g_forced_iss_set = false;
		return g_forced_iss;
	}
	if (tc_random_bytes(&v, sizeof v) != TC_OK)
		return 0x1234abcdu;
	return v;
}

int tc_tcp_connect(tc_tcp_conn *c, uint16_t local_port, uint16_t remote_port,
                   uint64_t now_ms)
{
	if (c == NULL || c->state != TC_TCP_CLOSED)
		return TC_ERR_INVAL;

	c->local_port = local_port;
	c->remote_port = remote_port;
	c->iss = pick_iss();
	c->snd_una = c->iss;
	c->snd_nxt = c->iss;
	c->state = TC_TCP_SYN_SENT;

	send_segment(c, c->iss, TH_SYN, NULL, 0, now_ms);
	c->snd_nxt = c->iss + 1;
	arm_rto(c, now_ms);
	return TC_OK;
}

int tc_tcp_listen(tc_tcp_conn *c, uint16_t local_port)
{
	if (c == NULL || c->state != TC_TCP_CLOSED)
		return TC_ERR_INVAL;
	c->local_port = local_port;
	c->state = TC_TCP_LISTEN;
	return TC_OK;
}

/* ---- input ----------------------------------------------------------- */

/* handle_ack processes the acknowledgement field, freeing acknowledged data
 * and driving congestion control. */
static void handle_ack(tc_tcp_conn *c, uint32_t ack, uint64_t now)
{
	if (seq_le(ack, c->snd_una)) {
		/* A duplicate ACK, if it carries no new data and the window is
		 * unchanged. Three of them mean a segment was lost but later ones
		 * are arriving, so resend at once rather than waiting for the RTO. */
		if (ack == c->snd_una && in_flight(c) > 0) {
			c->dupacks++;
			if (c->dupacks == 3) {
				c->ssthresh = in_flight(c) / 2;
				if (c->ssthresh < 2 * TC_TCP_MSS)
					c->ssthresh = 2 * TC_TCP_MSS;
				c->cwnd = c->ssthresh + 3 * TC_TCP_MSS;

				size_t n = c->snd_len;
				if (n > TC_TCP_MSS)
					n = TC_TCP_MSS;
				if (n > 0) {
					uint8_t seg[TC_TCP_MSS];
					for (size_t i = 0; i < n; i++)
						seg[i] = snd_at(c, i);
					send_segment(c, c->snd_una, TH_ACK | TH_PSH, seg, n, now);
					c->stats.fast_retransmits++;
					c->stats.retransmits++;
				}
			}
		}
		return;
	}
	if (seq_gt(ack, c->snd_nxt))
		return; /* acknowledges something we never sent */

	uint32_t acked = ack - c->snd_una;
	c->dupacks = 0;

	/* SYN and FIN each occupy one sequence number but no buffer space. */
	uint32_t data_acked = acked;
	if (c->state == TC_TCP_SYN_SENT || c->state == TC_TCP_SYN_RECEIVED) {
		if (data_acked > 0)
			data_acked--; /* the SYN */
	}
	if (c->fin_sent && seq_ge(ack, c->snd_nxt) && data_acked > 0)
		data_acked--; /* the FIN */

	if (data_acked > c->snd_len)
		data_acked = (uint32_t)c->snd_len;
	snd_drop(c, data_acked);
	c->snd_una = ack;

	/* Karn: only take a sample if the timed segment was never retransmitted,
	 * which rto_backoff being zero implies. */
	if (c->rtt_timing && seq_ge(ack, c->rtt_seq)) {
		if (c->rto_backoff == 0)
			update_rto(c, (int32_t)(now - c->rtt_start));
		c->rtt_timing = false;
	}

	c->rto_backoff = 0;
	if (in_flight(c) == 0)
		c->rto_deadline = 0; /* nothing outstanding */
	else
		arm_rto(c, now);

	/* Slow start doubles the window each round trip; congestion avoidance
	 * adds roughly one segment per round trip. */
	if (c->cwnd < c->ssthresh) {
		c->cwnd += TC_TCP_MSS;
	} else {
		uint32_t inc = (uint32_t)TC_TCP_MSS * TC_TCP_MSS / (c->cwnd ? c->cwnd : 1);
		c->cwnd += inc ? inc : 1;
	}
	if (c->cwnd > TC_TCP_SNDBUF)
		c->cwnd = TC_TCP_SNDBUF;
}

int tc_tcp_input(tc_tcp_conn *c, const uint8_t *ip_pkt, size_t len,
                 uint64_t now_ms)
{
	if (c == NULL || ip_pkt == NULL)
		return TC_ERR_INVAL;
	c->last_now = now_ms;
	if (len < TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN)
		return TC_OK; /* not ours; silently ignore */

	if ((ip_pkt[0] >> 4) != 6 || ip_pkt[6] != 6)
		return TC_OK; /* not IPv6, or not TCP */

	size_t payload_total = rd16(ip_pkt + 4);
	if (payload_total < TC_TCP_HEADER_LEN ||
	    TC_IPV6_HEADER_LEN + payload_total > len)
		return TC_OK;

	/* The addresses must match, in both directions. */
	if (memcmp(ip_pkt + 8, c->remote_ip, TC_IPV6_ADDR_LEN) != 0 ||
	    memcmp(ip_pkt + 24, c->local_ip, TC_IPV6_ADDR_LEN) != 0)
		return TC_OK;

	const uint8_t *th = ip_pkt + TC_IPV6_HEADER_LEN;
	uint16_t sport = rd16(th + 0);
	uint16_t dport = rd16(th + 2);
	if (dport != c->local_port)
		return TC_OK;
	if (c->state != TC_TCP_LISTEN && sport != c->remote_port)
		return TC_OK;

	uint16_t got_ck = rd16(th + 16);
	uint8_t seg[TC_IPV6_HEADER_LEN + 65535];
	if (payload_total > sizeof seg)
		return TC_OK;
	memcpy(seg, th, payload_total);
	wr16(seg + 16, 0);
	if (tcp_checksum(c->remote_ip, c->local_ip, seg, payload_total) != got_ck) {
		c->stats.segs_dropped_checksum++;
		return TC_OK;
	}

	size_t doff = (size_t)(th[12] >> 4) * 4;
	if (doff < TC_TCP_HEADER_LEN || doff > payload_total)
		return TC_OK;

	uint8_t flags = th[13];
	uint32_t seq = rd32(th + 4);
	uint32_t ack = rd32(th + 8);
	uint16_t wnd = rd16(th + 14);
	const uint8_t *data = th + doff;
	size_t data_len = payload_total - doff;

	c->stats.segs_received++;

	if (flags & TH_RST) {
		/* Only a reset that fits the window counts, otherwise an off-path
		 * attacker could tear the connection down by guessing. */
		if (c->state == TC_TCP_SYN_SENT || seq == c->rcv_nxt) {
			c->reset = true;
			c->state = TC_TCP_CLOSED;
		}
		return TC_OK;
	}

	switch (c->state) {
	case TC_TCP_LISTEN:
		if (!(flags & TH_SYN))
			return TC_OK;
		c->remote_port = sport;
		c->irs = seq;
		c->rcv_nxt = seq + 1;
		c->iss = pick_iss();
		c->snd_una = c->iss;
		c->snd_nxt = c->iss;
		c->snd_wnd = wnd ? wnd : TC_TCP_MSS;
		c->state = TC_TCP_SYN_RECEIVED;
		send_segment(c, c->iss, TH_SYN | TH_ACK, NULL, 0, now_ms);
		c->snd_nxt = c->iss + 1;
		arm_rto(c, now_ms);
		return TC_OK;

	case TC_TCP_SYN_SENT:
		if (!(flags & TH_SYN))
			return TC_OK;
		if (flags & TH_ACK) {
			if (ack != c->iss + 1) {
				send_rst(c, ack, now_ms);
				return TC_OK;
			}
			c->irs = seq;
			c->rcv_nxt = seq + 1;
			c->snd_wnd = wnd ? wnd : TC_TCP_MSS;
			handle_ack(c, ack, now_ms);
			c->state = TC_TCP_ESTABLISHED;
			send_ack(c, now_ms);
			try_send(c, now_ms);
		}
		return TC_OK;

	default:
		break;
	}

	if (!(flags & TH_ACK))
		return TC_OK;

	/* A SYN arriving on a synchronised connection is the peer retransmitting
	 * its handshake because our ACK was lost. It has no new data to elicit an
	 * ACK from us, so without answering here the peer retries until it gives
	 * up -- a connection that never establishes over a lossy link. */
	if (flags & TH_SYN)
		send_ack(c, now_ms);

	c->snd_wnd = wnd;
	handle_ack(c, ack, now_ms);

	if (c->state == TC_TCP_SYN_RECEIVED && seq_ge(c->snd_una, c->iss + 1))
		c->state = TC_TCP_ESTABLISHED;

	/* Accept payload. Anything wholly before rcv_nxt is a duplicate; anything
	 * after it goes to the reassembly queue. */
	if (data_len > 0 && !c->fin_received) {
		if (seq_le(seq, c->rcv_nxt) && seq_gt(seq + (uint32_t)data_len,
		                                      c->rcv_nxt)) {
			uint32_t skip = c->rcv_nxt - seq;
			size_t n = data_len - skip;
			if (n > rcv_space(c))
				n = rcv_space(c);
			if (n > 0) {
				rcv_push(c, data + skip, n);
				c->rcv_nxt += (uint32_t)n;
				c->stats.bytes_received += n;
				ooo_drain(c);
			}
			if (c->delack_deadline == 0)
				c->delack_deadline = now_ms + DELACK_MS;
		} else if (seq_gt(seq, c->rcv_nxt)) {
			ooo_insert(c, seq, data, data_len);
			/* A gap: acknowledge immediately so the sender can fast
			 * retransmit rather than wait for its timer. */
			send_ack(c, now_ms);
		} else {
			/* Entirely old: re-acknowledge, since our previous ACK was
			 * evidently lost. */
			send_ack(c, now_ms);
		}
	}

	/* FIN counts only once everything before it has been received. */
	if ((flags & TH_FIN) && seq_le(seq + (uint32_t)data_len, c->rcv_nxt) &&
	    !c->fin_received) {
		c->fin_received = true;
		c->rcv_nxt++;
		send_ack(c, now_ms);

		switch (c->state) {
		case TC_TCP_ESTABLISHED:
			c->state = TC_TCP_CLOSE_WAIT;
			break;
		case TC_TCP_FIN_WAIT_1:
			c->state = seq_ge(c->snd_una, c->snd_nxt) ? TC_TCP_TIME_WAIT
			                                          : TC_TCP_CLOSING;
			if (c->state == TC_TCP_TIME_WAIT)
				c->timewait_deadline = now_ms + TIMEWAIT_MS;
			break;
		case TC_TCP_FIN_WAIT_2:
			c->state = TC_TCP_TIME_WAIT;
			c->timewait_deadline = now_ms + TIMEWAIT_MS;
			break;
		default:
			break;
		}
	}

	/* Our own FIN being acknowledged advances the closing states. */
	if (c->fin_sent && seq_ge(c->snd_una, c->snd_nxt)) {
		switch (c->state) {
		case TC_TCP_FIN_WAIT_1:
			c->state = TC_TCP_FIN_WAIT_2;
			break;
		case TC_TCP_CLOSING:
			c->state = TC_TCP_TIME_WAIT;
			c->timewait_deadline = now_ms + TIMEWAIT_MS;
			break;
		case TC_TCP_LAST_ACK:
			c->state = TC_TCP_CLOSED;
			break;
		default:
			break;
		}
	}

	try_send(c, now_ms);
	return TC_OK;
}

/* ---- timers ---------------------------------------------------------- */

int tc_tcp_tick(tc_tcp_conn *c, uint64_t now_ms)
{
	if (c == NULL)
		return TC_ERR_INVAL;
	c->last_now = now_ms;

	if (c->timewait_deadline != 0 && now_ms >= c->timewait_deadline) {
		c->state = TC_TCP_CLOSED;
		c->timewait_deadline = 0;
	}

	if (c->delack_deadline != 0 && now_ms >= c->delack_deadline)
		send_ack(c, now_ms);

	if (c->rto_deadline != 0 && now_ms >= c->rto_deadline) {
		if (c->rto_backoff >= MAX_RETRIES) {
			c->state = TC_TCP_CLOSED;
			c->reset = true;
			c->rto_deadline = 0;
			return TC_ERR_TIMEOUT;
		}

		/* A timeout means congestion: drop to one segment and start over. */
		c->ssthresh = in_flight(c) / 2;
		if (c->ssthresh < 2 * TC_TCP_MSS)
			c->ssthresh = 2 * TC_TCP_MSS;
		c->cwnd = TC_TCP_MSS;
		c->dupacks = 0;
		c->rtt_timing = false;
		c->rto_backoff++;
		c->stats.retransmits++;

		if (c->state == TC_TCP_SYN_SENT) {
			send_segment(c, c->iss, TH_SYN, NULL, 0, now_ms);
		} else if (c->state == TC_TCP_SYN_RECEIVED) {
			send_segment(c, c->iss, TH_SYN | TH_ACK, NULL, 0, now_ms);
		} else if (c->snd_len > 0) {
			size_t n = c->snd_len;
			if (n > TC_TCP_MSS)
				n = TC_TCP_MSS;
			uint8_t seg[TC_TCP_MSS];
			for (size_t i = 0; i < n; i++)
				seg[i] = snd_at(c, i);
			send_segment(c, c->snd_una, TH_ACK | TH_PSH, seg, n, now_ms);
		} else if (c->fin_sent) {
			send_segment(c, c->snd_nxt - 1, TH_ACK | TH_FIN, NULL, 0, now_ms);
		}
		arm_rto(c, now_ms);
	}

	try_send(c, now_ms);
	return TC_OK;
}

uint64_t tc_tcp_next_deadline(const tc_tcp_conn *c)
{
	uint64_t d = UINT64_MAX;
	if (c == NULL)
		return d;
	if (c->rto_deadline != 0 && c->rto_deadline < d)
		d = c->rto_deadline;
	if (c->delack_deadline != 0 && c->delack_deadline < d)
		d = c->delack_deadline;
	if (c->timewait_deadline != 0 && c->timewait_deadline < d)
		d = c->timewait_deadline;
	return d;
}

/* ---- caller interface ------------------------------------------------ */

int tc_tcp_write(tc_tcp_conn *c, const void *buf, size_t len, size_t *written,
                 uint64_t now_ms)
{
	if (c == NULL || (buf == NULL && len != 0))
		return TC_ERR_INVAL;
	if (written != NULL)
		*written = 0;
	c->last_now = now_ms;
	if (c->fin_queued)
		return TC_ERR_INVAL; /* write side already closed */
	if (c->state != TC_TCP_ESTABLISHED && c->state != TC_TCP_CLOSE_WAIT &&
	    c->state != TC_TCP_SYN_SENT && c->state != TC_TCP_SYN_RECEIVED)
		return TC_ERR_INVAL;

	size_t n = len;
	if (n > snd_space(c))
		n = snd_space(c);
	if (n > 0)
		snd_push(c, (const uint8_t *)buf, n);
	if (written != NULL)
		*written = n;

	try_send(c, now_ms);
	return TC_OK;
}

int tc_tcp_read(tc_tcp_conn *c, void *buf, size_t cap, size_t *nread)
{
	if (c == NULL || (buf == NULL && cap != 0))
		return TC_ERR_INVAL;
	if (nread != NULL)
		*nread = 0;

	size_t space_before = rcv_space(c);
	size_t n = c->rcv_len;
	if (n > cap)
		n = cap;
	uint8_t *p = (uint8_t *)buf;
	for (size_t i = 0; i < n; i++)
		p[i] = c->rcvbuf[(c->rcv_off + i) % TC_TCP_RCVBUF];
	c->rcv_off = (c->rcv_off + n) % TC_TCP_RCVBUF;
	c->rcv_len -= n;
	if (nread != NULL)
		*nread = n;

	/* If the window had closed, the peer has stopped sending and has nothing
	 * to prompt another ACK from us -- so draining the buffer must announce
	 * itself, or the connection deadlocks with both sides waiting. Only when
	 * the window actually reopens by a useful amount, to avoid silly window
	 * syndrome. */
	if (n > 0 && space_before < TC_TCP_MSS && rcv_space(c) >= TC_TCP_MSS &&
	    tc_tcp_is_established(c))
		send_ack(c, c->last_now);

	return TC_OK;
}

int tc_tcp_shutdown_write(tc_tcp_conn *c, uint64_t now_ms)
{
	if (c == NULL)
		return TC_ERR_INVAL;
	if (c->fin_queued)
		return TC_OK;
	if (c->state != TC_TCP_ESTABLISHED && c->state != TC_TCP_CLOSE_WAIT)
		return TC_ERR_INVAL;
	c->fin_queued = true;
	try_send(c, now_ms);
	return TC_OK;
}

void tc_tcp_abort(tc_tcp_conn *c, uint64_t now_ms)
{
	if (c == NULL || c->state == TC_TCP_CLOSED)
		return;
	send_rst(c, c->snd_nxt, now_ms);
	c->state = TC_TCP_CLOSED;
	c->rto_deadline = 0;
	c->delack_deadline = 0;
	c->timewait_deadline = 0;
}

tc_tcp_state tc_tcp_get_state(const tc_tcp_conn *c)
{
	return c == NULL ? TC_TCP_CLOSED : c->state;
}

size_t tc_tcp_readable(const tc_tcp_conn *c)
{
	return c == NULL ? 0 : c->rcv_len;
}

size_t tc_tcp_writable(const tc_tcp_conn *c)
{
	if (c == NULL || c->fin_queued)
		return 0;
	return snd_space(c);
}

bool tc_tcp_read_closed(const tc_tcp_conn *c)
{
	return c != NULL && c->fin_received && c->rcv_len == 0;
}

bool tc_tcp_is_established(const tc_tcp_conn *c)
{
	if (c == NULL)
		return false;
	return c->state == TC_TCP_ESTABLISHED || c->state == TC_TCP_CLOSE_WAIT ||
	       c->state == TC_TCP_FIN_WAIT_1 || c->state == TC_TCP_FIN_WAIT_2;
}

size_t tc_tcp_send_unacked(const tc_tcp_conn *c)
{
	return c == NULL ? 0 : c->snd_len;
}

void tc_tcp_get_stats(const tc_tcp_conn *c, tc_tcp_stats *out)
{
	if (c == NULL || out == NULL)
		return;
	*out = c->stats;
}
