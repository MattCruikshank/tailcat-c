/* SPDX-License-Identifier: BSD-3-Clause
 *
 * WireGuard Noise IKpsk2 handshake and transport tests.
 *
 * These drive both roles in-process. They establish that the implementation
 * agrees with itself and that the security properties hold; agreement with
 * the real WireGuard is what tests/livewg.c checks, against wireguard-go.
 */

#include "tc/noise.h"

#include "tc/crypto.h"
#include "tctest.h"

/* handshake runs a full exchange and leaves both sides with a session. */
static void do_handshake(tc_wg_identity *ia, tc_wg_identity *ir,
                         tc_wg_session *si, tc_wg_session *sr,
                         const uint8_t *psk)
{
	tc_wg_handshake hi, hr;
	uint8_t init[TC_WG_INITIATION_SIZE];
	uint8_t resp[TC_WG_RESPONSE_SIZE];

	TCT_EQ_INT(tc_wg_handshake_init(&hi, ia, ir->public_key, psk), TC_OK);
	TCT_EQ_INT(tc_wg_handshake_init(&hr, ir, NULL, psk), TC_OK);

	TCT_EQ_INT(tc_wg_create_initiation(init, &hi, ia, 0), TC_OK);

	uint8_t peer[32], ts[TC_WG_TIMESTAMP_LEN];
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, ir, init, peer, ts), TC_OK);
	TCT_EQ_MEM(peer, ia->public_key, 32);

	TCT_EQ_INT(tc_wg_create_response(resp, &hr, ir, 0), TC_OK);
	TCT_EQ_INT(tc_wg_consume_response(&hi, ia, resp), TC_OK);

	TCT_EQ_INT(tc_wg_begin_session(si, &hi), TC_OK);
	TCT_EQ_INT(tc_wg_begin_session(sr, &hr), TC_OK);
}

static void test_full_handshake(void)
{
	TCT_CASE("a full handshake agrees on keys in both directions");

	tc_wg_identity ia, ir;
	TCT_EQ_INT(tc_wg_identity_generate(&ia), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&ir), TC_OK);

	uint8_t psk[32];
	TCT_EQ_INT(tc_random_bytes(psk, sizeof psk), TC_OK);

	tc_wg_session si, sr;
	do_handshake(&ia, &ir, &si, &sr, psk);

	TCT_TRUE(si.is_initiator);
	TCT_TRUE(!sr.is_initiator);

	/* The initiator's send key is the responder's receive key, and the
	 * indices are crossed. */
	TCT_EQ_MEM(si.send_key, sr.recv_key, 32);
	TCT_EQ_MEM(si.recv_key, sr.send_key, 32);
	TCT_TRUE(memcmp(si.send_key, si.recv_key, 32) != 0);
	TCT_EQ_INT(si.local_index, sr.remote_index);
	TCT_EQ_INT(sr.local_index, si.remote_index);

	TCT_CASE("transport works initiator to responder");
	static const char kMsg[] = "the quick brown fox";
	uint8_t pkt[256], got[256];
	size_t pkt_len = 0, got_len = 0;

	TCT_EQ_INT(tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &si, kMsg,
	                         sizeof kMsg - 1),
	           TC_OK);
	TCT_EQ_INT(pkt_len, TC_WG_TRANSPORT_HEADER_SIZE + sizeof kMsg - 1 +
	                        TC_WG_TAG_LEN);
	TCT_EQ_INT(pkt[0], TC_WG_MSG_TRANSPORT);

	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &sr, pkt, pkt_len),
	           TC_OK);
	TCT_EQ_INT(got_len, sizeof kMsg - 1);
	TCT_EQ_MEM(got, kMsg, sizeof kMsg - 1);

	TCT_CASE("and responder to initiator");
	static const char kReply[] = "jumps over the lazy dog";
	TCT_EQ_INT(tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &sr, kReply,
	                         sizeof kReply - 1),
	           TC_OK);
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &si, pkt, pkt_len),
	           TC_OK);
	TCT_EQ_MEM(got, kReply, sizeof kReply - 1);

	TCT_CASE("an empty payload is carried");
	TCT_EQ_INT(tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &si, NULL, 0), TC_OK);
	TCT_EQ_INT(pkt_len, TC_WG_TRANSPORT_HEADER_SIZE + TC_WG_TAG_LEN);
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &sr, pkt, pkt_len),
	           TC_OK);
	TCT_EQ_INT(got_len, 0);

	TCT_CASE("handshake state is wiped once the session starts");
	tc_wg_session_clear(&si);
	tc_wg_session_clear(&sr);
	TCT_TRUE(tc_ct_is_zero(&si, sizeof si));
}

static void test_psk_matters(void)
{
	TCT_CASE("a mismatched pre-shared key fails the response");
	/* This is the property that keeps a DERP operator who has seen both
	 * public keys out of the tunnel. */
	tc_wg_identity ia, ir;
	TCT_EQ_INT(tc_wg_identity_generate(&ia), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&ir), TC_OK);

	uint8_t psk_a[32], psk_b[32];
	memset(psk_a, 0x11, sizeof psk_a);
	memset(psk_b, 0x22, sizeof psk_b);

	tc_wg_handshake hi, hr;
	uint8_t init[TC_WG_INITIATION_SIZE], resp[TC_WG_RESPONSE_SIZE];

	TCT_EQ_INT(tc_wg_handshake_init(&hi, &ia, ir.public_key, psk_a), TC_OK);
	TCT_EQ_INT(tc_wg_handshake_init(&hr, &ir, NULL, psk_b), TC_OK);

	TCT_EQ_INT(tc_wg_create_initiation(init, &hi, &ia, 0), TC_OK);
	/* The initiation does not involve the PSK, so it still decrypts. */
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, &ir, init, NULL, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_create_response(resp, &hr, &ir, 0), TC_OK);
	/* The response does, so it does not verify. */
	TCT_EQ_INT(tc_wg_consume_response(&hi, &ia, resp), TC_ERR_INVAL);

	TCT_CASE("a zero pre-shared key still completes (plain IK)");
	tc_wg_session si, sr;
	do_handshake(&ia, &ir, &si, &sr, NULL);
	TCT_EQ_MEM(si.send_key, sr.recv_key, 32);
}

static void test_rejections(void)
{
	tc_wg_identity ia, ir, io;
	TCT_EQ_INT(tc_wg_identity_generate(&ia), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&ir), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&io), TC_OK);

	tc_wg_handshake hi, hr;
	uint8_t init[TC_WG_INITIATION_SIZE];

	TCT_EQ_INT(tc_wg_handshake_init(&hi, &ia, ir.public_key, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_create_initiation(init, &hi, &ia, 0), TC_OK);

	TCT_CASE("an initiation for someone else fails mac1");
	/* mac1 is keyed by the recipient's public key, so a third party cannot
	 * be made to do the Diffie-Hellman. */
	TCT_EQ_INT(tc_wg_handshake_init(&hr, &io, NULL, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, &io, init, NULL, NULL),
	           TC_ERR_INVAL);

	TCT_CASE("corrupting any authenticated byte is rejected");
	/* Everything up to the start of mac2 is covered by either the AEAD tags
	 * or mac1, so a single flipped bit anywhere in that range must fail. */
	const size_t kMac2Off = TC_WG_INITIATION_SIZE - TC_WG_MAC_LEN;
	for (size_t off = 0; off < kMac2Off; off++) {
		uint8_t bad[TC_WG_INITIATION_SIZE];
		memcpy(bad, init, sizeof bad);
		bad[off] ^= 0x40;
		tc_wg_handshake h;
		TCT_EQ_INT(tc_wg_handshake_init(&h, &ir, NULL, NULL), TC_OK);
		TCT_TRUE(tc_wg_consume_initiation(&h, &ir, bad, NULL, NULL) != TC_OK);
	}

	TCT_CASE("this layer does not check mac2");
	/* mac2 only carries meaning once a peer under load has issued a cookie,
	 * and WireGuard ignores it otherwise, so tc_wg_consume_initiation accepts
	 * a modified one. The check lives a layer up in tc_wg_peer, which knows
	 * whether it is under load and holds the secret the cookie is derived
	 * from; tests/test_wgpeer.c covers it there. Asserting the tolerance here
	 * keeps the division visible rather than looking like an oversight. */
	for (size_t off = kMac2Off; off < TC_WG_INITIATION_SIZE; off++) {
		uint8_t bad[TC_WG_INITIATION_SIZE];
		memcpy(bad, init, sizeof bad);
		bad[off] ^= 0x40;
		tc_wg_handshake h;
		TCT_EQ_INT(tc_wg_handshake_init(&h, &ir, NULL, NULL), TC_OK);
		TCT_EQ_INT(tc_wg_consume_initiation(&h, &ir, bad, NULL, NULL), TC_OK);
	}

	TCT_CASE("a wrong message type is rejected");
	uint8_t bad[TC_WG_INITIATION_SIZE];
	memcpy(bad, init, sizeof bad);
	bad[0] = TC_WG_MSG_RESPONSE;
	TCT_EQ_INT(tc_wg_handshake_init(&hr, &ir, NULL, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, &ir, bad, NULL, NULL),
	           TC_ERR_INVAL);

	TCT_CASE("an initiation from an unexpected peer is refused");
	/* With the peer pinned, only that peer's initiation is accepted. */
	TCT_EQ_INT(tc_wg_handshake_init(&hr, &ir, io.public_key, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, &ir, init, NULL, NULL),
	           TC_ERR_INVAL);

	TCT_CASE("a response for the wrong handshake index is refused");
	TCT_EQ_INT(tc_wg_handshake_init(&hr, &ir, NULL, NULL), TC_OK);
	TCT_EQ_INT(tc_wg_consume_initiation(&hr, &ir, init, NULL, NULL), TC_OK);
	uint8_t resp[TC_WG_RESPONSE_SIZE];
	TCT_EQ_INT(tc_wg_create_response(resp, &hr, &ir, 0), TC_OK);
	resp[8] ^= 0xff; /* receiver index */
	TCT_EQ_INT(tc_wg_consume_response(&hi, &ia, resp), TC_ERR_INVAL);

	TCT_CASE("a small-order peer key is refused at setup");
	uint8_t zero[32] = { 0 };
	tc_wg_handshake h;
	TCT_EQ_INT(tc_wg_handshake_init(&h, &ia, zero, NULL), TC_ERR_INVAL);
}

static void test_transport_rejections(void)
{
	tc_wg_identity ia, ir;
	TCT_EQ_INT(tc_wg_identity_generate(&ia), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&ir), TC_OK);

	tc_wg_session si, sr;
	do_handshake(&ia, &ir, &si, &sr, NULL);

	uint8_t pkt[256], got[256];
	size_t pkt_len = 0, got_len = 0;
	static const char kMsg[] = "payload";
	TCT_EQ_INT(tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &si, kMsg,
	                         sizeof kMsg - 1),
	           TC_OK);

	TCT_CASE("a flipped bit anywhere in the ciphertext is rejected");
	for (size_t off = TC_WG_TRANSPORT_HEADER_SIZE; off < pkt_len; off++) {
		uint8_t bad[256];
		memcpy(bad, pkt, pkt_len);
		bad[off] ^= 1;
		tc_wg_session tmp = sr;
		TCT_TRUE(tc_wg_decrypt(got, sizeof got, &got_len, &tmp, bad,
		                       pkt_len) != TC_OK);
	}

	TCT_CASE("a tampered counter is rejected");
	uint8_t bad[256];
	memcpy(bad, pkt, pkt_len);
	bad[8] ^= 1;
	tc_wg_session tmp = sr;
	TCT_TRUE(tc_wg_decrypt(got, sizeof got, &got_len, &tmp, bad, pkt_len) !=
	         TC_OK);

	TCT_CASE("a packet for another session index is rejected");
	memcpy(bad, pkt, pkt_len);
	bad[4] ^= 0xff;
	tmp = sr;
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &tmp, bad, pkt_len),
	           TC_ERR_INVAL);

	TCT_CASE("a truncated packet is rejected");
	tmp = sr;
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &tmp, pkt,
	                         TC_WG_TRANSPORT_HEADER_SIZE + 4),
	           TC_ERR_TRUNC);

	TCT_CASE("a packet from the wrong direction does not decrypt");
	/* si and sr have crossed keys, so the initiator cannot open its own. */
	tmp = si;
	TCT_TRUE(tc_wg_decrypt(got, sizeof got, &got_len, &tmp, pkt, pkt_len) !=
	         TC_OK);
}

static void test_replay_window(void)
{
	tc_wg_identity ia, ir;
	TCT_EQ_INT(tc_wg_identity_generate(&ia), TC_OK);
	TCT_EQ_INT(tc_wg_identity_generate(&ir), TC_OK);

	tc_wg_session si, sr;
	do_handshake(&ia, &ir, &si, &sr, NULL);

	uint8_t got[256];
	size_t got_len = 0;

	/* Build a run of packets, keeping each so it can be replayed. */
	enum { N = 64 };
	static uint8_t pkts[N][256];
	static size_t lens[N];
	for (size_t i = 0; i < N; i++) {
		uint8_t body = (uint8_t)i;
		TCT_EQ_INT(tc_wg_encrypt(pkts[i], sizeof pkts[i], &lens[i], &si, &body,
		                         1),
		           TC_OK);
	}

	TCT_CASE("in-order delivery is accepted");
	for (size_t i = 0; i < N; i++)
		TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &sr, pkts[i],
		                         lens[i]),
		           TC_OK);

	TCT_CASE("every one of those replayed is rejected");
	for (size_t i = 0; i < N; i++)
		TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &sr, pkts[i],
		                         lens[i]),
		           TC_ERR_INVAL);

	TCT_CASE("out-of-order within the window is accepted once");
	tc_wg_session s2, i2;
	do_handshake(&ia, &ir, &i2, &s2, NULL);
	static uint8_t p2[N][256];
	static size_t l2[N];
	for (size_t i = 0; i < N; i++) {
		uint8_t body = (uint8_t)i;
		TCT_EQ_INT(tc_wg_encrypt(p2[i], sizeof p2[i], &l2[i], &i2, &body, 1),
		           TC_OK);
	}
	/* Deliver the highest first, then the rest backwards. */
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s2, p2[N - 1],
	                         l2[N - 1]),
	           TC_OK);
	for (size_t i = N - 1; i-- > 0;)
		TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s2, p2[i], l2[i]),
		           TC_OK);
	/* And none of them a second time. */
	for (size_t i = 0; i < N; i++)
		TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s2, p2[i], l2[i]),
		           TC_ERR_INVAL);

	TCT_CASE("a counter far below the window is rejected");
	tc_wg_session s3, i3;
	do_handshake(&ia, &ir, &i3, &s3, NULL);
	uint8_t first[256];
	size_t first_len = 0;
	uint8_t body = 1;
	TCT_EQ_INT(tc_wg_encrypt(first, sizeof first, &first_len, &i3, &body, 1),
	           TC_OK);
	/* Jump the sender far ahead, past the window. */
	i3.send_counter = TC_WG_REPLAY_WINDOW_BITS + 100;
	uint8_t far[256];
	size_t far_len = 0;
	TCT_EQ_INT(tc_wg_encrypt(far, sizeof far, &far_len, &i3, &body, 1), TC_OK);
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s3, far, far_len),
	           TC_OK);
	/* The old packet is now too far behind to be judged, so it is refused. */
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s3, first, first_len),
	           TC_ERR_INVAL);

	TCT_CASE("a forged packet does not move the window");
	/* Recording before verification would let a forgery with a huge counter
	 * slide the window forward and drop real traffic. */
	tc_wg_session s4, i4;
	do_handshake(&ia, &ir, &i4, &s4, NULL);
	uint8_t good[256];
	size_t good_len = 0;
	TCT_EQ_INT(tc_wg_encrypt(good, sizeof good, &good_len, &i4, &body, 1),
	           TC_OK);

	uint8_t forged[256];
	memcpy(forged, good, good_len);
	forged[8] = 0xff; /* enormous counter */
	forged[9] = 0xff;
	forged[10] = 0xff;
	TCT_TRUE(tc_wg_decrypt(got, sizeof got, &got_len, &s4, forged, good_len) !=
	         TC_OK);
	/* The genuine packet still arrives. */
	TCT_EQ_INT(tc_wg_decrypt(got, sizeof got, &got_len, &s4, good, good_len),
	           TC_OK);
}

static void test_timestamp(void)
{
	TCT_CASE("TAI64N is well formed and whitened");
	uint8_t ts[TC_WG_TIMESTAMP_LEN];
	tc_wg_timestamp(ts);

	/* Seconds are big-endian, offset by 2^62 + 10, so the top byte is 0x40
	 * for any plausible date. */
	TCT_EQ_INT(ts[0], 0x40);

	/* The low 24 bits of the nanosecond field are cleared. */
	TCT_EQ_INT(ts[9], 0);
	TCT_EQ_INT(ts[10], 0);
	TCT_EQ_INT(ts[11], 0);

	TCT_CASE("timestamps do not go backwards");
	uint8_t later[TC_WG_TIMESTAMP_LEN];
	tc_wg_timestamp(later);
	TCT_TRUE(memcmp(later, ts, sizeof ts) >= 0);
}

static void test_identity(void)
{
	TCT_CASE("a private key derives a stable public key");
	uint8_t priv[32];
	memset(priv, 0x5a, sizeof priv);

	tc_wg_identity a, b;
	TCT_EQ_INT(tc_wg_identity_from_private(&a, priv), TC_OK);
	TCT_EQ_INT(tc_wg_identity_from_private(&b, priv), TC_OK);
	TCT_EQ_MEM(a.public_key, b.public_key, 32);

	TCT_CASE("the stored private key is clamped");
	TCT_EQ_INT(a.private_key[0] & 7, 0);
	TCT_EQ_INT(a.private_key[31] & 0x80, 0);
	TCT_EQ_INT(a.private_key[31] & 0x40, 0x40);
}

int main(void)
{
	test_identity();
	test_timestamp();
	test_full_handshake();
	test_psk_matters();
	test_rejections();
	test_transport_rejections();
	test_replay_window();
	return tct_report("noise");
}
