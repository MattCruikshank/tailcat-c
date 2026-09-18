/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH server transport. See tc/sshserver.h.
 */

#include "tc/sshserver.h"

#include "tc/crypto.h"
#include "tc/ed25519.h"
#include "tc/sshwire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEXINIT_MAX 2048
#define HOSTKEY_BLOB_MAX 128

struct tc_ssh_server {
	const tc_ssh_server_opts *opts;

	tc_ssh_cipher in;
	tc_ssh_cipher out;

	char v_client[TC_SSH_VERSION_MAX + 1];
	size_t v_client_len;
	char v_server[TC_SSH_VERSION_MAX + 1];
	size_t v_server_len;

	uint8_t i_client[KEXINIT_MAX];
	size_t i_client_len;
	uint8_t i_server[KEXINIT_MAX];
	size_t i_server_len;

	uint8_t session_id[TC_SSH_HASH_LEN];

	uint8_t host_pub[32];
	uint8_t host_blob[HOSTKEY_BLOB_MAX];
	size_t host_blob_len;

	tc_ssh_channel ch;

	/* One packet in flight each way. Sized for the largest packet the
	 * protocol lets a peer send us, because that is what decode_length may
	 * legitimately ask for. */
	uint8_t rx[TC_SSH_MAX_PACKET];
	uint8_t payload[TC_SSH_MAX_PAYLOAD + 64];
	uint8_t tx[TC_SSH_MAX_PACKET];

	/* Channel data received but not yet handed to the application. */
	const uint8_t *pending;
	size_t pending_len;
	bool peer_eof;

	/* True while a key exchange is running. recv_packet handles a KEXINIT by
	 * starting a rekey, so without this the exchange's own messages would
	 * start another one, recursively. */
	bool in_kex;
	/* Cleared once the first exchange has produced a session id, which is
	 * what distinguishes a rekey from the opening handshake. */
	bool kex_done;
	/* Exchanges after the first. Exposed so a test can assert that a rekey
	 * actually happened rather than that the transfer merely succeeded --
	 * a client that ignored RekeyLimit would pass every other check. */
	unsigned rekeys;
};

static int kex_exchange(tc_ssh_server *s);

/* ---- stream helpers ---------------------------------------------------- */

static int read_full(tc_ssh_server *s, uint8_t *buf, size_t want)
{
	size_t got = 0;
	while (got < want) {
		size_t n = 0;
		int rc = s->opts->read(s->opts->io_ctx, buf + got, want - got, &n);
		if (rc != TC_OK)
			return rc;
		if (n == 0)
			return TC_ERR_CLOSED;
		got += n;
	}
	return TC_OK;
}

static int write_all(tc_ssh_server *s, const uint8_t *buf, size_t len)
{
	return s->opts->write(s->opts->io_ctx, buf, len);
}

/* ---- version exchange -------------------------------------------------- */

/* read_version_line reads one CR LF terminated line.
 *
 * RFC 4253 4.2 lets a server send any number of lines before its
 * identification, for legal banners, and requires a client to skip them. The
 * same courtesy is extended here in the other direction: a client that sends
 * one is unusual but not wrong, and dropping the connection over it would be
 * a needless incompatibility. The count is bounded so a peer cannot hold the
 * connection open sending banner lines for ever. */
static int read_version_line(tc_ssh_server *s, char *out, size_t cap,
                             size_t *out_len)
{
	for (int line = 0; line < 64; line++) {
		size_t n = 0;
		for (;;) {
			uint8_t ch;
			int rc = read_full(s, &ch, 1);
			if (rc != TC_OK)
				return rc;
			if (ch == '\n')
				break;
			if (n + 1 >= cap)
				return TC_ERR_TOOMANY;
			out[n++] = (char)ch;
		}
		/* Strip the CR, which is part of the terminator and must not reach
		 * the exchange hash. */
		if (n > 0 && out[n - 1] == '\r')
			n--;
		out[n] = '\0';

		if (n >= 4 && memcmp(out, "SSH-", 4) == 0) {
			*out_len = n;
			return TC_OK;
		}
		/* Anything else is a banner line: skipped. */
	}
	return TC_ERR_TOOMANY;
}

/* ---- packets ----------------------------------------------------------- */

static int send_packet(tc_ssh_server *s, const uint8_t *payload, size_t len)
{
	/* The sequence number is the cipher nonce, so wrapping it would reuse a
	 * keystream. Rekeying is what a long-lived session is supposed to do
	 * here; since this server does not implement it, it stops instead. */
	if (s->out.seq == UINT32_MAX)
		return TC_ERR_TOOMANY;

	size_t n = 0;
	int rc = tc_ssh_packet_encode(s->tx, sizeof s->tx, &n, payload, len,
	                              &s->out);
	if (rc != TC_OK)
		return rc;
	return write_all(s, s->tx, n);
}

/* recv_packet reads one packet and returns its payload in s->payload.
 *
 * Transport-layer noise -- IGNORE, DEBUG, UNIMPLEMENTED -- is consumed here
 * rather than in every caller. RFC 4253 requires all three to be accepted at
 * any time, and a state machine that only tolerates them where it expects
 * them works against one implementation and not the next. */
static int recv_packet(tc_ssh_server *s, size_t *out_len)
{
	for (;;) {
		if (s->in.seq == UINT32_MAX)
			return TC_ERR_TOOMANY;

		int rc = read_full(s, s->rx, TC_SSH_LENGTH_LEN);
		if (rc != TC_OK)
			return rc;

		size_t total = 0;
		rc = tc_ssh_packet_decode_length(&s->in, s->rx, &total);
		if (rc != TC_OK)
			return rc;
		if (total > sizeof s->rx)
			return TC_ERR_TOOMANY;

		rc = read_full(s, s->rx + TC_SSH_LENGTH_LEN,
		               total - TC_SSH_LENGTH_LEN);
		if (rc != TC_OK)
			return rc;

		size_t n = 0;
		rc = tc_ssh_packet_decode(s->payload, sizeof s->payload, &n, s->rx,
		                          total, &s->in);
		if (rc != TC_OK)
			return rc;
		if (n == 0)
			return TC_ERR_INVAL; /* every packet names a message */

		switch (s->payload[0]) {
		case TC_SSH_MSG_IGNORE:
		case TC_SSH_MSG_DEBUG:
		case TC_SSH_MSG_UNIMPLEMENTED:
			continue;
		case TC_SSH_MSG_DISCONNECT:
			return TC_ERR_CLOSED;
		case TC_SSH_MSG_KEXINIT:
			/* Handled here rather than in each caller, for the same reason
			 * IGNORE is: a peer may start a key exchange at any moment, and a
			 * state machine that only tolerates one where it expects one
			 * works against one implementation and hangs against the next.
			 *
			 * During an exchange this is the message the exchange itself is
			 * waiting for, so it is passed through. */
			if (s->in_kex || !s->kex_done) {
				*out_len = n;
				return TC_OK;
			}
			if (n > sizeof s->i_client)
				return TC_ERR_TOOMANY;
			memcpy(s->i_client, s->payload, n);
			s->i_client_len = n;
			rc = kex_exchange(s);
			if (rc != TC_OK)
				return rc;
			continue;
		default:
			*out_len = n;
			return TC_OK;
		}
	}
}

/* unimplemented answers a message we do not handle. RFC 4253 11.4 requires
 * it, and a client that gets silence instead will wait. */
static int send_unimplemented(tc_ssh_server *s, uint32_t seq)
{
	uint8_t buf[8];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, buf, sizeof buf);
	tc_ssh_put_byte(&w, TC_SSH_MSG_UNIMPLEMENTED);
	tc_ssh_put_u32(&w, seq);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	return send_packet(s, buf, tc_ssh_wbuf_len(&w));
}

/* ---- key exchange ------------------------------------------------------ */

/* do_kex runs the opening handshake: we offer first, then read theirs. */
static int do_kex(tc_ssh_server *s)
{
	int rc = tc_ssh_kexinit_build(s->i_server, sizeof s->i_server,
	                              &s->i_server_len);
	if (rc != TC_OK)
		return rc;
	s->in_kex = true;
	rc = send_packet(s, s->i_server, s->i_server_len);
	if (rc != TC_OK)
		goto out;

	size_t n = 0;
	rc = recv_packet(s, &n);
	if (rc != TC_OK)
		goto out;
	if (s->payload[0] != TC_SSH_MSG_KEXINIT) {
		rc = TC_ERR_INVAL;
		goto out;
	}
	if (n > sizeof s->i_client) {
		rc = TC_ERR_TOOMANY;
		goto out;
	}
	/* Kept verbatim: the signature covers the bytes the client sent, not a
	 * re-encoding of what we understood them to mean. */
	memcpy(s->i_client, s->payload, n);
	s->i_client_len = n;
	s->in_kex = false;

	return kex_exchange(s);
out:
	s->in_kex = false;
	return rc;
}

/* kex_exchange runs one exchange, with both KEXINIT payloads already in hand.
 *
 * The opening handshake and a rekey differ in exactly two places, and both
 * are marked below: the session id is set only the first time, and a rekey
 * has already read the peer's KEXINIT before getting here. Everything else --
 * the exchange, the signature, the derivation -- is identical, which is why
 * it is one function rather than two that drift. */
static int kex_exchange(tc_ssh_server *s)
{
	int rc;
	size_t n = 0;
	bool first = !s->kex_done;

	s->in_kex = true;

	/* A rekey we did not start: the peer's KEXINIT arrived first, so ours
	 * goes out now. RFC 4253 7.1 requires a reply before anything else. */
	if (!first) {
		rc = tc_ssh_kexinit_build(s->i_server, sizeof s->i_server,
		                          &s->i_server_len);
		if (rc != TC_OK)
			goto out;
		rc = send_packet(s, s->i_server, s->i_server_len);
		if (rc != TC_OK)
			goto out;
	}

	tc_ssh_negotiated neg;
	rc = tc_ssh_kexinit_parse(&neg, s->i_client, s->i_client_len);
	if (rc != TC_OK)
		goto out;

	if (neg.first_kex_packet_follows && neg.guess_was_wrong) {
		/* RFC 4253 7.1: the guessed packet is discarded. Reading it as the
		 * real KEX_ECDH_INIT would use the client's ephemeral key from a
		 * different algorithm's message. */
		rc = recv_packet(s, &n);
		if (rc != TC_OK)
			goto out;
	}

	rc = recv_packet(s, &n);
	if (rc != TC_OK)
		goto out;
	if (s->payload[0] != TC_SSH_MSG_KEX_ECDH_INIT) {
		/* RFC 4253 7.1 allows only transport and kex messages between
		 * KEXINIT and NEWKEYS, so anything else here is the peer breaking
		 * the rule rather than something to tolerate. */
		rc = TC_ERR_INVAL;
		goto out;
	}

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, s->payload, n);
	(void)tc_ssh_get_byte(&r);
	size_t qc_len = 0;
	const uint8_t *q_client = tc_ssh_get_string(&r, TC_SSH_X25519_LEN,
	                                            &qc_len);
	if (q_client == NULL || qc_len != TC_SSH_X25519_LEN ||
	    !tc_ssh_rbuf_ok(&r)) {
		rc = TC_ERR_INVAL;
		goto out;
	}
	uint8_t qc[TC_SSH_X25519_LEN];
	memcpy(qc, q_client, sizeof qc);

	uint8_t eph_priv[32], eph_pub[32];
	rc = tc_x25519_keypair(eph_priv, eph_pub);
	if (rc != TC_OK)
		goto out;

	uint8_t secret[32];
	/* tc_x25519 refuses a small-order peer key, which is the contributory
	 * behaviour check RFC 8731 section 3 requires: an all-zero shared secret
	 * would let anyone who can send a crafted Q_C fix the session keys. */
	rc = tc_x25519(secret, eph_priv, qc);
	tc_memzero_explicit(eph_priv, sizeof eph_priv);
	if (rc != TC_OK)
		goto out;

	tc_ssh_exchange e;
	memset(&e, 0, sizeof e);
	e.v_client = s->v_client;
	e.v_client_len = s->v_client_len;
	e.v_server = s->v_server;
	e.v_server_len = s->v_server_len;
	e.i_client = s->i_client;
	e.i_client_len = s->i_client_len;
	e.i_server = s->i_server;
	e.i_server_len = s->i_server_len;
	e.k_server = s->host_blob;
	e.k_server_len = s->host_blob_len;
	e.q_client = qc;
	e.q_server = eph_pub;
	e.secret = secret;
	e.secret_len = sizeof secret;

	uint8_t h[TC_SSH_HASH_LEN];
	rc = tc_ssh_exchange_hash(h, &e);
	if (rc != TC_OK)
		goto done;

	uint8_t sig[64];
	rc = tc_ed25519_sign(sig, s->opts->host_seed, s->host_pub, h, sizeof h);
	if (rc != TC_OK)
		goto done;

	uint8_t sigblob[128];
	size_t sigblob_len = 0;
	rc = tc_ssh_signature_blob(sigblob, sizeof sigblob, &sigblob_len, sig);
	if (rc != TC_OK)
		goto done;

	uint8_t reply[512];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, reply, sizeof reply);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEX_ECDH_REPLY);
	tc_ssh_put_string(&w, s->host_blob, s->host_blob_len);
	tc_ssh_put_string(&w, eph_pub, sizeof eph_pub);
	tc_ssh_put_string(&w, sigblob, sigblob_len);
	if (!tc_ssh_wbuf_ok(&w)) {
		rc = TC_ERR_NOSPACE;
		goto done;
	}
	rc = send_packet(s, reply, tc_ssh_wbuf_len(&w));
	if (rc != TC_OK)
		goto done;

	/* The session id is H from the *first* exchange and never changes after
	 * it. That is what ties a rekey to the identity originally proven: the
	 * derivation below folds it in, so new keys are bound to the same
	 * session rather than to a fresh anonymous one. Overwriting it here
	 * would let an attacker who forced a rekey start again with a session
	 * whose id they had influenced. */
	if (first)
		memcpy(s->session_id, h, sizeof s->session_id);

	uint8_t c2s[TC_SSH_CIPHER_KEY_LEN], s2c[TC_SSH_CIPHER_KEY_LEN];
	rc = tc_ssh_derive_keys(c2s, s2c, secret, sizeof secret, h,
	                        s->session_id);
	if (rc != TC_OK)
		goto done;

	/* Order matters in both directions and they are not symmetric.
	 *
	 * Ours: everything after our NEWKEYS must use the new send key, so the
	 * key goes in immediately after the message goes out.
	 *
	 * Theirs: their NEWKEYS is still under the *old* receive key -- it is
	 * the last message that is -- so the new receive key can only go in once
	 * that message has been read. Installing both at once would mean trying
	 * to decrypt their NEWKEYS with a key they had not started using. */
	uint8_t newkeys = TC_SSH_MSG_NEWKEYS;
	rc = send_packet(s, &newkeys, 1);
	if (rc != TC_OK)
		goto keys_done;
	tc_ssh_cipher_set_key(&s->out, s2c);

	rc = recv_packet(s, &n);
	if (rc != TC_OK)
		goto keys_done;
	if (n != 1 || s->payload[0] != TC_SSH_MSG_NEWKEYS) {
		rc = TC_ERR_INVAL;
		goto keys_done;
	}
	tc_ssh_cipher_set_key(&s->in, c2s);

	/* The sequence numbers deliberately do not reset. RFC 4253 6.4: the
	 * count is never reset, even when keys are renegotiated -- and since it
	 * is also the cipher nonce, resetting it would repeat a nonce under the
	 * new key on the very first packet. tc_ssh_cipher_set_key leaves it
	 * alone for exactly this reason. */
	if (!first)
		s->rekeys++;
	s->kex_done = true;
	rc = TC_OK;

keys_done:
	tc_memzero_explicit(c2s, sizeof c2s);
	tc_memzero_explicit(s2c, sizeof s2c);
done:
	tc_memzero_explicit(secret, sizeof secret);
out:
	s->in_kex = false;
	return rc;
}

/* ---- authentication ---------------------------------------------------- */

static int do_auth(tc_ssh_server *s)
{
	size_t n = 0;
	int rc = recv_packet(s, &n);
	if (rc != TC_OK)
		return rc;
	if (s->payload[0] != TC_SSH_MSG_SERVICE_REQUEST)
		return TC_ERR_INVAL;

	char service[TC_SSH_MAX_SERVICE];
	rc = tc_ssh_service_request_parse(service, sizeof service, s->payload, n);
	if (rc != TC_OK)
		return rc;
	if (strcmp(service, "ssh-userauth") != 0)
		return TC_ERR_INVAL;

	uint8_t buf[512];
	size_t buf_len = 0;
	rc = tc_ssh_service_accept_build(buf, sizeof buf, &buf_len,
	                                 "ssh-userauth");
	if (rc != TC_OK)
		return rc;
	rc = send_packet(s, buf, buf_len);
	if (rc != TC_OK)
		return rc;

	/* Bounded. Without a cap a client can sit here offering keys for ever,
	 * and each offer costs us a signature verification. */
	for (int attempt = 0; attempt < 32; attempt++) {
		rc = recv_packet(s, &n);
		if (rc != TC_OK)
			return rc;
		if (s->payload[0] != TC_SSH_MSG_USERAUTH_REQUEST) {
			rc = send_unimplemented(s, s->in.seq - 1);
			if (rc != TC_OK)
				return rc;
			continue;
		}

		tc_ssh_auth_request req;
		rc = tc_ssh_auth_parse(&req, s->payload, n);
		if (rc != TC_OK)
			return rc;

		/* The query form: the client is asking whether this key is worth
		 * signing with. Answering PK_OK authenticates nobody. */
		if (req.method == TC_SSH_AUTH_METHOD_PUBLICKEY && !req.has_signature) {
			bool known = s->opts->any_key_authenticates;
			for (size_t i = 0; i < s->opts->num_authorized; i++)
				if (tc_ct_equal(s->opts->authorized +
				                    i * TC_SSH_ED25519_PUB_LEN,
				                req.pubkey, TC_SSH_ED25519_PUB_LEN))
					known = true;
			if (known)
				rc = tc_ssh_auth_pk_ok_build(buf, sizeof buf, &buf_len,
				                             req.pubkey);
			else
				rc = tc_ssh_auth_failure_build(buf, sizeof buf, &buf_len);
			if (rc != TC_OK)
				return rc;
			rc = send_packet(s, buf, buf_len);
			if (rc != TC_OK)
				return rc;
			continue;
		}

		/* With any_key_authenticates the key still has to prove itself: the
		 * signature is checked against the key the client named, over this
		 * session's id. What is skipped is only the question of whether that
		 * key is on a list, which something below this layer has already
		 * answered. An unsigned request never gets here. */
		bool ok = s->opts->any_key_authenticates
		              ? tc_ssh_auth_check(&req, s->session_id, req.pubkey, 1) ==
		                    TC_OK
		              : tc_ssh_auth_check(&req, s->session_id,
		                                  s->opts->authorized,
		                                  s->opts->num_authorized) == TC_OK;
		if (ok) {
			rc = tc_ssh_auth_success_build(buf, sizeof buf, &buf_len);
			if (rc != TC_OK)
				return rc;
			return send_packet(s, buf, buf_len);
		}

		rc = tc_ssh_auth_failure_build(buf, sizeof buf, &buf_len);
		if (rc != TC_OK)
			return rc;
		rc = send_packet(s, buf, buf_len);
		if (rc != TC_OK)
			return rc;
	}
	return TC_ERR_TOOMANY;
}

/* ---- the session ------------------------------------------------------- */

int tc_ssh_server_write(tc_ssh_server *s, const void *data, size_t len)
{
	if (s == NULL || (data == NULL && len != 0))
		return TC_ERR_INVAL;
	const uint8_t *p = (const uint8_t *)data;

	while (len > 0) {
		/* Wait for window if the peer has not extended it. A server that
		 * sent anyway would be dropped by OpenSSH as a protocol error. */
		while (s->ch.remote_window == 0) {
			size_t n = 0;
			int rc = recv_packet(s, &n);
			if (rc != TC_OK)
				return rc;
			if (s->payload[0] == TC_SSH_MSG_CHANNEL_WINDOW_ADJUST) {
				rc = tc_ssh_channel_window_adjust_parse(&s->ch, s->payload, n);
				if (rc != TC_OK)
					return rc;
			} else if (s->payload[0] == TC_SSH_MSG_CHANNEL_CLOSE) {
				return TC_ERR_CLOSED;
			}
		}

		size_t chunk = len;
		if (chunk > s->ch.remote_window)
			chunk = s->ch.remote_window;
		/* Room for the header the builder puts in front of the data. A
		 * chunk of exactly remote_max_packet would be nine bytes too long
		 * for the buffer it is built into, and sending slightly less than
		 * the peer allows is always legal. */
		if (chunk > s->ch.remote_max_packet - TC_SSH_CHANNEL_DATA_OVERHEAD)
			chunk = s->ch.remote_max_packet - TC_SSH_CHANNEL_DATA_OVERHEAD;

		uint8_t msg[TC_SSH_MAX_PAYLOAD];
		size_t msg_len = 0;
		int rc = tc_ssh_channel_data_build(msg, sizeof msg, &msg_len, &s->ch,
		                                   p, chunk);
		if (rc != TC_OK)
			return rc;
		rc = send_packet(s, msg, msg_len);
		if (rc != TC_OK)
			return rc;
		p += chunk;
		len -= chunk;
	}
	return TC_OK;
}

int tc_ssh_server_read(tc_ssh_server *s, void *buf, size_t cap, size_t *nread)
{
	if (s == NULL || buf == NULL || nread == NULL)
		return TC_ERR_INVAL;
	*nread = 0;

	while (s->pending_len == 0) {
		if (s->peer_eof)
			return TC_ERR_DONE;

		size_t n = 0;
		int rc = recv_packet(s, &n);
		if (rc != TC_OK)
			return rc;

		switch (s->payload[0]) {
		case TC_SSH_MSG_CHANNEL_DATA:
			rc = tc_ssh_channel_data_parse(&s->ch, &s->pending,
			                               &s->pending_len, s->payload, n);
			if (rc != TC_OK)
				return rc;
			break;
		case TC_SSH_MSG_CHANNEL_WINDOW_ADJUST:
			rc = tc_ssh_channel_window_adjust_parse(&s->ch, s->payload, n);
			if (rc != TC_OK)
				return rc;
			break;
		case TC_SSH_MSG_CHANNEL_EOF:
			s->peer_eof = true;
			break;
		case TC_SSH_MSG_CHANNEL_CLOSE:
			s->peer_eof = true;
			s->ch.closed = true;
			return TC_ERR_DONE;
		case TC_SSH_MSG_CHANNEL_REQUEST: {
			/* A request mid-session, such as a window-change. Refused, but
			 * answered if it wants an answer. */
			tc_ssh_channel_request req;
			if (tc_ssh_channel_request_parse(&req, &s->ch, s->payload, n) ==
			        TC_OK &&
			    req.want_reply) {
				uint8_t msg[32];
				size_t msg_len = 0;
				if (tc_ssh_channel_reply_build(msg, sizeof msg, &msg_len,
				                               s->ch.remote_id,
				                               false) == TC_OK)
					(void)send_packet(s, msg, msg_len);
			}
			break;
		}
		default:
			break;
		}
	}

	/* Replenish before handing the bytes over, so a caller that reads in a
	 * tight loop never stalls waiting for a window it forgot to extend. */
	uint32_t inc = 0;
	if (tc_ssh_channel_window_needed(&s->ch, &inc)) {
		uint8_t msg[32];
		size_t msg_len = 0;
		int rc = tc_ssh_channel_window_adjust_build(msg, sizeof msg, &msg_len,
		                                            &s->ch, inc);
		if (rc == TC_OK)
			rc = send_packet(s, msg, msg_len);
		if (rc != TC_OK)
			return rc;
	}

	size_t take = s->pending_len < cap ? s->pending_len : cap;
	memcpy(buf, s->pending, take);
	s->pending += take;
	s->pending_len -= take;
	*nread = take;
	return TC_OK;
}

int tc_ssh_server_exit(tc_ssh_server *s, uint32_t status)
{
	if (s == NULL)
		return TC_ERR_INVAL;
	uint8_t msg[64];
	size_t msg_len = 0;
	int rc = tc_ssh_channel_exit_status_build(msg, sizeof msg, &msg_len,
	                                          &s->ch, status);
	if (rc != TC_OK)
		return rc;
	return send_packet(s, msg, msg_len);
}

const uint8_t *tc_ssh_server_session_id(const tc_ssh_server *s)
{
	return s == NULL ? NULL : s->session_id;
}

unsigned tc_ssh_server_rekeys(const tc_ssh_server *s)
{
	return s == NULL ? 0u : s->rekeys;
}

static int do_session(tc_ssh_server *s)
{
	uint8_t msg[512];
	size_t msg_len = 0;

	/* The channel. One, and only of type "session". */
	for (;;) {
		size_t n = 0;
		int rc = recv_packet(s, &n);
		if (rc != TC_OK)
			return rc;

		if (s->payload[0] == TC_SSH_MSG_GLOBAL_REQUEST) {
			/* Refused, but answered: a client that set want_reply and gets
			 * nothing back waits for ever. */
			tc_ssh_rbuf r;
			tc_ssh_rbuf_init(&r, s->payload, n);
			(void)tc_ssh_get_byte(&r);
			(void)tc_ssh_get_string(&r, SIZE_MAX, NULL);
			bool want_reply = tc_ssh_get_bool(&r);
			if (tc_ssh_rbuf_ok(&r) && want_reply) {
				uint8_t fail = TC_SSH_MSG_REQUEST_FAILURE;
				rc = send_packet(s, &fail, 1);
				if (rc != TC_OK)
					return rc;
			}
			continue;
		}

		if (s->payload[0] != TC_SSH_MSG_CHANNEL_OPEN)
			continue;

		char type[32];
		rc = tc_ssh_channel_open_parse(&s->ch, type, sizeof type, s->payload,
		                              n);
		if (rc != TC_OK)
			return rc;

		if (strcmp(type, "session") != 0 || s->ch.open) {
			/* A second channel, or a type we do not serve. Refused by name
			 * so the client reports something useful. */
			rc = tc_ssh_channel_open_failure_build(
			    msg, sizeof msg, &msg_len, s->ch.remote_id,
			    TC_SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "only one session");
			if (rc != TC_OK)
				return rc;
			rc = send_packet(s, msg, msg_len);
			if (rc != TC_OK)
				return rc;
			continue;
		}

		s->ch.open = true;
		rc = tc_ssh_channel_confirm_build(msg, sizeof msg, &msg_len, &s->ch);
		if (rc != TC_OK)
			return rc;
		rc = send_packet(s, msg, msg_len);
		if (rc != TC_OK)
			return rc;
		break;
	}

	/* Then the request that says what the channel is for. */
	for (;;) {
		size_t n = 0;
		int rc = recv_packet(s, &n);
		if (rc != TC_OK)
			return rc;
		if (s->payload[0] != TC_SSH_MSG_CHANNEL_REQUEST)
			continue;

		tc_ssh_channel_request req;
		rc = tc_ssh_channel_request_parse(&req, &s->ch, s->payload, n);
		if (rc != TC_OK)
			return rc;

		/* Decide, answer, *then* work. RFC 4254 4 has the requester wait for
		 * CHANNEL_SUCCESS before using the channel, so running the
		 * application first and replying afterwards deadlocks against a
		 * client that waits. */
		bool accept = false;
		if (req.type == TC_SSH_REQ_SUBSYSTEM || req.type == TC_SSH_REQ_EXEC) {
			/* Refused rather than truncated. A name that does not fit is not
			 * a name we serve, and shortening it would make "sftp" and
			 * "sftp-and-more" the same request. */
			accept = strlen(req.arg) < sizeof s->ch.subsystem &&
			         (s->opts->on_accept == NULL ||
			          s->opts->on_accept(s->opts->app_ctx, req.type, req.arg));
		}

		if (req.want_reply) {
			rc = tc_ssh_channel_reply_build(msg, sizeof msg, &msg_len,
			                                s->ch.remote_id, accept);
			if (rc != TC_OK)
				return rc;
			rc = send_packet(s, msg, msg_len);
			if (rc != TC_OK)
				return rc;
		}
		if (!accept)
			continue; /* pty-req and friends; the real request may follow */

		s->ch.started = true;
		memcpy(s->ch.subsystem, req.arg, strlen(req.arg) + 1);
		if (s->opts->on_start != NULL) {
			int arc = s->opts->on_start(s->opts->app_ctx, s, req.type,
			                            req.arg);
			if (arc != TC_OK)
				return arc;
		}
		return TC_OK;
	}
}

int tc_ssh_server_run(const tc_ssh_server_opts *opts)
{
	if (opts == NULL || opts->host_seed == NULL || opts->read == NULL ||
	    opts->write == NULL)
		return TC_ERR_INVAL;

	/* Heap rather than stack: the packet buffers alone are nearly 100KB, and
	 * this may be called from a thread with a small stack. */
	tc_ssh_server *s = calloc(1, sizeof *s);
	if (s == NULL)
		return TC_ERR_NOSPACE;
	s->opts = opts;
	tc_ssh_cipher_init_plain(&s->in);
	tc_ssh_cipher_init_plain(&s->out);
	tc_ssh_channel_init(&s->ch);

	int rc = tc_ed25519_public_from_seed(s->host_pub, opts->host_seed);
	if (rc != TC_OK)
		goto out;
	rc = tc_ssh_hostkey_blob(s->host_blob, sizeof s->host_blob,
	                         &s->host_blob_len, s->host_pub);
	if (rc != TC_OK)
		goto out;

	rc = tc_ssh_version_build(s->v_server, sizeof s->v_server, NULL,
	                          "tailcatc_0.1");
	if (rc != TC_OK)
		goto out;
	rc = write_all(s, (const uint8_t *)s->v_server, strlen(s->v_server));
	if (rc != TC_OK)
		goto out;
	/* The hash covers the line without its CR LF. */
	s->v_server_len = strlen(s->v_server) - 2;
	s->v_server[s->v_server_len] = '\0';

	rc = read_version_line(s, s->v_client, sizeof s->v_client,
	                       &s->v_client_len);
	if (rc != TC_OK)
		goto out;
	rc = tc_ssh_version_check(s->v_client, s->v_client_len);
	if (rc != TC_OK)
		goto out;

	rc = do_kex(s);
	if (rc != TC_OK)
		goto out;
	rc = do_auth(s);
	if (rc != TC_OK)
		goto out;
	rc = do_session(s);
	if (rc != TC_OK)
		goto out;

	/* The application has had its turn inside on_start; wind the channel up
	 * politely so the client sees a clean end rather than a dropped socket. */
	uint8_t msg[64];
	size_t msg_len = 0;
	if (tc_ssh_channel_eof_build(msg, sizeof msg, &msg_len, &s->ch) == TC_OK)
		(void)send_packet(s, msg, msg_len);
	if (tc_ssh_channel_close_build(msg, sizeof msg, &msg_len, &s->ch) == TC_OK)
		(void)send_packet(s, msg, msg_len);

out:
	tc_ssh_cipher_wipe(&s->in);
	tc_ssh_cipher_wipe(&s->out);
	tc_memzero_explicit(s->session_id, sizeof s->session_id);
	free(s);
	return rc;
}
