/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH client transport. See tc/sshclient.h.
 *
 * The shape mirrors src/ssh/server.c closely, and the pieces that are genuinely
 * symmetric -- the exchange hash, the key derivation, the packet layer -- are
 * shared rather than written twice. What differs is who speaks first and which
 * direction each derived key belongs to, and those are the two places a client
 * written by adapting a server goes wrong.
 */

#include "tc/sshclient.h"

#include "tc/crypto.h"
#include "tc/ed25519.h"
#include "tc/sshwire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEXINIT_MAX 2048

/* RFC 8308's extension negotiation -- TC_SSH_MSG_EXT_INFO, from tc/sshkex.h.
 * OpenSSH, Go and our own server all send it right after NEWKEYS. It carries
 * no obligation for a client that only has one key type, and is ignored. */

struct tc_ssh_client {
	const tc_ssh_client_opts *opts;

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
	uint8_t host_key[32];

	tc_ssh_channel ch;

	uint8_t rx[TC_SSH_MAX_PACKET];
	uint8_t payload[TC_SSH_MAX_PAYLOAD + 64];
	uint8_t tx[TC_SSH_MAX_PACKET];

	const uint8_t *pending;
	size_t pending_len;
	bool peer_eof;
};

/* ---- stream helpers ---------------------------------------------------- */

static int read_full(tc_ssh_client *c, uint8_t *buf, size_t want)
{
	size_t got = 0;
	while (got < want) {
		size_t n = 0;
		int rc = c->opts->read(c->opts->io_ctx, buf + got, want - got, &n);
		if (rc != TC_OK)
			return rc;
		if (n == 0)
			return TC_ERR_CLOSED;
		got += n;
	}
	return TC_OK;
}

static int send_packet(tc_ssh_client *c, const uint8_t *payload, size_t len)
{
	if (c->out.seq == UINT32_MAX)
		return TC_ERR_TOOMANY;
	size_t n = 0;
	int rc = tc_ssh_packet_encode(c->tx, sizeof c->tx, &n, payload, len,
	                              &c->out);
	if (rc != TC_OK)
		return rc;
	return c->opts->write(c->opts->io_ctx, c->tx, n);
}

static int recv_packet(tc_ssh_client *c, size_t *out_len)
{
	for (;;) {
		if (c->in.seq == UINT32_MAX)
			return TC_ERR_TOOMANY;

		int rc = read_full(c, c->rx, TC_SSH_LENGTH_LEN);
		if (rc != TC_OK)
			return rc;

		size_t total = 0;
		rc = tc_ssh_packet_decode_length(&c->in, c->rx, &total);
		if (rc != TC_OK)
			return rc;
		if (total > sizeof c->rx)
			return TC_ERR_TOOMANY;

		rc = read_full(c, c->rx + TC_SSH_LENGTH_LEN,
		               total - TC_SSH_LENGTH_LEN);
		if (rc != TC_OK)
			return rc;

		size_t n = 0;
		rc = tc_ssh_packet_decode(c->payload, sizeof c->payload, &n, c->rx,
		                          total, &c->in);
		if (rc != TC_OK)
			return rc;
		if (n == 0)
			return TC_ERR_INVAL;

		switch (c->payload[0]) {
		case TC_SSH_MSG_IGNORE:
		case TC_SSH_MSG_DEBUG:
		case TC_SSH_MSG_UNIMPLEMENTED:
		case TC_SSH_MSG_EXT_INFO:
		case TC_SSH_MSG_USERAUTH_BANNER:
			/* All five may arrive at any time and none of them changes what
			 * we are waiting for. A banner in particular arrives mid-auth
			 * and is the server's to print, not ours to act on. */
			continue;
		case TC_SSH_MSG_DISCONNECT:
			return TC_ERR_CLOSED;
		default:
			*out_len = n;
			return TC_OK;
		}
	}
}

/* ---- version exchange -------------------------------------------------- */

static int read_version_line(tc_ssh_client *c, char *out, size_t cap,
                             size_t *out_len)
{
	/* RFC 4253 4.2 lets a server send any number of lines before its
	 * identification, and requires a client to skip them. Bounded so a server
	 * cannot hold us open sending banners for ever. */
	for (int line = 0; line < 64; line++) {
		size_t n = 0;
		for (;;) {
			uint8_t ch;
			int rc = read_full(c, &ch, 1);
			if (rc != TC_OK)
				return rc;
			if (ch == '\n')
				break;
			if (n + 1 >= cap)
				return TC_ERR_TOOMANY;
			out[n++] = (char)ch;
		}
		if (n > 0 && out[n - 1] == '\r')
			n--;
		out[n] = '\0';
		if (n >= 4 && memcmp(out, "SSH-", 4) == 0) {
			*out_len = n;
			return TC_OK;
		}
	}
	return TC_ERR_TOOMANY;
}

/* ---- key exchange ------------------------------------------------------ */

/* read_host_key pulls the 32-byte Ed25519 key out of the server's K_S. */
static bool read_host_key(const uint8_t *blob, size_t len, uint8_t out[32])
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519"))
		return false;
	size_t n = 0;
	const uint8_t *k = tc_ssh_get_string(&r, 32, &n);
	if (k == NULL || n != 32 || tc_ssh_rbuf_remaining(&r) != 0)
		return false;
	memcpy(out, k, 32);
	return tc_ssh_rbuf_ok(&r);
}

static bool read_signature(const uint8_t *blob, size_t len, uint8_t out[64])
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519"))
		return false;
	size_t n = 0;
	const uint8_t *s = tc_ssh_get_string(&r, 64, &n);
	if (s == NULL || n != 64 || tc_ssh_rbuf_remaining(&r) != 0)
		return false;
	memcpy(out, s, 64);
	return tc_ssh_rbuf_ok(&r);
}

static int do_kex(tc_ssh_client *c)
{
	int rc = tc_ssh_kexinit_build(c->i_client, sizeof c->i_client,
	                              &c->i_client_len);
	if (rc != TC_OK)
		return rc;
	rc = send_packet(c, c->i_client, c->i_client_len);
	if (rc != TC_OK)
		return rc;

	size_t n = 0;
	rc = recv_packet(c, &n);
	if (rc != TC_OK)
		return rc;
	if (c->payload[0] != TC_SSH_MSG_KEXINIT)
		return TC_ERR_INVAL;
	if (n > sizeof c->i_server)
		return TC_ERR_TOOMANY;
	memcpy(c->i_server, c->payload, n);
	c->i_server_len = n;

	tc_ssh_negotiated neg;
	rc = tc_ssh_kexinit_parse(&neg, c->i_server, c->i_server_len);
	if (rc != TC_OK)
		return rc;

	uint8_t eph_priv[32], eph_pub[32];
	rc = tc_x25519_keypair(eph_priv, eph_pub);
	if (rc != TC_OK)
		return rc;

	uint8_t init[64];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, init, sizeof init);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEX_ECDH_INIT);
	tc_ssh_put_string(&w, eph_pub, sizeof eph_pub);
	if (!tc_ssh_wbuf_ok(&w)) {
		tc_memzero_explicit(eph_priv, sizeof eph_priv);
		return TC_ERR_NOSPACE;
	}
	rc = send_packet(c, init, tc_ssh_wbuf_len(&w));
	if (rc != TC_OK) {
		tc_memzero_explicit(eph_priv, sizeof eph_priv);
		return rc;
	}

	rc = recv_packet(c, &n);
	if (rc != TC_OK) {
		tc_memzero_explicit(eph_priv, sizeof eph_priv);
		return rc;
	}
	if (c->payload[0] != TC_SSH_MSG_KEX_ECDH_REPLY) {
		tc_memzero_explicit(eph_priv, sizeof eph_priv);
		return TC_ERR_INVAL;
	}

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, c->payload, n);
	(void)tc_ssh_get_byte(&r);
	size_t ks_len = 0, qs_len = 0, sig_len = 0;
	const uint8_t *k_server = tc_ssh_get_string(&r, 4096, &ks_len);
	const uint8_t *q_server = tc_ssh_get_string(&r, TC_SSH_X25519_LEN,
	                                            &qs_len);
	const uint8_t *sigblob = tc_ssh_get_string(&r, 4096, &sig_len);

	uint8_t qs[TC_SSH_X25519_LEN], sig[64];
	if (k_server == NULL || q_server == NULL || sigblob == NULL ||
	    qs_len != TC_SSH_X25519_LEN || !tc_ssh_rbuf_ok(&r) ||
	    !read_host_key(k_server, ks_len, c->host_key) ||
	    !read_signature(sigblob, sig_len, sig)) {
		tc_memzero_explicit(eph_priv, sizeof eph_priv);
		return TC_ERR_INVAL;
	}
	memcpy(qs, q_server, sizeof qs);

	uint8_t secret[32];
	rc = tc_x25519(secret, eph_priv, qs);
	tc_memzero_explicit(eph_priv, sizeof eph_priv);
	if (rc != TC_OK)
		return rc;

	tc_ssh_exchange e;
	memset(&e, 0, sizeof e);
	e.v_client = c->v_client;
	e.v_client_len = c->v_client_len;
	e.v_server = c->v_server;
	e.v_server_len = c->v_server_len;
	e.i_client = c->i_client;
	e.i_client_len = c->i_client_len;
	e.i_server = c->i_server;
	e.i_server_len = c->i_server_len;
	e.k_server = k_server;
	e.k_server_len = ks_len;
	e.q_client = eph_pub;
	e.q_server = qs;
	e.secret = secret;
	e.secret_len = sizeof secret;

	uint8_t h[TC_SSH_HASH_LEN];
	rc = tc_ssh_exchange_hash(h, &e);
	if (rc != TC_OK)
		goto done;

	/* The host key is not compared against anything -- see the header -- but
	 * the signature over H is checked, which is what ties the exchange we
	 * just did to the key the server presented. Skipping this would let
	 * anyone in the path complete a key exchange of their own and claim any
	 * host key they liked. */
	if (tc_ed25519_verify(sig, c->host_key, h, sizeof h) != TC_OK) {
		rc = TC_ERR_INVAL;
		goto done;
	}

	memcpy(c->session_id, h, sizeof c->session_id);

	uint8_t c2s[TC_SSH_CIPHER_KEY_LEN], s2c[TC_SSH_CIPHER_KEY_LEN];
	rc = tc_ssh_derive_keys(c2s, s2c, secret, sizeof secret, h,
	                        c->session_id);
	if (rc != TC_OK)
		goto done;

	uint8_t newkeys = TC_SSH_MSG_NEWKEYS;
	rc = send_packet(c, &newkeys, 1);
	if (rc != TC_OK)
		goto keys_done;
	/* c2s is what a *client* sends with. Taking s2c here is the mistake a
	 * client adapted from a server makes, and it produces a connection whose
	 * every packet fails the tag with nothing to say why. */
	tc_ssh_cipher_set_key(&c->out, c2s);

	rc = recv_packet(c, &n);
	if (rc != TC_OK)
		goto keys_done;
	if (n != 1 || c->payload[0] != TC_SSH_MSG_NEWKEYS) {
		rc = TC_ERR_INVAL;
		goto keys_done;
	}
	tc_ssh_cipher_set_key(&c->in, s2c);
	rc = TC_OK;

keys_done:
	tc_memzero_explicit(c2s, sizeof c2s);
	tc_memzero_explicit(s2c, sizeof s2c);
done:
	tc_memzero_explicit(secret, sizeof secret);
	return rc;
}

/* ---- authentication ---------------------------------------------------- */

/* auth_none offers the method upstream's own client offers, which is the one
 * a tailcat file server accepts. */
static int auth_none(tc_ssh_client *c, bool *out_ok)
{
	uint8_t msg[256];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, c->opts->user != NULL ? c->opts->user : "tailcat");
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "none");
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	int rc = send_packet(c, msg, tc_ssh_wbuf_len(&w));
	if (rc != TC_OK)
		return rc;

	size_t n = 0;
	rc = recv_packet(c, &n);
	if (rc != TC_OK)
		return rc;
	*out_ok = c->payload[0] == TC_SSH_MSG_USERAUTH_SUCCESS;
	if (!*out_ok && c->payload[0] != TC_SSH_MSG_USERAUTH_FAILURE)
		return TC_ERR_INVAL;
	return TC_OK;
}

static int auth_publickey(tc_ssh_client *c, bool *out_ok)
{
	uint8_t pub[32];
	int rc = tc_ed25519_public_from_seed(pub, c->opts->user_seed);
	if (rc != TC_OK)
		return rc;

	uint8_t keyblob[4 + 11 + 4 + 32];
	tc_ssh_wbuf kb;
	tc_ssh_wbuf_init(&kb, keyblob, sizeof keyblob);
	tc_ssh_put_cstring(&kb, "ssh-ed25519");
	tc_ssh_put_string(&kb, pub, sizeof pub);
	if (!tc_ssh_wbuf_ok(&kb))
		return TC_ERR_NOSPACE;
	size_t keyblob_len = tc_ssh_wbuf_len(&kb);

	const char *user = c->opts->user != NULL ? c->opts->user : "tailcat";

	/* The signed blob, RFC 4252 section 7: the session id first, which is
	 * what stops this signature working on any other connection. */
	uint8_t blob[512];
	tc_ssh_wbuf b;
	tc_ssh_wbuf_init(&b, blob, sizeof blob);
	tc_ssh_put_string(&b, c->session_id, TC_SSH_HASH_LEN);
	tc_ssh_put_byte(&b, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&b, user);
	tc_ssh_put_cstring(&b, "ssh-connection");
	tc_ssh_put_cstring(&b, "publickey");
	tc_ssh_put_bool(&b, true);
	tc_ssh_put_cstring(&b, "ssh-ed25519");
	tc_ssh_put_string(&b, keyblob, keyblob_len);
	if (!tc_ssh_wbuf_ok(&b))
		return TC_ERR_NOSPACE;

	uint8_t sig[64];
	rc = tc_ed25519_sign(sig, c->opts->user_seed, pub, blob,
	                     tc_ssh_wbuf_len(&b));
	if (rc != TC_OK)
		return rc;

	uint8_t sigblob[4 + 11 + 4 + 64];
	tc_ssh_wbuf sb;
	tc_ssh_wbuf_init(&sb, sigblob, sizeof sigblob);
	tc_ssh_put_cstring(&sb, "ssh-ed25519");
	tc_ssh_put_string(&sb, sig, sizeof sig);
	if (!tc_ssh_wbuf_ok(&sb))
		return TC_ERR_NOSPACE;

	uint8_t msg[768];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, user);
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, keyblob, keyblob_len);
	tc_ssh_put_string(&w, sigblob, tc_ssh_wbuf_len(&sb));
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;

	rc = send_packet(c, msg, tc_ssh_wbuf_len(&w));
	if (rc != TC_OK)
		return rc;

	size_t n = 0;
	rc = recv_packet(c, &n);
	if (rc != TC_OK)
		return rc;
	*out_ok = c->payload[0] == TC_SSH_MSG_USERAUTH_SUCCESS;
	return TC_OK;
}

static int do_auth(tc_ssh_client *c)
{
	uint8_t msg[128];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_SERVICE_REQUEST);
	tc_ssh_put_cstring(&w, "ssh-userauth");
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	int rc = send_packet(c, msg, tc_ssh_wbuf_len(&w));
	if (rc != TC_OK)
		return rc;

	size_t n = 0;
	rc = recv_packet(c, &n);
	if (rc != TC_OK)
		return rc;
	if (c->payload[0] != TC_SSH_MSG_SERVICE_ACCEPT)
		return TC_ERR_INVAL;

	bool ok = false;
	rc = auth_none(c, &ok);
	if (rc != TC_OK)
		return rc;
	if (ok)
		return TC_OK;

	if (c->opts->user_seed == NULL)
		return TC_ERR_UNSUPPORTED;
	rc = auth_publickey(c, &ok);
	if (rc != TC_OK)
		return rc;
	return ok ? TC_OK : TC_ERR_UNSUPPORTED;
}

/* ---- the channel ------------------------------------------------------- */

static int do_channel(tc_ssh_client *c)
{
	uint8_t msg[256];
	size_t msg_len = 0;
	int rc = tc_ssh_channel_open_build(msg, sizeof msg, &msg_len, &c->ch);
	if (rc != TC_OK)
		return rc;
	rc = send_packet(c, msg, msg_len);
	if (rc != TC_OK)
		return rc;

	for (;;) {
		size_t n = 0;
		rc = recv_packet(c, &n);
		if (rc != TC_OK)
			return rc;
		if (c->payload[0] == TC_SSH_MSG_CHANNEL_OPEN_FAILURE)
			return TC_ERR_UNSUPPORTED;
		if (c->payload[0] == TC_SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
			rc = tc_ssh_channel_confirm_parse(&c->ch, c->payload, n);
			if (rc != TC_OK)
				return rc;
			break;
		}
		/* A global request or anything else the server volunteered before
		 * answering. Ignored rather than treated as a refusal. */
	}

	rc = tc_ssh_channel_subsystem_build(msg, sizeof msg, &msg_len, &c->ch,
	                                    c->opts->subsystem != NULL
	                                        ? c->opts->subsystem
	                                        : "sftp");
	if (rc != TC_OK)
		return rc;
	rc = send_packet(c, msg, msg_len);
	if (rc != TC_OK)
		return rc;

	for (;;) {
		size_t n = 0;
		rc = recv_packet(c, &n);
		if (rc != TC_OK)
			return rc;
		if (c->payload[0] == TC_SSH_MSG_CHANNEL_SUCCESS) {
			c->ch.started = true;
			return TC_OK;
		}
		if (c->payload[0] == TC_SSH_MSG_CHANNEL_FAILURE)
			return TC_ERR_UNSUPPORTED;
		if (c->payload[0] == TC_SSH_MSG_CHANNEL_CLOSE)
			return TC_ERR_CLOSED;
	}
}

/* ---- data -------------------------------------------------------------- */

int tc_ssh_client_write(tc_ssh_client *c, const void *data, size_t len)
{
	if (c == NULL || (data == NULL && len != 0))
		return TC_ERR_INVAL;
	const uint8_t *p = (const uint8_t *)data;

	while (len > 0) {
		while (c->ch.remote_window == 0) {
			size_t n = 0;
			int rc = recv_packet(c, &n);
			if (rc != TC_OK)
				return rc;
			if (c->payload[0] == TC_SSH_MSG_CHANNEL_WINDOW_ADJUST) {
				rc = tc_ssh_channel_window_adjust_parse(&c->ch, c->payload, n);
				if (rc != TC_OK)
					return rc;
			} else if (c->payload[0] == TC_SSH_MSG_CHANNEL_CLOSE) {
				return TC_ERR_CLOSED;
			}
		}

		size_t chunk = len;
		if (chunk > c->ch.remote_window)
			chunk = c->ch.remote_window;
		/* See the same cap in server.c: the builder's header has to fit in
		 * front of the chunk, and remote_max_packet does not leave room. */
		if (chunk > c->ch.remote_max_packet - TC_SSH_CHANNEL_DATA_OVERHEAD)
			chunk = c->ch.remote_max_packet - TC_SSH_CHANNEL_DATA_OVERHEAD;

		uint8_t msg[TC_SSH_MAX_PAYLOAD];
		size_t msg_len = 0;
		int rc = tc_ssh_channel_data_build(msg, sizeof msg, &msg_len, &c->ch,
		                                   p, chunk);
		if (rc != TC_OK)
			return rc;
		rc = send_packet(c, msg, msg_len);
		if (rc != TC_OK)
			return rc;
		p += chunk;
		len -= chunk;
	}
	return TC_OK;
}

int tc_ssh_client_read(tc_ssh_client *c, void *buf, size_t cap, size_t *nread)
{
	if (c == NULL || buf == NULL || nread == NULL)
		return TC_ERR_INVAL;
	*nread = 0;

	while (c->pending_len == 0) {
		if (c->peer_eof)
			return TC_ERR_DONE;

		size_t n = 0;
		int rc = recv_packet(c, &n);
		if (rc != TC_OK)
			return rc;

		switch (c->payload[0]) {
		case TC_SSH_MSG_CHANNEL_DATA:
			rc = tc_ssh_channel_data_parse(&c->ch, &c->pending,
			                               &c->pending_len, c->payload, n);
			if (rc != TC_OK)
				return rc;
			break;
		case TC_SSH_MSG_CHANNEL_EXTENDED_DATA:
			/* The server's stderr. A listing has no use for it, and mixing
			 * it into the SFTP stream would corrupt the framing. */
			break;
		case TC_SSH_MSG_CHANNEL_WINDOW_ADJUST:
			rc = tc_ssh_channel_window_adjust_parse(&c->ch, c->payload, n);
			if (rc != TC_OK)
				return rc;
			break;
		case TC_SSH_MSG_CHANNEL_EOF:
			c->peer_eof = true;
			break;
		case TC_SSH_MSG_CHANNEL_CLOSE:
			c->peer_eof = true;
			c->ch.closed = true;
			return TC_ERR_DONE;
		default:
			break;
		}
	}

	uint32_t inc = 0;
	if (tc_ssh_channel_window_needed(&c->ch, &inc)) {
		uint8_t msg[32];
		size_t msg_len = 0;
		int rc = tc_ssh_channel_window_adjust_build(msg, sizeof msg, &msg_len,
		                                            &c->ch, inc);
		if (rc == TC_OK)
			rc = send_packet(c, msg, msg_len);
		if (rc != TC_OK)
			return rc;
	}

	size_t take = c->pending_len < cap ? c->pending_len : cap;
	memcpy(buf, c->pending, take);
	c->pending += take;
	c->pending_len -= take;
	*nread = take;
	return TC_OK;
}

int tc_ssh_client_eof(tc_ssh_client *c)
{
	if (c == NULL)
		return TC_ERR_INVAL;
	if (c->ch.eof_sent)
		return TC_OK;
	uint8_t msg[32];
	size_t msg_len = 0;
	int rc = tc_ssh_channel_eof_build(msg, sizeof msg, &msg_len, &c->ch);
	if (rc != TC_OK)
		return rc;
	return send_packet(c, msg, msg_len);
}

const uint8_t *tc_ssh_client_host_key(const tc_ssh_client *c)
{
	return c == NULL ? NULL : c->host_key;
}

int tc_ssh_client_run(const tc_ssh_client_opts *opts)
{
	if (opts == NULL || opts->read == NULL || opts->write == NULL)
		return TC_ERR_INVAL;

	tc_ssh_client *c = calloc(1, sizeof *c);
	if (c == NULL)
		return TC_ERR_NOSPACE;
	c->opts = opts;
	tc_ssh_cipher_init_plain(&c->in);
	tc_ssh_cipher_init_plain(&c->out);
	tc_ssh_channel_init(&c->ch);

	int rc = tc_ssh_version_build(c->v_client, sizeof c->v_client, NULL,
	                              "tailcatc_0.1");
	if (rc != TC_OK)
		goto out;
	rc = opts->write(opts->io_ctx, (const uint8_t *)c->v_client,
	                 strlen(c->v_client));
	if (rc != TC_OK)
		goto out;
	c->v_client_len = strlen(c->v_client) - 2; /* the hash excludes CR LF */
	c->v_client[c->v_client_len] = '\0';

	rc = read_version_line(c, c->v_server, sizeof c->v_server,
	                       &c->v_server_len);
	if (rc != TC_OK)
		goto out;
	rc = tc_ssh_version_check(c->v_server, c->v_server_len);
	if (rc != TC_OK)
		goto out;

	rc = do_kex(c);
	if (rc != TC_OK)
		goto out;
	rc = do_auth(c);
	if (rc != TC_OK)
		goto out;
	rc = do_channel(c);
	if (rc != TC_OK)
		goto out;

	if (opts->on_ready != NULL)
		rc = opts->on_ready(opts->app_ctx, c);

	/* Only what has not been said already, and only while the far end is
	 * still there. A caller that finished with tc_ssh_client_eof has sent
	 * its EOF, and the server may well have closed by now -- writing anyway
	 * is a write to a socket nobody is reading. */
	uint8_t msg[64];
	size_t msg_len = 0;
	if (!c->ch.eof_sent &&
	    tc_ssh_channel_eof_build(msg, sizeof msg, &msg_len, &c->ch) == TC_OK)
		(void)send_packet(c, msg, msg_len);
	if (!c->ch.closed &&
	    tc_ssh_channel_close_build(msg, sizeof msg, &msg_len, &c->ch) == TC_OK)
		(void)send_packet(c, msg, msg_len);

out:
	tc_ssh_cipher_wipe(&c->in);
	tc_ssh_cipher_wipe(&c->out);
	tc_memzero_explicit(c->session_id, sizeof c->session_id);
	free(c);
	return rc;
}
