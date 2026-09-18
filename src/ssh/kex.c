/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4253 section 7, RFC 8731. See tc/sshkex.h for the reasoning.
 */

#include "tc/sshkex.h"

#include "tc/crypto.h"
#include "tc/sshwire.h"

#include "mbedtls/sha256.h"

#include <string.h>

/* One of each, deliberately. See the header. */
const char *const tc_ssh_kex_algs[2] = {
	"curve25519-sha256",
	/* The same algorithm under the name it had before RFC 8731 gave it one.
	 * Still what several implementations send, and identical on the wire. */
	"curve25519-sha256@libssh.org",
};
const char *const tc_ssh_hostkey_algs[1] = { "ssh-ed25519" };
const char *const tc_ssh_cipher_algs[1] = { "chacha20-poly1305@openssh.com" };
const char *const tc_ssh_mac_algs[1] = { "hmac-sha2-256" };
const char *const tc_ssh_comp_algs[1] = { "none" };

#define NELEMS(a) (sizeof(a) / sizeof(*(a)))

/* ---- KEXINIT ----------------------------------------------------------- */

int tc_ssh_ext_info_build(uint8_t *out, size_t cap, size_t *out_len,
                          const char *const *algos, size_t num_algos)
{
	if (out == NULL || algos == NULL || num_algos == 0)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_EXT_INFO);
	tc_ssh_put_u32(&w, 1); /* one extension */
	tc_ssh_put_cstring(&w, "server-sig-algs");
	tc_ssh_put_namelist(&w, algos, num_algos);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_kexinit_build(uint8_t *out, size_t cap, size_t *out_len)
{
	if (out == NULL)
		return TC_ERR_INVAL;

	uint8_t cookie[TC_SSH_COOKIE_LEN];
	int rc = tc_random_bytes(cookie, sizeof cookie);
	if (rc != TC_OK)
		return rc;

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEXINIT);
	tc_ssh_put_raw(&w, cookie, sizeof cookie);
	tc_ssh_put_namelist(&w, tc_ssh_kex_algs, NELEMS(tc_ssh_kex_algs));
	tc_ssh_put_namelist(&w, tc_ssh_hostkey_algs, NELEMS(tc_ssh_hostkey_algs));
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, NELEMS(tc_ssh_cipher_algs));
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, NELEMS(tc_ssh_cipher_algs));
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, NELEMS(tc_ssh_mac_algs));
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, NELEMS(tc_ssh_mac_algs));
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, NELEMS(tc_ssh_comp_algs));
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, NELEMS(tc_ssh_comp_algs));
	tc_ssh_put_namelist(&w, NULL, 0); /* languages, client to server */
	tc_ssh_put_namelist(&w, NULL, 0); /* languages, server to client */
	/* We never guess: a guess is only worth sending when you already know the
	 * peer's preferences, and it costs a discarded packet when wrong. */
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_u32(&w, 0); /* reserved */

	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

/* pick reads one name-list and resolves it against ours. */
static int pick(tc_ssh_rbuf *r, const char *const *ours, size_t count)
{
	size_t len = 0;
	const uint8_t *list = tc_ssh_get_string(r, SIZE_MAX, &len);
	if (list == NULL)
		return -1;
	return tc_ssh_namelist_first_supported(list, len, ours, count);
}

int tc_ssh_kexinit_parse(tc_ssh_negotiated *out, const uint8_t *payload,
                         size_t len)
{
	if (out == NULL || payload == NULL)
		return TC_ERR_INVAL;
	memset(out, 0, sizeof *out);

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_KEXINIT)
		return TC_ERR_INVAL;
	if (tc_ssh_get_raw(&r, TC_SSH_COOKIE_LEN) == NULL)
		return TC_ERR_INVAL;

	/* The first kex algorithm the peer lists, kept only to judge a guess. */
	size_t kex_list_len = 0;
	const uint8_t *kex_list = tc_ssh_get_string(&r, SIZE_MAX, &kex_list_len);
	if (kex_list == NULL)
		return TC_ERR_INVAL;
	out->kex = tc_ssh_namelist_first_supported(kex_list, kex_list_len,
	                                           tc_ssh_kex_algs,
	                                           NELEMS(tc_ssh_kex_algs));

	out->hostkey = pick(&r, tc_ssh_hostkey_algs, NELEMS(tc_ssh_hostkey_algs));
	out->cipher_c2s = pick(&r, tc_ssh_cipher_algs, NELEMS(tc_ssh_cipher_algs));
	out->cipher_s2c = pick(&r, tc_ssh_cipher_algs, NELEMS(tc_ssh_cipher_algs));
	/* The MAC lists are read to keep the field order right and then
	 * discarded: our only cipher is an AEAD, so RFC 4253 says the MAC
	 * algorithm is not used. Nothing is negotiated here that could be. */
	(void)tc_ssh_get_string(&r, SIZE_MAX, NULL);
	(void)tc_ssh_get_string(&r, SIZE_MAX, NULL);
	out->comp_c2s = pick(&r, tc_ssh_comp_algs, NELEMS(tc_ssh_comp_algs));
	out->comp_s2c = pick(&r, tc_ssh_comp_algs, NELEMS(tc_ssh_comp_algs));
	(void)tc_ssh_get_string(&r, SIZE_MAX, NULL); /* languages */
	(void)tc_ssh_get_string(&r, SIZE_MAX, NULL);
	out->first_kex_packet_follows = tc_ssh_get_bool(&r);
	(void)tc_ssh_get_u32(&r); /* reserved */

	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	if (out->kex < 0 || out->hostkey < 0 || out->cipher_c2s < 0 ||
	    out->cipher_s2c < 0 || out->comp_c2s < 0 || out->comp_s2c < 0)
		return TC_ERR_UNSUPPORTED;

	/* A guess is right only if the peer's *first* choice is what we settled
	 * on. Comparing against the negotiated result alone is not enough: the
	 * peer guesses with its own favourite, which may be an algorithm we
	 * support but rank lower. */
	if (out->first_kex_packet_follows) {
		size_t off = 0;
		size_t first_len = 0;
		while (off < kex_list_len && kex_list[off] != ',')
			off++;
		first_len = off;
		const char *chosen = tc_ssh_kex_algs[out->kex];
		out->guess_was_wrong =
		    !(first_len == strlen(chosen) &&
		      memcmp(kex_list, chosen, first_len) == 0);
	}
	return TC_OK;
}

/* ---- the exchange hash ------------------------------------------------- */

/* Hashed incrementally rather than assembled: the two KEXINIT payloads are a
 * few hundred bytes each and the host key blob is another, and a buffer big
 * enough for all of it is a buffer big enough to get wrong. */
static void hash_bytes(mbedtls_sha256_context *h, const void *p, size_t n)
{
	(void)mbedtls_sha256_update(h, (const unsigned char *)p, n);
}

static void hash_string(mbedtls_sha256_context *h, const void *p, size_t n)
{
	uint8_t len[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16),
		               (uint8_t)(n >> 8), (uint8_t)n };
	hash_bytes(h, len, sizeof len);
	if (n != 0)
		hash_bytes(h, p, n);
}

/* hash_mpint applies RFC 4251's minimal two's-complement form. The shared
 * secret is the only mpint in the exchange hash and the only place the rule
 * bites: about half of all secrets have their top bit set and need the
 * leading zero byte. */
static void hash_mpint(mbedtls_sha256_context *h, const uint8_t *be, size_t n)
{
	size_t i = 0;
	while (i < n && be[i] == 0)
		i++;
	size_t digits = n - i;
	if (digits == 0) {
		hash_string(h, NULL, 0);
		return;
	}
	bool pad = (be[i] & 0x80u) != 0;
	uint32_t total = (uint32_t)(digits + (pad ? 1u : 0u));
	uint8_t len[4] = { (uint8_t)(total >> 24), (uint8_t)(total >> 16),
		               (uint8_t)(total >> 8), (uint8_t)total };
	hash_bytes(h, len, sizeof len);
	if (pad) {
		static const uint8_t zero = 0;
		hash_bytes(h, &zero, 1);
	}
	hash_bytes(h, be + i, digits);
}

int tc_ssh_exchange_hash(uint8_t out[TC_SSH_HASH_LEN],
                         const tc_ssh_exchange *e)
{
	if (out == NULL || e == NULL || e->v_client == NULL ||
	    e->v_server == NULL || e->i_client == NULL || e->i_server == NULL ||
	    e->k_server == NULL || e->q_client == NULL || e->q_server == NULL ||
	    e->secret == NULL)
		return TC_ERR_INVAL;

	mbedtls_sha256_context h;
	mbedtls_sha256_init(&h);
	int rc = TC_ERR_INVAL;
	if (mbedtls_sha256_starts(&h, 0) != 0)
		goto out;

	hash_string(&h, e->v_client, e->v_client_len);
	hash_string(&h, e->v_server, e->v_server_len);
	hash_string(&h, e->i_client, e->i_client_len);
	hash_string(&h, e->i_server, e->i_server_len);
	hash_string(&h, e->k_server, e->k_server_len);
	hash_string(&h, e->q_client, TC_SSH_X25519_LEN);
	hash_string(&h, e->q_server, TC_SSH_X25519_LEN);
	/* An mpint, where the two keys above are strings. RFC 8731 3. */
	hash_mpint(&h, e->secret, e->secret_len);

	if (mbedtls_sha256_finish(&h, out) != 0)
		goto out;
	rc = TC_OK;
out:
	mbedtls_sha256_free(&h);
	return rc;
}

int tc_ssh_hostkey_blob(uint8_t *out, size_t cap, size_t *out_len,
                        const uint8_t pub[32])
{
	if (out == NULL || pub == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, pub, 32);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_signature_blob(uint8_t *out, size_t cap, size_t *out_len,
                          const uint8_t sig[64])
{
	if (out == NULL || sig == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, sig, 64);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

/* ---- key derivation ---------------------------------------------------- */

/* derive_one produces `want` bytes for the key named by `letter`. */
static int derive_one(uint8_t *out, size_t want, uint8_t letter,
                      const uint8_t *secret, size_t secret_len,
                      const uint8_t h[TC_SSH_HASH_LEN],
                      const uint8_t session_id[TC_SSH_HASH_LEN])
{
	size_t got = 0;
	uint8_t block[TC_SSH_HASH_LEN];

	while (got < want) {
		mbedtls_sha256_context ctx;
		mbedtls_sha256_init(&ctx);
		if (mbedtls_sha256_starts(&ctx, 0) != 0) {
			mbedtls_sha256_free(&ctx);
			return TC_ERR_INVAL;
		}
		/* K and H prefix every block, which is what keeps the extension from
		 * being a plain hash chain an attacker could continue. */
		hash_mpint(&ctx, secret, secret_len);
		hash_bytes(&ctx, h, TC_SSH_HASH_LEN);
		if (got == 0) {
			hash_bytes(&ctx, &letter, 1);
			hash_bytes(&ctx, session_id, TC_SSH_HASH_LEN);
		} else {
			/* Everything produced so far, not just the previous block. */
			hash_bytes(&ctx, out, got);
		}
		int rc = mbedtls_sha256_finish(&ctx, block);
		mbedtls_sha256_free(&ctx);
		if (rc != 0)
			return TC_ERR_INVAL;

		size_t take = want - got;
		if (take > sizeof block)
			take = sizeof block;
		memcpy(out + got, block, take);
		got += take;
	}
	tc_memzero_explicit(block, sizeof block);
	return TC_OK;
}

int tc_ssh_derive_keys(uint8_t c2s[TC_SSH_CIPHER_KEY_LEN],
                       uint8_t s2c[TC_SSH_CIPHER_KEY_LEN],
                       const uint8_t *secret, size_t secret_len,
                       const uint8_t h[TC_SSH_HASH_LEN],
                       const uint8_t session_id[TC_SSH_HASH_LEN])
{
	if (c2s == NULL || s2c == NULL || secret == NULL || h == NULL ||
	    session_id == NULL)
		return TC_ERR_INVAL;

	/* 'C' and 'D' are the encryption keys. 'A' and 'B' are IVs and 'E' and
	 * 'F' are MAC keys; this cipher needs neither, taking its nonce from the
	 * sequence number and its tag from the AEAD. */
	int rc = derive_one(c2s, TC_SSH_CIPHER_KEY_LEN, 'C', secret, secret_len, h,
	                    session_id);
	if (rc != TC_OK)
		return rc;
	return derive_one(s2c, TC_SSH_CIPHER_KEY_LEN, 'D', secret, secret_len, h,
	                  session_id);
}

int tc_ssh_disconnect_build(uint8_t *out, size_t cap, size_t *out_len,
                            uint32_t reason, const char *description)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_DISCONNECT);
	tc_ssh_put_u32(&w, reason);
	tc_ssh_put_cstring(&w, description != NULL ? description : "");
	tc_ssh_put_cstring(&w, ""); /* language tag */
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}
