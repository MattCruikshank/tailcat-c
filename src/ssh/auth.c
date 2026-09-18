/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4252, publickey only. See tc/sshauth.h for why there is one function
 * rather than two.
 */

#include "tc/sshauth.h"

#include <stdio.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "tc/ed25519.h"
#include "tc/sshwire.h"

#include <string.h>

int tc_ssh_service_request_parse(char *out, size_t cap, const uint8_t *payload,
                                 size_t len)
{
	if (out == NULL || cap == 0 || payload == NULL)
		return TC_ERR_INVAL;
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_SERVICE_REQUEST)
		return TC_ERR_INVAL;
	if (!tc_ssh_get_cstring(&r, out, cap))
		return TC_ERR_INVAL;
	return tc_ssh_rbuf_ok(&r) ? TC_OK : TC_ERR_INVAL;
}

int tc_ssh_service_accept_build(uint8_t *out, size_t cap, size_t *out_len,
                                const char *service)
{
	if (out == NULL || service == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_SERVICE_ACCEPT);
	tc_ssh_put_cstring(&w, service);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

/* The algorithms a client may authenticate under, most preferred first.
 *
 * Deliberately not here: `ssh-rsa` and `ssh-dss`, both of which sign with
 * SHA-1. OpenSSH has disabled `ssh-rsa` by default since 8.8, and adding a
 * SHA-1 implementation back to accept a deprecated algorithm is a trade in
 * the wrong direction. Also absent: the `sk-*` hardware-token forms and the
 * `*-cert-v01@openssh.com` certificates, each a feature rather than an
 * algorithm. Upstream accepts all of those; this accepts everything anyone
 * has in practice, and says so in README's feature table. */
const char *const tc_ssh_auth_algos[] = {
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"rsa-sha2-512",
	"rsa-sha2-256",
};
const size_t tc_ssh_auth_num_algos =
    sizeof tc_ssh_auth_algos / sizeof tc_ssh_auth_algos[0];

bool tc_ssh_auth_can_verify(const char *algo)
{
	if (algo == NULL)
		return false;
	for (size_t i = 0; i < tc_ssh_auth_num_algos; i++)
		if (strcmp(algo, tc_ssh_auth_algos[i]) == 0)
			return true;
	return false;
}

/* key_type_for returns the key blob's own algorithm name for a request
 * algorithm. They differ for RSA and only for RSA: RFC 8332 added
 * rsa-sha2-256 and rsa-sha2-512 as *signature* algorithms over a key whose
 * blob still says "ssh-rsa". A verifier that looked for "rsa-sha2-256"
 * inside the key blob would reject every modern RSA client. */
static const char *key_type_for(const char *algo)
{
	if (strncmp(algo, "rsa-sha2-", 9) == 0)
		return "ssh-rsa";
	return algo;
}

const char *tc_ssh_auth_key_type(const char *algo)
{
	return algo == NULL ? NULL : key_type_for(algo);
}

bool tc_ssh_auth_can_verify_key_type(const char *type)
{
	if (type == NULL)
		return false;
	/* Derived from the one list rather than written out again, so a new
	 * algorithm cannot be verifiable while its key type is unreadable from
	 * authorized_keys -- which is a failure that looks like a bad key. */
	for (size_t i = 0; i < tc_ssh_auth_num_algos; i++)
		if (strcmp(type, key_type_for(tc_ssh_auth_algos[i])) == 0)
			return true;
	return false;
}

bool tc_ssh_pubkey_wellformed(const char *algo, const tc_ssh_pubkey *key)
{
	if (algo == NULL || key == NULL)
		return false;
	const char *type = key_type_for(algo);

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, key->blob, key->len);
	if (!tc_ssh_get_string_eq(&r, type))
		return false;

	if (strcmp(type, "ssh-ed25519") == 0) {
		size_t n = 0;
		const uint8_t *k = tc_ssh_get_string(&r, TC_SSH_ED25519_PUB_LEN, &n);
		if (k == NULL || n != TC_SSH_ED25519_PUB_LEN)
			return false;
	} else if (strcmp(type, "ssh-rsa") == 0) {
		/* Exponent then modulus, each an mpint. Their sizes are not fixed --
		 * a 2048-bit key and a 4096-bit one are both ordinary -- so this
		 * checks the shape and leaves the arithmetic to mbedtls. */
		size_t elen = 0, nlen = 0;
		if (tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &elen) == NULL ||
		    tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &nlen) == NULL)
			return false;
	} else if (strncmp(type, "ecdsa-sha2-", 11) == 0) {
		/* The curve is named a second time inside the blob, and it must be
		 * the same curve: a point on P-384 inside a key labelled P-256 is
		 * not a key, it is a question about our parser. */
		if (!tc_ssh_get_string_eq(&r, type + 11))
			return false;
		size_t qlen = 0;
		if (tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &qlen) == NULL ||
		    qlen == 0)
			return false;
	} else {
		return false;
	}

	return tc_ssh_rbuf_ok(&r) && tc_ssh_rbuf_remaining(&r) == 0;
}

/* unwrap_sig checks the signature blob's own algorithm tag and hands back
 * what it wraps.
 *
 * The tag has to match the algorithm the request named. A client that asks to
 * be verified under one algorithm and encloses a signature labelled another
 * is either broken or probing for exactly the confusion this rejects. */
static const uint8_t *unwrap_sig(const tc_ssh_auth_request *req,
                                 size_t *out_len)
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, req->sigblob, req->sigblob_len);
	if (!tc_ssh_get_string_eq(&r, req->algo))
		return NULL;
	const uint8_t *sig = tc_ssh_get_string(&r, TC_SSH_MAX_SIGBLOB, out_len);
	if (sig == NULL || tc_ssh_rbuf_remaining(&r) != 0)
		return NULL;
	return sig;
}

/* hash_msg reduces the signed message with the digest an algorithm implies.
 * The pairing is fixed by the algorithm name and is not negotiable: SHA-256
 * for rsa-sha2-256 and nistp256, SHA-512 for rsa-sha2-512, SHA-384 for
 * nistp384. */
static bool hash_msg(const char *algo, const uint8_t *msg, size_t msg_len,
                     uint8_t out[64], size_t *out_len,
                     mbedtls_md_type_t *md_type)
{
	if (strcmp(algo, "rsa-sha2-256") == 0 ||
	    strcmp(algo, "ecdsa-sha2-nistp256") == 0) {
		if (mbedtls_sha256(msg, msg_len, out, 0) != 0)
			return false;
		*out_len = 32;
		*md_type = MBEDTLS_MD_SHA256;
		return true;
	}
	if (strcmp(algo, "rsa-sha2-512") == 0) {
		if (mbedtls_sha512(msg, msg_len, out, 0) != 0)
			return false;
		*out_len = 64;
		*md_type = MBEDTLS_MD_SHA512;
		return true;
	}
	if (strcmp(algo, "ecdsa-sha2-nistp384") == 0) {
		/* SHA-384 is SHA-512's truncated variant; mbedtls selects it with
		 * the third argument. */
		if (mbedtls_sha512(msg, msg_len, out, 1) != 0)
			return false;
		*out_len = 48;
		*md_type = MBEDTLS_MD_SHA384;
		return true;
	}
	return false;
}

/* verify_rsa checks a PKCS#1 v1.5 signature over the hashed message.
 *
 * v1.5 and not PSS: RFC 8332 specifies v1.5 for rsa-sha2-*, and accepting
 * both would mean accepting a signature the client did not make in the form
 * the protocol names. mbedtls does the padding check, which is the part worth
 * not writing by hand -- a lenient v1.5 verifier is a forgery oracle. */
static bool verify_rsa(const tc_ssh_auth_request *req, const uint8_t *msg,
                       size_t msg_len)
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, req->pubkey.blob, req->pubkey.len);
	if (!tc_ssh_get_string_eq(&r, "ssh-rsa"))
		return false;
	size_t elen = 0, nlen = 0;
	const uint8_t *e = tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &elen);
	const uint8_t *n = tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &nlen);
	if (e == NULL || n == NULL || tc_ssh_rbuf_remaining(&r) != 0)
		return false;

	uint8_t digest[64];
	size_t dlen = 0;
	mbedtls_md_type_t md = MBEDTLS_MD_NONE;
	if (!hash_msg(req->algo, msg, msg_len, digest, &dlen, &md))
		return false;

	size_t sig_len = 0;
	const uint8_t *sig = unwrap_sig(req, &sig_len);
	if (sig == NULL)
		return false;

	bool ok = false;
	mbedtls_rsa_context rsa;
	mbedtls_rsa_init(&rsa);
	mbedtls_mpi N, E;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);
	if (mbedtls_mpi_read_binary(&N, n, nlen) == 0 &&
	    mbedtls_mpi_read_binary(&E, e, elen) == 0 &&
	    mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E) == 0 &&
	    mbedtls_rsa_complete(&rsa) == 0) {
		/* The signature is exactly the modulus size, always. A shorter one
		 * is not a small signature, it is a different number. */
		if (sig_len == mbedtls_rsa_get_len(&rsa))
			ok = mbedtls_rsa_pkcs1_verify(&rsa, md, (unsigned)dlen, digest,
			                              sig) == 0;
	}
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_rsa_free(&rsa);
	return ok;
}

/* verify_ecdsa checks an ECDSA signature over the hashed message.
 *
 * The signature is two mpints inside a string inside the signature blob,
 * which is one more layer than RSA has and easy to read past. */
static bool verify_ecdsa(const tc_ssh_auth_request *req, const uint8_t *msg,
                         size_t msg_len)
{
	mbedtls_ecp_group_id gid;
	const char *curve;
	if (strcmp(req->algo, "ecdsa-sha2-nistp256") == 0) {
		gid = MBEDTLS_ECP_DP_SECP256R1;
		curve = "nistp256";
	} else if (strcmp(req->algo, "ecdsa-sha2-nistp384") == 0) {
		gid = MBEDTLS_ECP_DP_SECP384R1;
		curve = "nistp384";
	} else {
		return false;
	}

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, req->pubkey.blob, req->pubkey.len);
	if (!tc_ssh_get_string_eq(&r, req->algo))
		return false;
	/* The curve is named twice, in the algorithm and again inside the blob,
	 * and the two must agree -- a key claiming one curve while carrying a
	 * point on another is not a key we should try to use. */
	if (!tc_ssh_get_string_eq(&r, curve))
		return false;
	size_t qlen = 0;
	const uint8_t *q = tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &qlen);
	if (q == NULL || qlen == 0 || tc_ssh_rbuf_remaining(&r) != 0)
		return false;

	uint8_t digest[64];
	size_t dlen = 0;
	mbedtls_md_type_t md = MBEDTLS_MD_NONE;
	if (!hash_msg(req->algo, msg, msg_len, digest, &dlen, &md))
		return false;

	size_t inner_len = 0;
	const uint8_t *inner = unwrap_sig(req, &inner_len);
	if (inner == NULL)
		return false;
	tc_ssh_rbuf sr;
	tc_ssh_rbuf_init(&sr, inner, inner_len);
	size_t rlen = 0, slen = 0;
	const uint8_t *rb = tc_ssh_get_string(&sr, TC_SSH_MAX_SIGBLOB, &rlen);
	const uint8_t *sb = tc_ssh_get_string(&sr, TC_SSH_MAX_SIGBLOB, &slen);
	if (rb == NULL || sb == NULL || tc_ssh_rbuf_remaining(&sr) != 0)
		return false;

	bool ok = false;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	mbedtls_mpi sig_r, sig_s;
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Q);
	mbedtls_mpi_init(&sig_r);
	mbedtls_mpi_init(&sig_s);
	if (mbedtls_ecp_group_load(&grp, gid) == 0 &&
	    mbedtls_ecp_point_read_binary(&grp, &Q, q, qlen) == 0 &&
	    mbedtls_ecp_check_pubkey(&grp, &Q) == 0 &&
	    mbedtls_mpi_read_binary(&sig_r, rb, rlen) == 0 &&
	    mbedtls_mpi_read_binary(&sig_s, sb, slen) == 0) {
		ok = mbedtls_ecdsa_verify(&grp, digest, dlen, &Q, &sig_r, &sig_s) ==
		     0;
	}
	mbedtls_mpi_free(&sig_r);
	mbedtls_mpi_free(&sig_s);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);
	return ok;
}

static bool verify_ed25519(const tc_ssh_auth_request *req,
                           const uint8_t *msg, size_t msg_len)
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, req->pubkey.blob, req->pubkey.len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519"))
		return false;
	size_t n = 0;
	const uint8_t *key = tc_ssh_get_string(&r, TC_SSH_ED25519_PUB_LEN, &n);
	if (key == NULL || n != TC_SSH_ED25519_PUB_LEN ||
	    tc_ssh_rbuf_remaining(&r) != 0)
		return false;

	size_t sig_len = 0;
	const uint8_t *sig = unwrap_sig(req, &sig_len);
	if (sig == NULL || sig_len != TC_SSH_ED25519_SIG_LEN)
		return false;
	return tc_ed25519_verify(sig, key, msg, msg_len) == TC_OK;
}

int tc_ssh_auth_parse(tc_ssh_auth_request *out, const uint8_t *payload,
                      size_t len)
{
	if (out == NULL || payload == NULL)
		return TC_ERR_INVAL;
	memset(out, 0, sizeof *out);

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_USERAUTH_REQUEST)
		return TC_ERR_INVAL;
	if (!tc_ssh_get_cstring(&r, out->user, sizeof out->user))
		return TC_ERR_INVAL;
	if (!tc_ssh_get_cstring(&r, out->service, sizeof out->service))
		return TC_ERR_INVAL;

	char method[32];
	if (!tc_ssh_get_cstring(&r, method, sizeof method)) {
		/* A method name too long for the buffer is not malformed, just not
		 * one of ours -- but the fields after it can no longer be located,
		 * so the request cannot be answered specifically. */
		return TC_ERR_INVAL;
	}

	if (strcmp(method, "none") == 0) {
		out->method = TC_SSH_AUTH_METHOD_NONE;
		return tc_ssh_rbuf_ok(&r) ? TC_OK : TC_ERR_INVAL;
	}
	if (strcmp(method, "publickey") != 0) {
		out->method = TC_SSH_AUTH_METHOD_OTHER;
		return TC_OK;
	}

	out->has_signature = tc_ssh_get_bool(&r);

	char algo[64];
	if (!tc_ssh_get_cstring(&r, algo, sizeof algo))
		return TC_ERR_INVAL;

	size_t blob_len = 0;
	const uint8_t *blob = tc_ssh_get_string(&r, 4096, &blob_len);
	if (blob == NULL)
		return TC_ERR_INVAL;

	/* An algorithm we cannot check, or a key too large to hold. Well-formed
	 * either way, and answered with a FAILURE so the client can offer
	 * another key rather than being hung up on. */
	if (!tc_ssh_auth_can_verify(algo) || blob_len > sizeof out->pubkey.blob) {
		out->method = TC_SSH_AUTH_METHOD_OTHER;
		return TC_OK;
	}

	/* The blob must actually be a key of the type the algorithm implies.
	 * Checked here and not only at verification time, because a mismatch is
	 * the client naming one thing and sending another, and the answer to
	 * that is the same FAILURE whether or not a signature follows -- and
	 * because PK_OK would otherwise echo a blob nothing had read. */
	memcpy(out->pubkey.blob, blob, blob_len);
	out->pubkey.len = blob_len;
	if (!tc_ssh_pubkey_wellformed(algo, &out->pubkey)) {
		memset(&out->pubkey, 0, sizeof out->pubkey);
		out->method = TC_SSH_AUTH_METHOD_OTHER;
		return TC_OK;
	}
	(void)snprintf(out->algo, sizeof out->algo, "%s", algo);
	out->method = TC_SSH_AUTH_METHOD_PUBLICKEY;

	if (out->has_signature) {
		size_t sig_len = 0;
		const uint8_t *sig = tc_ssh_get_string(&r, TC_SSH_MAX_SIGBLOB,
		                                       &sig_len);
		if (sig == NULL || sig_len > sizeof out->sigblob)
			return TC_ERR_INVAL;
		memcpy(out->sigblob, sig, sig_len);
		out->sigblob_len = sig_len;
	}

	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;
	return TC_OK;
}

/* signed_blob rebuilds exactly what RFC 4252 section 7 says the client signed.
 *
 * Rebuilt from the parsed fields rather than sliced out of the request, which
 * is the point at which an implementation can go quietly wrong in the other
 * direction: taking the bytes from the packet would sign whatever the client
 * sent, including fields we then failed to parse the same way. Rebuilding
 * means the thing verified is the thing we acted on. */
static int signed_blob(uint8_t *out, size_t cap, size_t *out_len,
                       const tc_ssh_auth_request *req,
                       const uint8_t session_id[TC_SSH_HASH_LEN])
{
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_string(&w, session_id, TC_SSH_HASH_LEN);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, req->user);
	tc_ssh_put_cstring(&w, req->service);
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, true);
	/* The algorithm as the *request* named it, not the key blob's own type.
	 * For RSA those differ, and signing the wrong one of them is the bug RFC
	 * 8332 invites -- it would verify against nothing a client ever sent. */
	tc_ssh_put_cstring(&w, req->algo);
	tc_ssh_put_string(&w, req->pubkey.blob, req->pubkey.len);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_auth_check(const tc_ssh_auth_request *req,
                      const uint8_t session_id[TC_SSH_HASH_LEN],
                      const tc_ssh_pubkey *authorized, size_t num_authorized)
{
	if (req == NULL || session_id == NULL)
		return TC_ERR_INVAL;
	if (req->method != TC_SSH_AUTH_METHOD_PUBLICKEY || !req->has_signature)
		return TC_ERR_INVAL;
	/* No keys configured means nobody is authorized, not everybody. */
	if (authorized == NULL || num_authorized == 0)
		return TC_ERR_INVAL;

	/* Authorization first. It is the cheaper check and the one that decides
	 * whether the signature is worth a curve operation at all -- which also
	 * means an unauthorized key costs an attacker nothing to discover, and
	 * that is fine: which keys a server accepts is not a secret it can keep
	 * from someone who can simply try them. */
	bool known = false;
	for (size_t i = 0; i < num_authorized; i++)
		if (authorized[i].len == req->pubkey.len &&
		    tc_ct_equal(authorized[i].blob, req->pubkey.blob,
		                req->pubkey.len))
			known = true;
	if (!known)
		return TC_ERR_INVAL;

	uint8_t blob[TC_SSH_MAX_KEYBLOB + 512];
	size_t blob_len = 0;
	int rc = signed_blob(blob, sizeof blob, &blob_len, req, session_id);
	if (rc != TC_OK)
		return rc;

	/* One dispatch, and every arm ends in somebody else's verifier. The
	 * algorithm is req->algo throughout -- the name the client asked to be
	 * judged under, which is also the name baked into the message above, so
	 * the two cannot disagree. */
	bool ok;
	if (strcmp(req->algo, "ssh-ed25519") == 0)
		ok = verify_ed25519(req, blob, blob_len);
	else if (strncmp(req->algo, "rsa-sha2-", 9) == 0)
		ok = verify_rsa(req, blob, blob_len);
	else if (strncmp(req->algo, "ecdsa-sha2-", 11) == 0)
		ok = verify_ecdsa(req, blob, blob_len);
	else
		ok = false;
	return ok ? TC_OK : TC_ERR_INVAL;
}

int tc_ssh_auth_failure_build(uint8_t *out, size_t cap, size_t *out_len)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_FAILURE);
	static const char *const methods[] = { "publickey" };
	tc_ssh_put_namelist(&w, methods, 1);
	/* Never a partial success: there is one method and it either worked or
	 * it did not. */
	tc_ssh_put_bool(&w, false);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_auth_success_build(uint8_t *out, size_t cap, size_t *out_len)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_SUCCESS);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_auth_pk_ok_build(uint8_t *out, size_t cap, size_t *out_len,
                            const char *algo, const tc_ssh_pubkey *pubkey)
{
	if (out == NULL || algo == NULL || pubkey == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_PK_OK);
	tc_ssh_put_cstring(&w, algo);
	tc_ssh_put_string(&w, pubkey->blob, pubkey->len);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}
