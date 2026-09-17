/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4252, publickey only. See tc/sshauth.h for why there is one function
 * rather than two.
 */

#include "tc/sshauth.h"

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

/* read_ed25519_key pulls a 32-byte key out of an ssh-ed25519 blob:
 * string "ssh-ed25519", string key. Returns false for any other algorithm,
 * which the caller turns into "a method we cannot check" rather than an
 * error -- a client offering an RSA key is not malformed. */
static bool read_ed25519_key(const uint8_t *blob, size_t blob_len,
                             uint8_t out[TC_SSH_ED25519_PUB_LEN])
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, blob_len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519"))
		return false;
	size_t n = 0;
	const uint8_t *key = tc_ssh_get_string(&r, TC_SSH_ED25519_PUB_LEN, &n);
	if (key == NULL || n != TC_SSH_ED25519_PUB_LEN)
		return false;
	/* Nothing may follow: a blob with trailing bytes is one whose bytes are
	 * not the bytes we will hash into the signed message. */
	if (tc_ssh_rbuf_remaining(&r) != 0)
		return false;
	memcpy(out, key, TC_SSH_ED25519_PUB_LEN);
	return tc_ssh_rbuf_ok(&r);
}

static bool read_ed25519_sig(const uint8_t *blob, size_t blob_len,
                             uint8_t out[TC_SSH_ED25519_SIG_LEN])
{
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, blob_len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519"))
		return false;
	size_t n = 0;
	const uint8_t *sig = tc_ssh_get_string(&r, TC_SSH_ED25519_SIG_LEN, &n);
	if (sig == NULL || n != TC_SSH_ED25519_SIG_LEN)
		return false;
	if (tc_ssh_rbuf_remaining(&r) != 0)
		return false;
	memcpy(out, sig, TC_SSH_ED25519_SIG_LEN);
	return tc_ssh_rbuf_ok(&r);
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

	if (strcmp(algo, "ssh-ed25519") != 0 ||
	    !read_ed25519_key(blob, blob_len, out->pubkey)) {
		/* A key type we cannot check. Well-formed, and answered with a
		 * FAILURE so the client can offer another key. */
		out->method = TC_SSH_AUTH_METHOD_OTHER;
		return TC_OK;
	}
	out->method = TC_SSH_AUTH_METHOD_PUBLICKEY;

	if (out->has_signature) {
		size_t sig_len = 0;
		const uint8_t *sig = tc_ssh_get_string(&r, 1024, &sig_len);
		if (sig == NULL || !read_ed25519_sig(sig, sig_len, out->signature))
			return TC_ERR_INVAL;
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
	uint8_t keyblob[4 + 11 + 4 + TC_SSH_ED25519_PUB_LEN];
	tc_ssh_wbuf kb;
	tc_ssh_wbuf_init(&kb, keyblob, sizeof keyblob);
	tc_ssh_put_cstring(&kb, "ssh-ed25519");
	tc_ssh_put_string(&kb, req->pubkey, TC_SSH_ED25519_PUB_LEN);
	if (!tc_ssh_wbuf_ok(&kb))
		return TC_ERR_NOSPACE;

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_string(&w, session_id, TC_SSH_HASH_LEN);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, req->user);
	tc_ssh_put_cstring(&w, req->service);
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, keyblob, tc_ssh_wbuf_len(&kb));
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_auth_check(const tc_ssh_auth_request *req,
                      const uint8_t session_id[TC_SSH_HASH_LEN],
                      const uint8_t *authorized, size_t num_authorized)
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
		if (tc_ct_equal(authorized + i * TC_SSH_ED25519_PUB_LEN, req->pubkey,
		                TC_SSH_ED25519_PUB_LEN))
			known = true;
	if (!known)
		return TC_ERR_INVAL;

	uint8_t blob[512];
	size_t blob_len = 0;
	int rc = signed_blob(blob, sizeof blob, &blob_len, req, session_id);
	if (rc != TC_OK)
		return rc;

	if (tc_ed25519_verify(req->signature, req->pubkey, blob, blob_len) !=
	    TC_OK)
		return TC_ERR_INVAL;
	return TC_OK;
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
                            const uint8_t pubkey[TC_SSH_ED25519_PUB_LEN])
{
	if (out == NULL || pubkey == NULL)
		return TC_ERR_INVAL;
	uint8_t keyblob[4 + 11 + 4 + TC_SSH_ED25519_PUB_LEN];
	tc_ssh_wbuf kb;
	tc_ssh_wbuf_init(&kb, keyblob, sizeof keyblob);
	tc_ssh_put_cstring(&kb, "ssh-ed25519");
	tc_ssh_put_string(&kb, pubkey, TC_SSH_ED25519_PUB_LEN);
	if (!tc_ssh_wbuf_ok(&kb))
		return TC_ERR_NOSPACE;

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_PK_OK);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, keyblob, tc_ssh_wbuf_len(&kb));
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}
