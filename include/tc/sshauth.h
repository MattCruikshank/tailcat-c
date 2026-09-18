/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SSH user authentication (RFC 4252), publickey only.
 *
 * No password, no keyboard-interactive, no host-based. A drop box reachable
 * through a tunnel has no use for a password prompt, and every method left
 * out is one that cannot be misconfigured into working.
 *
 * This file parses `none` and never judges it: whether it succeeds is the
 * server's policy, in tc/sshserver.h, where it is tied to the same flag that
 * says the tunnel already did the authenticating. Keeping the decision there
 * rather than here is why it could be changed for bug 43 without touching
 * any of the signature checking below.
 *
 * ---- one function, because two would be a footgun ------------------------
 *
 * The classic way to get publickey auth catastrophically wrong is to verify
 * the signature and forget to check that the key is one you accept. The
 * signature proves the client holds the private half of the key it named --
 * which is true of every key in the world, including one generated a second
 * ago for this purpose. It says nothing about whether that key may log in.
 *
 * So there is no function here that verifies a signature on its own.
 * tc_ssh_auth_check takes the authorized keys and answers the only question
 * a server has: may this request in? Splitting it into "verify" and "is it
 * allowed" would make the dangerous half callable by itself, and it would
 * look complete.
 */
#ifndef TC_SSHAUTH_H_
#define TC_SSHAUTH_H_

#include "tc/sshkex.h"

#define TC_SSH_MSG_USERAUTH_REQUEST 50
#define TC_SSH_MSG_USERAUTH_FAILURE 51
#define TC_SSH_MSG_USERAUTH_SUCCESS 52
#define TC_SSH_MSG_USERAUTH_BANNER 53
/* 60 is method-specific; for publickey it is PK_OK. */
#define TC_SSH_MSG_USERAUTH_PK_OK 60

#define TC_SSH_MAX_USERNAME 64
#define TC_SSH_MAX_SERVICE 32
#define TC_SSH_ED25519_PUB_LEN 32
#define TC_SSH_ED25519_SIG_LEN 64

/* The largest public key and signature we will hold, in their SSH wire form.
 *
 * 768 covers an RSA-6144 key blob with room over; RSA-8192 exists and nobody
 * uses it, and a key too large to store is refused rather than truncated.
 * Signatures are bounded by the modulus for RSA, which is the same scale. */
#define TC_SSH_MAX_KEYBLOB 768
#define TC_SSH_MAX_SIGBLOB 768

/* A public key as it travels: the SSH wire encoding, opaque here.
 *
 * Kept as bytes rather than parsed because that is what the comparison has to
 * be. OpenSSH matches an offered key against authorized_keys by comparing
 * these blobs, upstream compares `key.Marshal()`, and the message the client
 * signs embeds the blob verbatim -- so the bytes are the identity, and
 * anything that parsed and re-encoded would be asserting that its round trip
 * is exact. */
typedef struct {
	uint8_t blob[TC_SSH_MAX_KEYBLOB];
	size_t len;
} tc_ssh_pubkey;

typedef enum {
	TC_SSH_AUTH_METHOD_NONE,      /* the probe every client opens with */
	TC_SSH_AUTH_METHOD_PUBLICKEY,
	TC_SSH_AUTH_METHOD_OTHER      /* anything we do not implement */
} tc_ssh_auth_method;

typedef struct {
	char user[TC_SSH_MAX_USERNAME];
	char service[TC_SSH_MAX_SERVICE];
	tc_ssh_auth_method method;

	/* publickey only. A request without a signature is the query form: the
	 * client is asking whether this key would be accepted before it troubles
	 * a hardware token or an agent for a signature. It must be answered with
	 * PK_OK or FAILURE and must never be treated as authentication. */
	bool has_signature;

	/* The key offered, exactly as sent. */
	tc_ssh_pubkey pubkey;

	/* The algorithm named in the *request*, which is not always the key's
	 * own type. RFC 8332 has a client present a key whose blob says
	 * "ssh-rsa" while signing with "rsa-sha2-256", and the signed message
	 * contains this name rather than the blob's. Conflating the two either
	 * rejects every modern RSA client or -- worse -- leaves the code
	 * unclear about which name it is actually verifying under. */
	/* Sized to match the buffer the parser reads it into, so no copy
	 * between them can truncate. Every name we accept is under 20 bytes. */
	char algo[64];

	/* The signature, still wrapped in its own algorithm-tagged blob. Parsed
	 * per algorithm at verification time, where the algorithm is known. */
	uint8_t sigblob[TC_SSH_MAX_SIGBLOB];
	size_t sigblob_len;
} tc_ssh_auth_request;

/* tc_ssh_auth_parse reads an SSH_MSG_USERAUTH_REQUEST payload.
 *
 * Returns TC_OK for any well-formed request, including methods we do not
 * support and keys we do not accept -- those are answered with a FAILURE
 * rather than a dropped connection, because a client that is told which
 * methods remain can try another one. TC_ERR_INVAL means malformed.
 *
 * A publickey request naming an algorithm we cannot verify parses as
 * TC_SSH_AUTH_METHOD_OTHER: it is a method we cannot check rather than a
 * protocol error. */
int tc_ssh_auth_parse(tc_ssh_auth_request *out, const uint8_t *payload,
                      size_t len);

/* tc_ssh_auth_check decides whether a request may in.
 *
 * Returns TC_OK only when all of the following hold: the method is
 * publickey, a signature is present, the key appears in `authorized`, and
 * the signature is valid over the blob RFC 4252 section 7 specifies.
 * Anything else is TC_ERR_INVAL -- one answer, because a server has one
 * decision to make and distinguishing the ways a request failed invites
 * treating some of them as nearly right.
 *
 * The signed blob begins with the session identifier, which is what stops a
 * signature captured from one connection being replayed on another: the
 * session id is a hash of both sides' ephemeral keys and cannot be made to
 * repeat.
 *
 * `authorized` is num_authorized key blobs. Matching is a byte comparison of
 * the blob, which is what OpenSSH does and what upstream does: the wire
 * encoding is the key's identity, and a comparison of anything reconstructed
 * from it would be asserting that the reconstruction is exact.
 *
 * An empty `authorized` list denies everything. That is the opposite of the
 * convention `--allow` follows elsewhere in this project, and deliberately:
 * an allow list that is absent means "no restriction", whereas an
 * authorized-keys list that is empty means "nobody has been given a key".
 * Reading the second as the first would open the drop box to the internet. */
int tc_ssh_auth_check(const tc_ssh_auth_request *req,
                      const uint8_t session_id[TC_SSH_HASH_LEN],
                      const tc_ssh_pubkey *authorized, size_t num_authorized);

/* tc_ssh_auth_can_verify reports whether an algorithm name is one this server
 * can check a signature under. Exposed because the server advertises the list
 * in EXT_INFO and the two must not drift. */
bool tc_ssh_auth_can_verify(const char *algo);

/* tc_ssh_pubkey_wellformed reports whether a blob really is a key of the type
 * `algo` implies: the right name inside, the right fields after it, and
 * nothing trailing.
 *
 * The last clause is the one worth naming. A blob with extra bytes on the end
 * decodes to the same key under a lenient reader and to a different blob under
 * a byte comparison -- so it is a second encoding of one key, and a list that
 * held both forms would be one key wearing two identities. It is also simply a
 * thing we did not understand, and echoing it back in PK_OK or storing it in
 * an authorized list means passing it on unread.
 *
 * For RSA, `algo` may be either the key type (`ssh-rsa`, as authorized_keys
 * writes it) or a signature algorithm (`rsa-sha2-256`); both name the same
 * blob structure. */
bool tc_ssh_pubkey_wellformed(const char *algo, const tc_ssh_pubkey *key);

/* tc_ssh_auth_key_type maps a signature algorithm to the type its key blob
 * carries. The two differ for RSA and only for RSA: RFC 8332's rsa-sha2-256
 * and rsa-sha2-512 sign keys whose blobs still say `ssh-rsa`. Any other name
 * comes back unchanged. */
const char *tc_ssh_auth_key_type(const char *algo);

/* tc_ssh_auth_can_verify_key_type reports whether a key *type* is one we can
 * check signatures for under some algorithm.
 *
 * This is the question authorized_keys asks, and it is not the same question
 * as tc_ssh_auth_can_verify: `ssh-rsa` is true here and false there. An
 * authorized_keys file names key types, so every RSA line in every such file
 * begins `ssh-rsa` -- while `ssh-rsa` as a *signature* algorithm means SHA-1,
 * which we do not accept. Conflating the two skips every RSA key there is. */
bool tc_ssh_auth_can_verify_key_type(const char *type);

/* The algorithms, most preferred first, for EXT_INFO's server-sig-algs.
 * Without that extension an OpenSSH client will not offer an RSA key at all:
 * it assumes SHA-1 `ssh-rsa` is all the server has, and refuses to use it. */
extern const char *const tc_ssh_auth_algos[];
extern const size_t tc_ssh_auth_num_algos;

/* tc_ssh_auth_failure_build writes SSH_MSG_USERAUTH_FAILURE, naming the
 * methods that could still work and whether this attempt partially
 * succeeded -- always false here, since one method is all there is. */
int tc_ssh_auth_failure_build(uint8_t *out, size_t cap, size_t *out_len);

/* tc_ssh_auth_success_build writes SSH_MSG_USERAUTH_SUCCESS. */
int tc_ssh_auth_success_build(uint8_t *out, size_t cap, size_t *out_len);

/* tc_ssh_auth_pk_ok_build answers the query form: this key would be
 * accepted, so go and produce a signature.
 *
 * RFC 4252 requires the reply to echo the algorithm and blob from the
 * request, and a client checks it -- OpenSSH treats a mismatch as the server
 * having answered about some other key, which it would be. */
int tc_ssh_auth_pk_ok_build(uint8_t *out, size_t cap, size_t *out_len,
                            const char *algo, const tc_ssh_pubkey *pubkey);

/* tc_ssh_service_accept_build answers SSH_MSG_SERVICE_REQUEST. */
int tc_ssh_service_accept_build(uint8_t *out, size_t cap, size_t *out_len,
                                const char *service);

/* tc_ssh_service_request_parse reads one, returning the service name. */
int tc_ssh_service_request_parse(char *out, size_t cap, const uint8_t *payload,
                                 size_t len);

#endif /* TC_SSHAUTH_H_ */
