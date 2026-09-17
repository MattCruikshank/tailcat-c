/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SSH user authentication (RFC 4252), publickey only.
 *
 * No password, no keyboard-interactive, no host-based, and no "none" that
 * ever succeeds. A drop box reachable through a tunnel has no use for a
 * password prompt, and every method left out is one that cannot be
 * misconfigured into working.
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
	uint8_t pubkey[TC_SSH_ED25519_PUB_LEN];
	uint8_t signature[TC_SSH_ED25519_SIG_LEN];
} tc_ssh_auth_request;

/* tc_ssh_auth_parse reads an SSH_MSG_USERAUTH_REQUEST payload.
 *
 * Returns TC_OK for any well-formed request, including methods we do not
 * support and keys we do not accept -- those are answered with a FAILURE
 * rather than a dropped connection, because a client that is told which
 * methods remain can try another one. TC_ERR_INVAL means malformed.
 *
 * A publickey request naming an algorithm other than ssh-ed25519 parses as
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
 * `authorized` is num_authorized keys packed end to end, 32 bytes each.
 * A flat array rather than an array-of-arrays because ISO C before C2x will
 * not implicitly add a const qualifier through the inner array type, which
 * made every call site need a cast that hid what it was casting.
 *
 * An empty `authorized` list denies everything. That is the opposite of the
 * convention `--allow` follows elsewhere in this project, and deliberately:
 * an allow list that is absent means "no restriction", whereas an
 * authorized-keys list that is empty means "nobody has been given a key".
 * Reading the second as the first would open the drop box to the internet. */
int tc_ssh_auth_check(const tc_ssh_auth_request *req,
                      const uint8_t session_id[TC_SSH_HASH_LEN],
                      const uint8_t *authorized, size_t num_authorized);

/* tc_ssh_auth_failure_build writes SSH_MSG_USERAUTH_FAILURE, naming the
 * methods that could still work and whether this attempt partially
 * succeeded -- always false here, since one method is all there is. */
int tc_ssh_auth_failure_build(uint8_t *out, size_t cap, size_t *out_len);

/* tc_ssh_auth_success_build writes SSH_MSG_USERAUTH_SUCCESS. */
int tc_ssh_auth_success_build(uint8_t *out, size_t cap, size_t *out_len);

/* tc_ssh_auth_pk_ok_build answers the query form: this key would be
 * accepted, so go and produce a signature. */
int tc_ssh_auth_pk_ok_build(uint8_t *out, size_t cap, size_t *out_len,
                            const uint8_t pubkey[TC_SSH_ED25519_PUB_LEN]);

/* tc_ssh_service_accept_build answers SSH_MSG_SERVICE_REQUEST. */
int tc_ssh_service_accept_build(uint8_t *out, size_t cap, size_t *out_len,
                                const char *service);

/* tc_ssh_service_request_parse reads one, returning the service name. */
int tc_ssh_service_request_parse(char *out, size_t cap, const uint8_t *payload,
                                 size_t len);

#endif /* TC_SSHAUTH_H_ */
