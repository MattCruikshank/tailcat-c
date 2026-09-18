/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Publickey authentication.
 *
 * This is the file where a bug lets strangers in, so the tests are written
 * around the ways that happens rather than around the happy path. The four
 * that matter:
 *
 *   1. Verifying the signature and forgetting to check the key is authorized.
 *      The signature proves the client holds the private half of the key it
 *      named -- which is true of a key generated a second ago for the
 *      purpose. It says nothing about permission.
 *   2. Treating the query form, which carries no signature at all, as though
 *      it were authentication.
 *   3. Reading an empty authorized list as "no restriction" rather than
 *      "nobody". (The early return for this is belt and braces: with no keys
 *      the search loop finds nothing and denies anyway, so a mutation that
 *      deletes the early return is equivalent rather than a gap. It is kept
 *      because the intent should be legible at the top of the function.)
 *   4. Leaving the session id out of the signed blob, which makes a signature
 *      captured from one connection replayable on every other.
 *
 * Each has a test below that fails if the mistake is made.
 *
 * Those four are exercised with ed25519 requests built here, because building
 * them here is what lets a test bend one field at a time. What that cannot
 * catch is a format misunderstanding, since a request we assemble and a
 * request we parse would share it -- so test_real_requests below runs golden
 * vectors instead: keys from ssh-keygen, signatures from openssl. See
 * tools/gen-sshauth-vectors.py.
 */

#include "tc/sshauth.h"

#include "tc/authkeys.h"
#include "tc/ed25519.h"
#include "tc/sshwire.h"

#include "sshauth_vectors.h"
#include "tctest.h"

#include <string.h>

#define BUFSZ 1024

/* build_request assembles a USERAUTH_REQUEST, signing with `seed` over the
 * blob RFC 4252 section 7 defines. sign_session_id is passed separately so a
 * test can sign over the wrong one. */
static size_t build_request(uint8_t *out, size_t cap, const char *user,
                            const char *service, const uint8_t seed[32],
                            const uint8_t pub[32],
                            const uint8_t sign_session_id[32],
                            bool with_signature)
{
	uint8_t keyblob[BUFSZ];
	tc_ssh_wbuf kb;
	tc_ssh_wbuf_init(&kb, keyblob, sizeof keyblob);
	tc_ssh_put_cstring(&kb, "ssh-ed25519");
	tc_ssh_put_string(&kb, pub, 32);
	if (!tc_ssh_wbuf_ok(&kb))
		return 0;
	size_t keyblob_len = tc_ssh_wbuf_len(&kb);

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, user);
	tc_ssh_put_cstring(&w, service);
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, with_signature);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, keyblob, keyblob_len);

	if (with_signature) {
		uint8_t blob[BUFSZ];
		tc_ssh_wbuf b;
		tc_ssh_wbuf_init(&b, blob, sizeof blob);
		tc_ssh_put_string(&b, sign_session_id, TC_SSH_HASH_LEN);
		tc_ssh_put_byte(&b, TC_SSH_MSG_USERAUTH_REQUEST);
		tc_ssh_put_cstring(&b, user);
		tc_ssh_put_cstring(&b, service);
		tc_ssh_put_cstring(&b, "publickey");
		tc_ssh_put_bool(&b, true);
		tc_ssh_put_cstring(&b, "ssh-ed25519");
		tc_ssh_put_string(&b, keyblob, keyblob_len);
		if (!tc_ssh_wbuf_ok(&b))
			return 0;

		uint8_t sig[64];
		if (tc_ed25519_sign(sig, seed, pub, blob, tc_ssh_wbuf_len(&b)) !=
		    TC_OK)
			return 0;

		uint8_t sigblob[BUFSZ];
		tc_ssh_wbuf sb;
		tc_ssh_wbuf_init(&sb, sigblob, sizeof sigblob);
		tc_ssh_put_cstring(&sb, "ssh-ed25519");
		tc_ssh_put_string(&sb, sig, sizeof sig);
		if (!tc_ssh_wbuf_ok(&sb))
			return 0;
		tc_ssh_put_string(&w, sigblob, tc_ssh_wbuf_len(&sb));
	}

	return tc_ssh_wbuf_ok(&w) ? tc_ssh_wbuf_len(&w) : 0;
}

static void make_key(uint8_t seed[32], uint8_t pub[32], uint8_t fill)
{
	memset(seed, fill, 32);
	TCT_EQ_INT(tc_ed25519_public_from_seed(pub, seed), TC_OK);
}

/* pubkey_of builds the authorized-keys entry for an ed25519 public key: the
 * wire blob, which is what the server compares and what the client signs
 * over, rather than the bare 32 bytes. */
static tc_ssh_pubkey pubkey_of(const uint8_t pub[32])
{
	tc_ssh_pubkey k;
	memset(&k, 0, sizeof k);
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, k.blob, sizeof k.blob);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	tc_ssh_put_string(&w, pub, 32);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	k.len = tc_ssh_wbuf_len(&w);
	return k;
}

static void test_a_good_request_is_accepted(void)
{
	TCT_CASE("a signed request from an authorized key is accepted");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x11);
	memset(sid, 0xaa, sizeof sid);

	uint8_t msg[BUFSZ];
	size_t len = build_request(msg, sizeof msg, "tester", "ssh-connection",
	                           seed, pub, sid, true);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_PUBLICKEY);
	TCT_TRUE(req.has_signature);
	TCT_EQ_STR(req.user, "tester");
	TCT_EQ_STR(req.service, "ssh-connection");
	TCT_EQ_STR(req.algo, "ssh-ed25519");
	tc_ssh_pubkey expect = pubkey_of(pub);
	TCT_EQ_INT((int)req.pubkey.len, (int)expect.len);
	TCT_EQ_MEM(req.pubkey.blob, expect.blob, expect.len);

	tc_ssh_pubkey authorized = expect;
	TCT_EQ_INT(tc_ssh_auth_check(&req, sid, &authorized, 1), TC_OK);

	TCT_CASE("and one key among several is found");
	tc_ssh_pubkey many[4];
	memset(many, 0, sizeof many);
	many[2] = expect;
	TCT_EQ_INT(tc_ssh_auth_check(&req, sid, many, 4), TC_OK);

	TCT_CASE("a truncated authorized entry does not match a longer key");
	/* The length is part of the comparison, not just the bytes: a stored
	 * prefix of a key must not admit the key it is a prefix of. */
	tc_ssh_pubkey prefix = expect;
	prefix.len = expect.len - 1;
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &prefix, 1) != TC_OK);
}

static void test_an_unauthorized_key_is_refused(void)
{
	/* Mistake 1: the signature is perfectly valid. It was made by a key the
	 * client really holds -- one it generated itself. Only the authorized
	 * list can say no. */
	TCT_CASE("a valid signature from an unauthorized key is refused");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x22);
	memset(sid, 0xbb, sizeof sid);

	uint8_t msg[BUFSZ];
	size_t len = build_request(msg, sizeof msg, "tester", "ssh-connection",
	                           seed, pub, sid, true);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);

	uint8_t other_seed[32], other_pub[32];
	make_key(other_seed, other_pub, 0x33);
	tc_ssh_pubkey authorized = pubkey_of(other_pub);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("mistake 3: an empty authorized list denies rather than allows");
	/* The opposite convention from --allow, and deliberately so: an absent
	 * allow list means no restriction, an empty key list means nobody has
	 * been given a key. Reading the second as the first opens the door. */
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 0) != TC_OK);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, NULL, 0) != TC_OK);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, NULL, 1) != TC_OK);
}

static void test_the_query_form_never_authenticates(void)
{
	/* Mistake 2: a request with want_signature false carries no proof of
	 * anything. It is a question, and PK_OK is the answer to it. */
	TCT_CASE("a request with no signature never authenticates");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x44);
	memset(sid, 0xcc, sizeof sid);

	uint8_t msg[BUFSZ];
	size_t len = build_request(msg, sizeof msg, "tester", "ssh-connection",
	                           seed, pub, sid, false);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_PUBLICKEY);
	TCT_TRUE(!req.has_signature);

	/* Even though the key *is* authorized. */
	tc_ssh_pubkey authorized = pubkey_of(pub);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("and the flag is checked, not just the signature that is absent");
	/* The check above passes for a weaker reason than it looks: a parsed
	 * query form has an all-zero signature, which fails verification anyway.
	 * Deleting the has_signature test entirely therefore changed nothing and
	 * the mutation survived -- the test asserted the outcome without
	 * exercising the guard that is supposed to produce it.
	 *
	 * That protection comes from tc_ssh_auth_parse zeroing the struct, which
	 * is an invariant established in a different function. A caller reusing
	 * a request, or building one by hand, does not have it. So: a request
	 * carrying a genuinely valid signature, with the flag cleared. */
	uint8_t signed_msg[BUFSZ];
	size_t signed_len = build_request(signed_msg, sizeof signed_msg, "tester",
	                                  "ssh-connection", seed, pub, sid, true);
	TCT_TRUE(signed_len > 0);
	tc_ssh_auth_request valid;
	TCT_EQ_INT(tc_ssh_auth_parse(&valid, signed_msg, signed_len), TC_OK);
	TCT_EQ_INT(tc_ssh_auth_check(&valid, sid, &authorized, 1), TC_OK);

	valid.has_signature = false;
	TCT_TRUE(tc_ssh_auth_check(&valid, sid, &authorized, 1) != TC_OK);
}

static void test_the_session_id_is_bound(void)
{
	/* Mistake 4: without the session id in the signed blob, a signature
	 * lifted from one connection authenticates on every other one for ever.
	 * The session id is a hash of both sides' ephemeral keys, so it cannot
	 * be made to repeat. */
	TCT_CASE("a signature over another session's id is refused");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN], other[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x55);
	memset(sid, 0xdd, sizeof sid);
	memset(other, 0xee, sizeof other);

	uint8_t msg[BUFSZ];
	/* Signed over `other`, presented on the connection whose id is `sid`. */
	size_t len = build_request(msg, sizeof msg, "tester", "ssh-connection",
	                           seed, pub, other, true);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	tc_ssh_pubkey authorized = pubkey_of(pub);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("and it is accepted on the session it was made for");
	TCT_EQ_INT(tc_ssh_auth_check(&req, other, &authorized, 1), TC_OK);
}

static void test_the_signed_fields_are_bound(void)
{
	/* The user name and service name are inside the signed blob, so a
	 * request cannot be edited in flight to log in as somebody else. The
	 * test edits the parsed request, which is the same thing from the
	 * verifier's side. */
	TCT_CASE("changing the user name invalidates the signature");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x66);
	memset(sid, 0x99, sizeof sid);

	uint8_t msg[BUFSZ];
	size_t len = build_request(msg, sizeof msg, "alice", "ssh-connection",
	                           seed, pub, sid, true);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	tc_ssh_pubkey authorized = pubkey_of(pub);
	TCT_EQ_INT(tc_ssh_auth_check(&req, sid, &authorized, 1), TC_OK);

	snprintf(req.user, sizeof req.user, "root");
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("and so does changing the service name");
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	snprintf(req.service, sizeof req.service, "ssh-userauth");
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("and any single-bit change to the signature");
	/* The raw 64 bytes are the tail of the signature blob, which is the
	 * algorithm name and then the signature string. */
	for (int bit = 0; bit < 64; bit += 7) {
		TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
		TCT_TRUE(req.sigblob_len > 64);
		req.sigblob[req.sigblob_len - 64 + (size_t)(bit % 64)] ^=
		    (uint8_t)(1u << (bit % 8));
		if (tc_ssh_auth_check(&req, sid, &authorized, 1) == TC_OK)
			TCT_FAILF("a tampered signature was accepted (bit %d)", bit);
	}
	tct_checks++;

	TCT_CASE("and naming a different algorithm than the key blob carries");
	/* Algorithm confusion: the request names the signature algorithm, the
	 * blob names the key type. An ed25519 key offered under an RSA
	 * algorithm must not verify -- and must not be handed to the RSA code
	 * either, which is the more interesting half. */
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	snprintf(req.algo, sizeof req.algo, "rsa-sha2-256");
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, len), TC_OK);
	snprintf(req.algo, sizeof req.algo, "ecdsa-sha2-nistp256");
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);
}

static void test_real_requests(void)
{
	/* Requests nothing in this repository produced: RSA under both SHA-2
	 * signature algorithms, ECDSA on both curves, and ed25519. The RSA ones
	 * are the point -- their key blobs say `ssh-rsa` while the request says
	 * `rsa-sha2-256`, and the message signed contains the latter. An
	 * implementation that used one name where the other belongs verifies its
	 * own signatures perfectly and no client's. */
	for (size_t i = 0; i < tc_sshauth_num_vectors; i++) {
		const tc_sshauth_vector *v = &tc_sshauth_vectors[i];
		TCT_CASE(v->name);

		tc_ssh_auth_request req;
		TCT_EQ_INT(tc_ssh_auth_parse(&req, v->payload, v->payload_len),
		           TC_OK);
		TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_PUBLICKEY);
		TCT_TRUE(req.has_signature);
		TCT_EQ_STR(req.algo, v->algo);
		TCT_EQ_STR(req.user, TC_SSHAUTH_VECTOR_USER);
		TCT_EQ_STR(req.service, TC_SSHAUTH_VECTOR_SERVICE);

		/* The authorized entry comes from the vector, not from the parse, so
		 * a parser that mangled the blob could not also supply the thing it
		 * is compared against. */
		tc_ssh_pubkey authorized;
		memset(&authorized, 0, sizeof authorized);
		TCT_TRUE(v->keyblob_len <= sizeof authorized.blob);
		memcpy(authorized.blob, v->keyblob, v->keyblob_len);
		authorized.len = v->keyblob_len;
		TCT_EQ_INT((int)req.pubkey.len, (int)v->keyblob_len);
		TCT_EQ_MEM(req.pubkey.blob, v->keyblob, v->keyblob_len);

		TCT_EQ_INT(tc_ssh_auth_check(&req, tc_sshauth_vector_sid, &authorized,
		                             1),
		           TC_OK);

		/* And the same authorized_keys line a person would paste in. */
		tc_ssh_pubkey parsed;
		TCT_EQ_INT(tc_authkeys_parse_line(v->authorized_line, &parsed), TC_OK);
		TCT_EQ_INT((int)parsed.len, (int)v->keyblob_len);
		TCT_EQ_MEM(parsed.blob, v->keyblob, v->keyblob_len);

		TCT_CASE("on another session id it is refused");
		uint8_t other[TC_SSH_HASH_LEN];
		memcpy(other, tc_sshauth_vector_sid, sizeof other);
		other[0] ^= 1;
		TCT_TRUE(tc_ssh_auth_check(&req, other, &authorized, 1) != TC_OK);

		TCT_CASE("a single flipped bit in the signature is refused");
		/* Every eleventh bit rather than all of them: an RSA signature is
		 * 2048 bits and the loop is the slow part of this file. */
		for (size_t bit = 0; bit < req.sigblob_len * 8; bit += 11) {
			TCT_EQ_INT(tc_ssh_auth_parse(&req, v->payload, v->payload_len),
			           TC_OK);
			req.sigblob[bit / 8] ^= (uint8_t)(1u << (bit % 8));
			if (tc_ssh_auth_check(&req, tc_sshauth_vector_sid, &authorized,
			                      1) == TC_OK)
				TCT_FAILF("%s: a tampered signature was accepted (bit %zu)",
				          v->name, bit);
		}
		tct_checks++;

		TCT_CASE("under any other algorithm name it is refused");
		/* Algorithm confusion, in the form a client can actually send it: the
		 * request names one algorithm and the key blob is a different kind of
		 * key. Both the signature check and the key-type check should stop
		 * it, and it must not reach a verifier expecting another shape. */
		for (size_t j = 0; j < tc_ssh_auth_num_algos; j++) {
			if (strcmp(tc_ssh_auth_algos[j], v->algo) == 0)
				continue;
			TCT_EQ_INT(tc_ssh_auth_parse(&req, v->payload, v->payload_len),
			           TC_OK);
			snprintf(req.algo, sizeof req.algo, "%s", tc_ssh_auth_algos[j]);
			if (tc_ssh_auth_check(&req, tc_sshauth_vector_sid, &authorized,
			                      1) == TC_OK)
				TCT_FAILF("%s: accepted as %s", v->name,
				          tc_ssh_auth_algos[j]);
		}
		tct_checks++;

		TCT_CASE("and another vector's key does not authorize it");
		for (size_t j = 0; j < tc_sshauth_num_vectors; j++) {
			if (j == i)
				continue;
			const tc_sshauth_vector *w = &tc_sshauth_vectors[j];
			tc_ssh_pubkey wrong;
			memset(&wrong, 0, sizeof wrong);
			memcpy(wrong.blob, w->keyblob, w->keyblob_len);
			wrong.len = w->keyblob_len;
			TCT_EQ_INT(tc_ssh_auth_parse(&req, v->payload, v->payload_len),
			           TC_OK);
			if (tc_ssh_auth_check(&req, tc_sshauth_vector_sid, &wrong, 1) ==
			    TC_OK)
				TCT_FAILF("%s: authorized by %s's key", v->name, w->name);
		}
		tct_checks++;
	}

	TCT_CASE("a key blob swapped between two requests is refused");
	/* The blob is inside the signed message, so pasting another key into a
	 * valid request cannot be made to verify -- and this is the shape of the
	 * attack that a verifier checking the signature against the *offered*
	 * key while authorizing the *stored* one would fall for. */
	TCT_TRUE(tc_sshauth_num_vectors >= 2);
	for (size_t i = 0; i + 1 < tc_sshauth_num_vectors; i++) {
		const tc_sshauth_vector *v = &tc_sshauth_vectors[i];
		const tc_sshauth_vector *w = &tc_sshauth_vectors[i + 1];
		tc_ssh_auth_request req;
		TCT_EQ_INT(tc_ssh_auth_parse(&req, v->payload, v->payload_len), TC_OK);
		memset(&req.pubkey, 0, sizeof req.pubkey);
		memcpy(req.pubkey.blob, w->keyblob, w->keyblob_len);
		req.pubkey.len = w->keyblob_len;
		snprintf(req.algo, sizeof req.algo, "%s", w->algo);

		tc_ssh_pubkey authorized;
		memset(&authorized, 0, sizeof authorized);
		memcpy(authorized.blob, w->keyblob, w->keyblob_len);
		authorized.len = w->keyblob_len;
		if (tc_ssh_auth_check(&req, tc_sshauth_vector_sid, &authorized, 1) ==
		    TC_OK)
			TCT_FAILF("%s's signature passed for %s's key", v->name, w->name);
	}
	tct_checks++;
}

static void test_other_methods(void)
{
	TCT_CASE("the none method parses and never authenticates");
	uint8_t msg[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, "tester");
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "none");
	TCT_TRUE(tc_ssh_wbuf_ok(&w));

	tc_ssh_auth_request req;
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_NONE);
	uint8_t sid[TC_SSH_HASH_LEN], any[32];
	memset(sid, 0, sizeof sid);
	memset(any, 0x5a, sizeof any);
	tc_ssh_pubkey authorized = pubkey_of(any);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("a password request parses as a method we do not implement");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, "tester");
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "password");
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_cstring(&w, "hunter2");
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_OTHER);
	TCT_TRUE(tc_ssh_auth_check(&req, sid, &authorized, 1) != TC_OK);

	TCT_CASE("a DSA key parses as a method we cannot check");
	/* Not malformed: a client offering a key we will not verify gets a
	 * FAILURE and tries another, which is what lets an agent with several
	 * keys work. ssh-dss signs with SHA-1 and is not in our list. */
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, "tester");
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_cstring(&w, "ssh-dss");
	uint8_t fake[64];
	memset(fake, 7, sizeof fake);
	tc_ssh_put_string(&w, fake, sizeof fake);
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_OTHER);
}

static void test_malformed_requests(void)
{
	TCT_CASE("a truncated request is refused at every length");
	uint8_t seed[32], pub[32], sid[TC_SSH_HASH_LEN];
	make_key(seed, pub, 0x77);
	memset(sid, 0x88, sizeof sid);
	uint8_t msg[BUFSZ];
	size_t len = build_request(msg, sizeof msg, "tester", "ssh-connection",
	                           seed, pub, sid, true);
	TCT_TRUE(len > 0);

	tc_ssh_auth_request req;
	for (size_t cut = 1; cut < len; cut++) {
		if (tc_ssh_auth_parse(&req, msg, cut) == TC_OK &&
		    req.method == TC_SSH_AUTH_METHOD_PUBLICKEY && req.has_signature) {
			TCT_FAILF("a request truncated to %zu bytes looked complete", cut);
			break;
		}
	}
	tct_checks++;

	TCT_CASE("a key blob with trailing bytes is refused");
	/* Two encodings of one key would be two identities for one key. */
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_USERAUTH_REQUEST);
	tc_ssh_put_cstring(&w, "tester");
	tc_ssh_put_cstring(&w, "ssh-connection");
	tc_ssh_put_cstring(&w, "publickey");
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_cstring(&w, "ssh-ed25519");
	uint8_t blob[BUFSZ];
	tc_ssh_wbuf kb;
	tc_ssh_wbuf_init(&kb, blob, sizeof blob);
	tc_ssh_put_cstring(&kb, "ssh-ed25519");
	tc_ssh_put_string(&kb, pub, 32);
	tc_ssh_put_byte(&kb, 0xff); /* one byte too many */
	tc_ssh_put_string(&w, blob, tc_ssh_wbuf_len(&kb));
	TCT_EQ_INT(tc_ssh_auth_parse(&req, msg, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_EQ_INT((int)req.method, (int)TC_SSH_AUTH_METHOD_OTHER);

	TCT_CASE("a wrong message number is refused");
	msg[0] = TC_SSH_MSG_USERAUTH_SUCCESS;
	TCT_TRUE(tc_ssh_auth_parse(&req, msg, tc_ssh_wbuf_len(&w)) != TC_OK);
}

static void test_replies(void)
{
	uint8_t msg[BUFSZ];
	size_t len = 0;

	TCT_CASE("a failure names the methods still worth trying");
	TCT_EQ_INT(tc_ssh_auth_failure_build(msg, sizeof msg, &len), TC_OK);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_USERAUTH_FAILURE);
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, msg, len);
	(void)tc_ssh_get_byte(&r);
	TCT_TRUE(tc_ssh_get_string_eq(&r, "publickey"));
	/* Never a partial success with one method. */
	TCT_TRUE(!tc_ssh_get_bool(&r));
	TCT_TRUE(tc_ssh_rbuf_ok(&r));

	TCT_CASE("a success is one byte");
	TCT_EQ_INT(tc_ssh_auth_success_build(msg, sizeof msg, &len), TC_OK);
	TCT_EQ_INT((int)len, 1);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_USERAUTH_SUCCESS);

	TCT_CASE("PK_OK echoes the algorithm and the key it is approving");
	uint8_t pub[32];
	memset(pub, 0x5e, sizeof pub);
	tc_ssh_pubkey k = pubkey_of(pub);
	TCT_EQ_INT(tc_ssh_auth_pk_ok_build(msg, sizeof msg, &len, "ssh-ed25519",
	                                   &k),
	           TC_OK);
	tc_ssh_rbuf_init(&r, msg, len);
	TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SSH_MSG_USERAUTH_PK_OK);
	TCT_TRUE(tc_ssh_get_string_eq(&r, "ssh-ed25519"));
	size_t n = 0;
	const uint8_t *blob = tc_ssh_get_string(&r, TC_SSH_MAX_KEYBLOB, &n);
	TCT_TRUE(blob != NULL);
	TCT_EQ_INT((int)n, (int)k.len);
	TCT_EQ_MEM(blob, k.blob, k.len);

	TCT_CASE("and the algorithm it echoes is the request's, not the key's");
	/* RFC 8332: an RSA key is offered under rsa-sha2-256 while its blob
	 * still says ssh-rsa. A reply that echoed the blob's name instead
	 * would be answering about an algorithm the client did not ask about,
	 * and OpenSSH treats that as a mismatch. */
	TCT_EQ_INT(tc_ssh_auth_pk_ok_build(msg, sizeof msg, &len, "rsa-sha2-256",
	                                   &k),
	           TC_OK);
	tc_ssh_rbuf_init(&r, msg, len);
	TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SSH_MSG_USERAUTH_PK_OK);
	TCT_TRUE(tc_ssh_get_string_eq(&r, "rsa-sha2-256"));

	TCT_CASE("a service request round trips");
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_SERVICE_REQUEST);
	tc_ssh_put_cstring(&w, "ssh-userauth");
	char service[TC_SSH_MAX_SERVICE];
	TCT_EQ_INT(tc_ssh_service_request_parse(service, sizeof service, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_STR(service, "ssh-userauth");
}

int main(void)
{
	test_a_good_request_is_accepted();
	test_an_unauthorized_key_is_refused();
	test_the_query_form_never_authenticates();
	test_the_session_id_is_bound();
	test_the_signed_fields_are_bound();
	test_real_requests();
	test_other_methods();
	test_malformed_requests();
	test_replies();
	return tct_report("sshauth");
}
