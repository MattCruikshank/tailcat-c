/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SSH key exchange: algorithm negotiation (RFC 4253 section 7),
 * curve25519-sha256 (RFC 8731), the exchange hash, and key derivation
 * (RFC 4253 section 7.2).
 *
 * Pure functions again: nothing here touches a socket or holds a state
 * machine, so every step can be checked against a fixed transcript.
 *
 * ---- what we offer, and why it is one of each ---------------------------
 *
 * One key exchange, one host key type, one cipher, no compression. A server
 * that offers a single modern algorithm cannot be downgraded to a weak one,
 * and there is no weak one here to fall back to. The cost is that a peer too
 * old to speak any of them fails rather than degrades, which for a tool whose
 * other end is usually the OpenSSH on the same machine is the right trade.
 *
 * The MAC lists are the one oddity. Our only cipher is an AEAD, so the MAC
 * algorithm is never consulted -- the tag comes from the cipher. We advertise
 * hmac-sha2-256 anyway, because an implementation that negotiates the MAC
 * list unconditionally would otherwise fail to find any overlap, and one that
 * follows RFC 4253 will never select it while an AEAD cipher is in force.
 *
 * ---- the exchange hash is the whole security argument -------------------
 *
 * H binds the two version strings, both KEXINIT payloads verbatim, the host
 * key, both ephemeral public keys and the shared secret into one digest that
 * the server signs. Everything an active attacker could have altered on the
 * way is inside it, which is what makes a man in the middle detectable rather
 * than merely inconvenient.
 *
 * That is why the KEXINIT payloads are hashed as the exact bytes that crossed
 * the wire rather than re-encoded from a parsed form: re-encoding would
 * quietly normalise whatever an attacker sent, and the signature would then
 * cover our tidied-up version instead of theirs.
 */
#ifndef TC_SSHKEX_H_
#define TC_SSHKEX_H_

#include "tc/sshpacket.h"

/* Message numbers, RFC 4253 section 12 and RFC 5656 section 7.1. */
#define TC_SSH_MSG_DISCONNECT 1
#define TC_SSH_MSG_IGNORE 2
#define TC_SSH_MSG_UNIMPLEMENTED 3
#define TC_SSH_MSG_DEBUG 4
#define TC_SSH_MSG_SERVICE_REQUEST 5
#define TC_SSH_MSG_SERVICE_ACCEPT 6
#define TC_SSH_MSG_KEXINIT 20
#define TC_SSH_MSG_NEWKEYS 21
/* 30 and 31 are reused by every kex method; these are their ECDH meanings. */
#define TC_SSH_MSG_KEX_ECDH_INIT 30
#define TC_SSH_MSG_KEX_ECDH_REPLY 31

#define TC_SSH_COOKIE_LEN 16
#define TC_SSH_HASH_LEN 32 /* SHA-256 */
#define TC_SSH_X25519_LEN 32

/* Disconnect reasons we send, RFC 4253 section 11.1. */
#define TC_SSH_DISCONNECT_KEY_EXCHANGE_FAILED 3
#define TC_SSH_DISCONNECT_MAC_ERROR 5
#define TC_SSH_DISCONNECT_PROTOCOL_ERROR 2
#define TC_SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14
#define TC_SSH_DISCONNECT_BY_APPLICATION 11

/* The algorithm names we offer, exposed so tests can assert on them rather
 * than restate them. */
extern const char *const tc_ssh_kex_algs[2];
extern const char *const tc_ssh_hostkey_algs[1];
extern const char *const tc_ssh_cipher_algs[1];
extern const char *const tc_ssh_mac_algs[1];
extern const char *const tc_ssh_comp_algs[1];

/* tc_ssh_kexinit_build writes a complete SSH_MSG_KEXINIT payload, message
 * number included, with a fresh random cookie.
 *
 * The bytes written are also what must be hashed later, so the caller keeps
 * them rather than rebuilding -- a second call would produce a different
 * cookie and a different hash. */
int tc_ssh_kexinit_build(uint8_t *out, size_t cap, size_t *out_len);

/* What a peer's KEXINIT resolved to. */
typedef struct {
	/* The index into our own list, so the caller names the algorithm rather
	 * than trusting a string from the peer. */
	int kex;
	int hostkey;
	int cipher_c2s;
	int cipher_s2c;
	int comp_c2s;
	int comp_s2c;
	/* RFC 4253 7.1: the peer may send a guessed kex packet immediately after
	 * its KEXINIT. If the guess does not match what was negotiated, that
	 * packet must be ignored -- and a caller that forgets will read the
	 * guess as though it were the real one. */
	bool first_kex_packet_follows;
	bool guess_was_wrong;
} tc_ssh_negotiated;

/* tc_ssh_kexinit_parse reads a peer's KEXINIT payload and negotiates.
 *
 * Returns TC_ERR_UNSUPPORTED when any list has no algorithm in common, which
 * is a clean failure rather than a fallback: there is nothing weaker to fall
 * back to. */
int tc_ssh_kexinit_parse(tc_ssh_negotiated *out, const uint8_t *payload,
                         size_t len);

/* Everything the exchange hash covers. Pointers are borrowed and must stay
 * valid for the call. */
typedef struct {
	const char *v_client; /* identification lines, with no CR LF */
	size_t v_client_len;
	const char *v_server;
	size_t v_server_len;
	const uint8_t *i_client; /* KEXINIT payloads, exactly as sent */
	size_t i_client_len;
	const uint8_t *i_server;
	size_t i_server_len;
	const uint8_t *k_server; /* the host key blob */
	size_t k_server_len;
	const uint8_t *q_client; /* 32-byte ephemeral public keys */
	const uint8_t *q_server;
	const uint8_t *secret; /* the X25519 output, big-endian */
	size_t secret_len;
} tc_ssh_exchange;

/* tc_ssh_exchange_hash computes H.
 *
 * The shared secret enters as an **mpint** while the two public keys enter as
 * strings, which is not a symmetry anyone would guess: RFC 8731 section 3
 * says so, and an implementation that encodes K as a string produces a hash
 * that differs from every other implementation's about half the time --
 * whenever the top bit of K happens to be set. */
int tc_ssh_exchange_hash(uint8_t out[TC_SSH_HASH_LEN],
                         const tc_ssh_exchange *e);

/* tc_ssh_hostkey_blob writes the ssh-ed25519 public key blob (RFC 8709):
 * string "ssh-ed25519", string key. */
int tc_ssh_hostkey_blob(uint8_t *out, size_t cap, size_t *out_len,
                        const uint8_t pub[32]);

/* tc_ssh_signature_blob writes string "ssh-ed25519", string signature. */
int tc_ssh_signature_blob(uint8_t *out, size_t cap, size_t *out_len,
                          const uint8_t sig[64]);

/* tc_ssh_derive_keys produces the two 64-byte cipher keys from K and H.
 *
 * RFC 4253 7.2 derives each key by hashing K, H, a single letter naming the
 * key, and the session id -- then extends it by hashing K, H and everything
 * produced so far. SHA-256 gives 32 bytes and this cipher wants 64, so every
 * key here needs both steps.
 *
 * session_id is H from the *first* exchange and stays fixed across rekeys,
 * which is what ties a later rekey to the identity originally proven. On the
 * first exchange the caller passes H itself. */
int tc_ssh_derive_keys(uint8_t c2s[TC_SSH_CIPHER_KEY_LEN],
                       uint8_t s2c[TC_SSH_CIPHER_KEY_LEN],
                       const uint8_t *secret, size_t secret_len,
                       const uint8_t h[TC_SSH_HASH_LEN],
                       const uint8_t session_id[TC_SSH_HASH_LEN]);

/* tc_ssh_disconnect_build writes an SSH_MSG_DISCONNECT payload. Sent in the
 * clear or encrypted depending on where the connection got to; either way it
 * tells the peer why rather than dropping the socket and leaving them to
 * guess. */
int tc_ssh_disconnect_build(uint8_t *out, size_t cap, size_t *out_len,
                            uint32_t reason, const char *description);

#endif /* TC_SSHKEX_H_ */
