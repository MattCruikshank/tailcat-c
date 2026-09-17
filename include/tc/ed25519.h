/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Ed25519 signatures, RFC 8032.
 *
 * The one primitive this project still had to borrow and could not. Mbed TLS
 * 3.6 has no Ed25519 at all -- not for signing, and not even for parsing an
 * Ed25519 certificate, which is what blocked TLS 1.3 against DERP relays. An
 * SSH server needs it too, for `ssh-ed25519` host and user keys. The same few
 * hundred lines unlock both, which is why they exist.
 *
 * ---- what is here, and what is deliberately not -------------------------
 *
 * PureEdDSA over edwards25519 only: the "Ed25519" of RFC 8032 section 5.1,
 * which is what OpenSSH, Go's crypto/ed25519, NaCl and everything else mean
 * by the name. Not Ed25519ctx, not Ed25519ph, not Ed448. Each is a different
 * domain-separated function, and an implementation that quietly accepted one
 * where another was meant would verify signatures nobody made.
 *
 * ---- why the curve arithmetic is here rather than borrowed --------------
 *
 * X25519 in this project is Mbed TLS's, because Mbed TLS has Curve25519.
 * Ed25519 uses the *same field* and a different curve -- a twisted Edwards
 * curve, birationally equivalent to the Montgomery one but with entirely
 * different formulas -- and Mbed TLS implements neither those formulas nor
 * the encoding. So the field arithmetic below is ours, and it is the part to
 * be suspicious of: everything above it is checkable against published
 * vectors, and a field bug shows up as a signature that verifies against our
 * own code and nothing else in the world.
 *
 * That is why the tests do not merely round-trip. They run RFC 8032's own
 * vectors, and every signature we produce is handed to Go's crypto/ed25519
 * to verify -- and every signature Go produces is handed to ours.
 *
 * ---- verification is cofactorless ---------------------------------------
 *
 * RFC 8032 permits checking either [S]B = R + [k]A (cofactorless) or
 * [8][S]B = [8]R + [8][k]A (cofactored). They accept slightly different sets
 * of signatures, and the difference matters for consensus protocols. We do
 * the cofactorless check, because that is what Go, OpenSSH and NaCl do, and
 * being in a different set from everything we interoperate with would be the
 * problem rather than the fix.
 *
 * S is required to be canonically reduced (S < L). Without that check a
 * signature can be trivially mauled into a different byte string that still
 * verifies, which breaks anything using the signature bytes as an identifier.
 */
#ifndef TC_ED25519_H_
#define TC_ED25519_H_

#include "tc/tc.h"

#define TC_ED25519_SEED_LEN 32
#define TC_ED25519_PUBLIC_LEN 32
#define TC_ED25519_SIGNATURE_LEN 64

/* tc_ed25519_public_from_seed derives the public key from a 32-byte seed.
 *
 * The seed is the private key. What RFC 8032 calls the private key *is* these
 * 32 bytes; the scalar and the nonce prefix are both derived from them by
 * hashing, and neither is stored. OpenSSH and NaCl store seed||public and
 * call the 64 bytes a "secret key", which is the same thing with the public
 * half cached. */
int tc_ed25519_public_from_seed(uint8_t out_pub[TC_ED25519_PUBLIC_LEN],
                                const uint8_t seed[TC_ED25519_SEED_LEN]);

/* tc_ed25519_keypair generates a fresh one from the CSPRNG. */
int tc_ed25519_keypair(uint8_t out_seed[TC_ED25519_SEED_LEN],
                       uint8_t out_pub[TC_ED25519_PUBLIC_LEN]);

/* tc_ed25519_sign produces a 64-byte signature.
 *
 * The public key is taken as an argument rather than re-derived, because it
 * is hashed into the challenge and callers almost always have it. It must be
 * the one belonging to the seed: signing with a mismatched pair produces a
 * signature that verifies under neither, silently.
 *
 * Deterministic, as RFC 8032 requires -- the nonce comes from hashing the
 * message under a secret prefix rather than from the CSPRNG, so there is no
 * randomness to fail and no repeated-nonce catastrophe to have. */
int tc_ed25519_sign(uint8_t out_sig[TC_ED25519_SIGNATURE_LEN],
                    const uint8_t seed[TC_ED25519_SEED_LEN],
                    const uint8_t pub[TC_ED25519_PUBLIC_LEN], const void *msg,
                    size_t msg_len);

/* tc_ed25519_verify checks one.
 *
 * Returns TC_OK only for a valid signature. Every other outcome -- a bad
 * signature, a public key that is not a point, an unreduced S -- is
 * TC_ERR_INVAL, because a caller has exactly one useful question here and
 * distinguishing the ways an attacker's input was wrong invites treating
 * some of them as nearly right. */
int tc_ed25519_verify(const uint8_t sig[TC_ED25519_SIGNATURE_LEN],
                      const uint8_t pub[TC_ED25519_PUBLIC_LEN],
                      const void *msg, size_t msg_len);

#endif /* TC_ED25519_H_ */
