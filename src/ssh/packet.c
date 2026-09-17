/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4253 sections 4.2 and 6. See tc/sshpacket.h for the reasoning, in
 * particular for why chacha20-poly1305@openssh.com is not the AEAD its name
 * suggests.
 */

#include "tc/sshpacket.h"

#include "tc/crypto.h"

#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"

#include <stdio.h>
#include <string.h>

/* ---- the cipher -------------------------------------------------------- */

void tc_ssh_cipher_init_plain(tc_ssh_cipher *c)
{
	if (c == NULL)
		return;
	memset(c, 0, sizeof *c);
	c->encrypted = false;
}

void tc_ssh_cipher_set_key(tc_ssh_cipher *c,
                           const uint8_t key[TC_SSH_CIPHER_KEY_LEN])
{
	if (c == NULL || key == NULL)
		return;
	/* The first half is K_2 and the second is K_1. That is the order
	 * OpenSSH's PROTOCOL.chacha20poly1305 specifies, and it reads backwards,
	 * which is exactly why it is written out here rather than left to a
	 * reader to infer from the offsets. */
	memcpy(c->k2, key, 32);
	memcpy(c->k1, key + 32, 32);
	c->encrypted = true;
}

void tc_ssh_cipher_wipe(tc_ssh_cipher *c)
{
	if (c == NULL)
		return;
	tc_memzero_explicit(c->k1, sizeof c->k1);
	tc_memzero_explicit(c->k2, sizeof c->k2);
	c->encrypted = false;
	c->seq = 0;
}

/* seq_nonce builds the 12-byte nonce Mbed TLS wants from the sequence number.
 *
 * OpenSSH uses ChaCha20 in its original form: a 64-bit counter in state words
 * 12 and 13, and a 64-bit nonce in words 14 and 15. RFC 8439 -- which is what
 * Mbed TLS implements -- moved the boundary, giving a 32-bit counter in word
 * 12 and a 96-bit nonce in words 13, 14 and 15.
 *
 * They describe the same keystream as long as the high half of the 64-bit
 * counter stays zero, which it does here: a packet is at most 32KB, so the
 * counter never leaves its low word. So word 13 must be zero and words 14 and
 * 15 must hold the big-endian sequence number, which means a nonce of four
 * zero bytes followed by the sequence number. Mbed TLS loads the nonce as
 * three little-endian words in order, so those eight bytes land in 14 and 15
 * exactly as OpenSSH's chacha_ivsetup puts them there. */
static void seq_nonce(uint8_t out[12], uint32_t seq)
{
	memset(out, 0, 12);
	/* Big-endian uint64 of the sequence number, in the last eight bytes. */
	out[8] = (uint8_t)(seq >> 24);
	out[9] = (uint8_t)(seq >> 16);
	out[10] = (uint8_t)(seq >> 8);
	out[11] = (uint8_t)seq;
}

/* poly_key derives the one-time Poly1305 key: the first 32 bytes of K_2's
 * keystream at counter zero. The payload starts at counter one, so the key
 * and the plaintext never share keystream. */
static int poly_key(uint8_t out[32], const tc_ssh_cipher *c, uint32_t seq)
{
	uint8_t nonce[12];
	seq_nonce(nonce, seq);
	uint8_t zeros[32];
	memset(zeros, 0, sizeof zeros);
	if (mbedtls_chacha20_crypt(c->k2, nonce, 0, sizeof zeros, zeros, out) != 0)
		return TC_ERR_INVAL;
	return TC_OK;
}

/* xor_length encrypts or decrypts the four-byte length field under K_1. The
 * operation is its own inverse, so one function serves both directions. */
static int xor_length(uint8_t out[4], const uint8_t in[4],
                      const tc_ssh_cipher *c, uint32_t seq)
{
	uint8_t nonce[12];
	seq_nonce(nonce, seq);
	if (mbedtls_chacha20_crypt(c->k1, nonce, 0, 4, in, out) != 0)
		return TC_ERR_INVAL;
	return TC_OK;
}

static int xor_payload(uint8_t *out, const uint8_t *in, size_t len,
                       const tc_ssh_cipher *c, uint32_t seq)
{
	if (len == 0)
		return TC_OK;
	uint8_t nonce[12];
	seq_nonce(nonce, seq);
	/* Counter one: block zero produced the Poly1305 key. */
	if (mbedtls_chacha20_crypt(c->k2, nonce, 1, len, in, out) != 0)
		return TC_ERR_INVAL;
	return TC_OK;
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
	       (uint32_t)p[3];
}

/* ---- version exchange -------------------------------------------------- */

int tc_ssh_version_build(char *out, size_t cap, size_t *out_len,
                         const char *software)
{
	if (out == NULL || software == NULL)
		return TC_ERR_INVAL;

	for (const char *p = software; *p != '\0'; p++) {
		/* RFC 4253 4.2: printable US-ASCII, and no space, because a space
		 * begins the optional comment field and would silently split this
		 * into two things. No minus either: the parser splits on it. */
		if ((unsigned char)*p < 0x21u || (unsigned char)*p > 0x7eu ||
		    *p == '-')
			return TC_ERR_INVAL;
	}

	int n = snprintf(out, cap, "SSH-2.0-%s\r\n", software);
	if (n < 0 || (size_t)n >= cap)
		return TC_ERR_NOSPACE;
	/* The cap is the protocol's, not the buffer's: a longer line is one no
	 * conforming peer will read. */
	if ((size_t)n > TC_SSH_VERSION_MAX)
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = (size_t)n;
	return TC_OK;
}

int tc_ssh_version_check(const char *line, size_t len)
{
	if (line == NULL)
		return TC_ERR_INVAL;
	/* The CR LF is the caller's to strip, so what arrives here must not
	 * still carry one -- a trailing CR left on would end up in the exchange
	 * hash and produce a mismatch with no other symptom. */
	if (len > TC_SSH_VERSION_MAX)
		return TC_ERR_INVAL;
	if (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n'))
		return TC_ERR_INVAL;

	static const char kV2[] = "SSH-2.0-";
	static const char kV199[] = "SSH-1.99-";
	bool v2 = len >= sizeof kV2 - 1 && memcmp(line, kV2, sizeof kV2 - 1) == 0;
	bool v199 =
	    len >= sizeof kV199 - 1 && memcmp(line, kV199, sizeof kV199 - 1) == 0;
	if (!v2 && !v199)
		return TC_ERR_INVAL;

	/* There must be something after the dash: an empty softwareversion is
	 * not a valid identification. */
	size_t prefix = v2 ? sizeof kV2 - 1 : sizeof kV199 - 1;
	if (len == prefix)
		return TC_ERR_INVAL;

	for (size_t i = 0; i < len; i++) {
		/* Printable US-ASCII or space; anything else, including an embedded
		 * NUL, is not a line we will hash and echo back. */
		unsigned char ch = (unsigned char)line[i];
		if (ch < 0x20u || ch > 0x7eu)
			return TC_ERR_INVAL;
	}
	return TC_OK;
}

/* ---- packets ----------------------------------------------------------- */

/* padding_for returns how many padding bytes a payload needs.
 *
 * Whether the length field counts toward the block alignment depends on the
 * cipher, and this is the detail that makes the two modes genuinely
 * different rather than merely differing in confidentiality:
 *
 *   - With chacha20-poly1305, the length field is encrypted separately under
 *     its own key and is *not* part of the aligned region. OpenSSH computes
 *     `block - ((len - aadlen) % block)` with aadlen 4.
 *   - Before NEWKEYS the cipher is "none", aadlen is 0, and RFC 4253's plain
 *     rule applies: the length field is counted like everything else.
 *
 * Using the AEAD rule for both is a server whose every handshake packet is
 * four bytes out of alignment, which OpenSSH rejects with "padding error:
 * need N block 8 mod 4" before the key exchange gets anywhere. Nothing
 * offline caught it here: the vectors are all encrypted. */
static size_t padding_for(size_t payload_len, bool encrypted)
{
	size_t base = encrypted ? (1 + payload_len)
	                        : (TC_SSH_LENGTH_LEN + 1 + payload_len);
	size_t pad = TC_SSH_BLOCK - (base % TC_SSH_BLOCK);
	if (pad < TC_SSH_MIN_PADDING)
		pad += TC_SSH_BLOCK;
	return pad;
}

int tc_ssh_packet_encode(uint8_t *out, size_t cap, size_t *out_len,
                         const void *payload, size_t payload_len,
                         tc_ssh_cipher *c)
{
	if (out == NULL || c == NULL)
		return TC_ERR_INVAL;
	if (payload == NULL && payload_len != 0)
		return TC_ERR_INVAL;
	if (payload_len > TC_SSH_MAX_PAYLOAD)
		return TC_ERR_TOOMANY;

	size_t pad = padding_for(payload_len, c->encrypted);
	size_t region = 1 + payload_len + pad; /* what gets encrypted */
	size_t total = TC_SSH_LENGTH_LEN + region +
	               (c->encrypted ? TC_SSH_MAC_LEN : 0);
	if (cap < total)
		return TC_ERR_NOSPACE;

	/* Assemble in the clear first, then encrypt in place. */
	wr32(out, (uint32_t)region);
	uint8_t *body = out + TC_SSH_LENGTH_LEN;
	body[0] = (uint8_t)pad;
	if (payload_len != 0)
		memcpy(body + 1, payload, payload_len);

	/* Random, not zeros: with a stream cipher a predictable tail would leak
	 * the payload length modulo the block size. RFC 4253 6 requires it. */
	int rc = tc_random_bytes(body + 1 + payload_len, pad);
	if (rc != TC_OK)
		return rc;

	if (c->encrypted) {
		rc = xor_payload(body, body, region, c, c->seq);
		if (rc != TC_OK)
			return rc;

		uint8_t pk[32];
		rc = poly_key(pk, c, c->seq);
		if (rc != TC_OK)
			return rc;

		rc = xor_length(out, out, c, c->seq);
		if (rc != TC_OK) {
			tc_memzero_explicit(pk, sizeof pk);
			return rc;
		}

		/* Encrypt-then-MAC over the whole ciphertext, length field
		 * included -- so a peer that tampers with the length is caught by
		 * the tag rather than by whatever the wrong length leads to. */
		int mrc = mbedtls_poly1305_mac(pk, out, TC_SSH_LENGTH_LEN + region,
		                               out + TC_SSH_LENGTH_LEN + region);
		tc_memzero_explicit(pk, sizeof pk);
		if (mrc != 0)
			return TC_ERR_INVAL;
	}

	c->seq++;
	if (out_len != NULL)
		*out_len = total;
	return TC_OK;
}

int tc_ssh_packet_decode_length(const tc_ssh_cipher *c,
                                const uint8_t hdr[TC_SSH_LENGTH_LEN],
                                size_t *out_total)
{
	if (c == NULL || hdr == NULL || out_total == NULL)
		return TC_ERR_INVAL;

	uint8_t plain[TC_SSH_LENGTH_LEN];
	if (c->encrypted) {
		int rc = xor_length(plain, hdr, c, c->seq);
		if (rc != TC_OK)
			return rc;
	} else {
		memcpy(plain, hdr, sizeof plain);
	}

	uint32_t region = rd32(plain);

	/* Every one of these bounds runs before the caller reads a single byte
	 * of the packet body, because at this point the number has been
	 * decrypted but not authenticated -- it is still entirely under the
	 * peer's control. */
	/* The same asymmetry as padding_for: the length field is inside the
	 * aligned region only when it is not separately encrypted. */
	/* Widened before the addition, not after: region is a uint32_t and a
	 * value near its maximum plus four wraps to a small number that passes
	 * the alignment check it should fail. */
	size_t aligned = (size_t)region +
	                 (c->encrypted ? 0u : (size_t)TC_SSH_LENGTH_LEN);
	if (aligned % TC_SSH_BLOCK != 0)
		return TC_ERR_INVAL;
	if (region < 1 + TC_SSH_MIN_PADDING)
		return TC_ERR_INVAL;
	if (region > 1 + TC_SSH_MAX_PAYLOAD + TC_SSH_BLOCK * 2)
		return TC_ERR_TOOMANY;

	*out_total = TC_SSH_LENGTH_LEN + region +
	             (c->encrypted ? TC_SSH_MAC_LEN : 0);
	return TC_OK;
}

int tc_ssh_packet_decode(uint8_t *out, size_t cap, size_t *out_len,
                         const uint8_t *in, size_t in_len, tc_ssh_cipher *c)
{
	if (out == NULL || in == NULL || c == NULL || out_len == NULL)
		return TC_ERR_INVAL;

	size_t want = 0;
	int rc = tc_ssh_packet_decode_length(c, in, &want);
	if (rc != TC_OK)
		return rc;
	/* The caller must hand over exactly the packet, not a prefix of the
	 * stream: a decoder that read "at least this much" would silently accept
	 * a short final packet as though the missing bytes were zeros. */
	if (in_len != want)
		return TC_ERR_INVAL;

	size_t region = want - TC_SSH_LENGTH_LEN -
	                (c->encrypted ? TC_SSH_MAC_LEN : 0);
	if (cap < region)
		return TC_ERR_NOSPACE;

	if (c->encrypted) {
		uint8_t pk[32];
		rc = poly_key(pk, c, c->seq);
		if (rc != TC_OK)
			return rc;

		uint8_t tag[TC_SSH_MAC_LEN];
		int mrc = mbedtls_poly1305_mac(pk, in, TC_SSH_LENGTH_LEN + region,
		                               tag);
		tc_memzero_explicit(pk, sizeof pk);
		if (mrc != 0)
			return TC_ERR_INVAL;

		/* Constant-time, and before any decryption: this is the whole point
		 * of encrypt-then-MAC, and comparing with memcmp would hand back a
		 * timing oracle on the tag. */
		if (!tc_ct_equal(tag, in + TC_SSH_LENGTH_LEN + region,
		                 TC_SSH_MAC_LEN))
			return TC_ERR_INVAL;

		rc = xor_payload(out, in + TC_SSH_LENGTH_LEN, region, c, c->seq);
		if (rc != TC_OK)
			return rc;
	} else {
		memcpy(out, in + TC_SSH_LENGTH_LEN, region);
	}

	size_t pad = out[0];
	/* Checked after authentication, so this is a well-formedness question
	 * about a packet we know the peer built, not an attack surface. A peer
	 * that gets it wrong is broken rather than hostile -- but a padding
	 * length of, say, 200 on a 16-byte region would underflow the payload
	 * size, so it is still checked rather than trusted. */
	if (pad < TC_SSH_MIN_PADDING || pad + 1 > region)
		return TC_ERR_INVAL;

	size_t payload_len = region - 1 - pad;
	memmove(out, out + 1, payload_len);
	*out_len = payload_len;

	c->seq++;
	return TC_OK;
}
