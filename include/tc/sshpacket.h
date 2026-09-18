/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH version exchange and binary packet protocol (RFC 4253 sections 4.2
 * and 6), with OpenSSH's chacha20-poly1305 as the only cipher.
 *
 * Pure functions over caller-supplied buffers: nothing here reads or writes a
 * socket, so the whole layer is testable without one. The transport above it
 * does the I/O.
 *
 * ---- chacha20-poly1305@openssh.com is not the RFC 8439 AEAD --------------
 *
 * The name is the same and the construction is not, which is the single most
 * likely way to get this file subtly wrong. OpenSSH's own
 * PROTOCOL.chacha20poly1305 defines it:
 *
 *   - It takes **512 bits** of key material, not 256, and splits it into two
 *     independent ChaCha20 keys. The first 32 bytes are **K_2** and the
 *     second 32 are **K_1** -- that order is genuinely reversed from what the
 *     names suggest, and getting it backwards produces a cipher that is
 *     self-consistent and interoperates with nothing.
 *   - **K_1 encrypts only the four-byte packet length field.** It has its own
 *     key because the length must be readable before the packet it describes
 *     has been authenticated -- the receiver cannot know how many bytes to
 *     read otherwise. A separate key is what stops that early decryption from
 *     leaking anything about the payload.
 *   - **K_2 encrypts the payload**, with the Poly1305 key taken from block
 *     zero of its keystream and the payload itself encrypted from block one.
 *   - The nonce for both is the packet **sequence number** as a big-endian
 *     uint64, in ChaCha20's original 64-bit-nonce form rather than RFC 8439's
 *     96-bit form. Mbed TLS only offers the latter, so the mapping is done in
 *     this file and pinned by a vector.
 *   - The MAC covers the **ciphertext**, both the encrypted length field and
 *     the encrypted payload. Encrypt-then-MAC, so a forged packet is rejected
 *     before anything decrypts it.
 *
 * ---- the length field is read before it is trusted -----------------------
 *
 * Inherent to the design above: a receiver decrypts the length, then reads
 * that many bytes, then checks the MAC. So a peer -- or anyone who can
 * corrupt the stream -- can make us read up to the maximum packet size before
 * we discover the packet was forged. That bound is the whole of the
 * containment, which is why tc_ssh_packet_decode_length enforces it rather
 * than leaving it to the caller, and why it is deliberately far below what
 * the length field could express.
 */
#ifndef TC_SSHPACKET_H_
#define TC_SSHPACKET_H_

#include "tc/tc.h"

/* The version string both sides exchange before anything else. RFC 4253 4.2
 * caps the line at 255 bytes including CR LF. */
#define TC_SSH_VERSION_MAX 255

/* 512 bits, as the cipher requires: two ChaCha20 keys. */
#define TC_SSH_CIPHER_KEY_LEN 64
#define TC_SSH_MAC_LEN 16
#define TC_SSH_LENGTH_LEN 4

/* RFC 4253 6: at least four bytes of padding, and the encrypted region a
 * multiple of the block size -- 8 for a stream cipher. */
#define TC_SSH_MIN_PADDING 4
#define TC_SSH_BLOCK 8

/* The largest payload we will send or accept.
 *
 * RFC 4253 6 requires every implementation to handle 32768 bytes of payload,
 * and that is what we allow: enough for any packet the subset produces, and
 * small enough that the unauthenticated read described above stays bounded.
 * OpenSSH allows 256KB; there is nothing to gain here from matching it. */
#define TC_SSH_MAX_PAYLOAD 32768

/* What CHANNEL_DATA costs in front of the bytes it carries: the message type,
 * the recipient channel, and the string length. A sender that fills a buffer
 * to remote_max_packet and then asks for the message to be built has
 * overflowed it by exactly this much, which is how bug 38 happened. */
#define TC_SSH_CHANNEL_DATA_OVERHEAD 9

/* The largest whole packet on the wire, which is what a read buffer must
 * hold: length field, the encrypted region, and the tag. */
#define TC_SSH_MAX_PACKET                                                     \
	(TC_SSH_LENGTH_LEN + 1 + TC_SSH_MAX_PAYLOAD + TC_SSH_BLOCK * 2 +          \
	 TC_SSH_MAC_LEN)

/* One direction's cipher state. Before NEWKEYS the connection is in the
 * clear, which is `encrypted == false` rather than a separate code path:
 * RFC 4253's framing is identical either way, only the confidentiality
 * differs, and two code paths for one frame format is how they drift. */
typedef struct {
	bool encrypted;
	uint8_t k1[32]; /* the length field */
	uint8_t k2[32]; /* the payload, and the Poly1305 key */
	/* Incremented for every packet, in each direction independently,
	 * starting at zero with the first packet after the version exchange.
	 * It is the nonce, so it must never repeat under one key -- which is
	 * what makes rekeying mandatory rather than an optimisation. */
	uint32_t seq;
} tc_ssh_cipher;

/* tc_ssh_cipher_init_plain sets up the pre-NEWKEYS state. */
void tc_ssh_cipher_init_plain(tc_ssh_cipher *c);

/* tc_ssh_cipher_set_key installs 64 bytes of key material and turns
 * encryption on, keeping the sequence number: RFC 4253 is explicit that it
 * continues across a rekey rather than restarting. */
void tc_ssh_cipher_set_key(tc_ssh_cipher *c,
                           const uint8_t key[TC_SSH_CIPHER_KEY_LEN]);

/* tc_ssh_cipher_wipe clears the key material. */
void tc_ssh_cipher_wipe(tc_ssh_cipher *c);

/* ---- version exchange -------------------------------------------------- */

/* tc_ssh_version_build writes "SSH-2.0-<software>\r\n".
 *
 * software must be printable US-ASCII with no space, hyphen-minus rules
 * aside; RFC 4253 4.2 forbids space in the softwareversion field because a
 * space starts the optional comment. */
int tc_ssh_version_build(char *out, size_t cap, size_t *out_len,
                         const char *software);

/* tc_ssh_version_check validates a peer's identification line, with the
 * trailing CR LF already stripped.
 *
 * Returns TC_OK only for a line beginning "SSH-2.0-" or "SSH-1.99-", the
 * latter being a server that also speaks version 1. The line itself is what
 * goes into the exchange hash, so the caller keeps it verbatim -- including
 * any comment, and excluding the CR LF. */
int tc_ssh_version_check(const char *line, size_t len);

/* ---- packets ----------------------------------------------------------- */

/* tc_ssh_packet_encode builds one packet from a payload and advances the
 * sequence number.
 *
 * The padding is random, as RFC 4253 requires -- it is not merely filler,
 * since a stream cipher would otherwise leak the payload length modulo the
 * block size through a predictable tail. */
int tc_ssh_packet_encode(uint8_t *out, size_t cap, size_t *out_len,
                         const void *payload, size_t payload_len,
                         tc_ssh_cipher *c);

/* tc_ssh_packet_decode_length reads the packet length from the first four
 * bytes on the wire, decrypting them when encryption is on.
 *
 * It does NOT advance the sequence number, and it does NOT authenticate:
 * see the note at the top. It returns TC_ERR_INVAL for a length that is not
 * a whole number of blocks, is too small to hold the padding, or exceeds
 * TC_SSH_MAX_PAYLOAD -- so a caller never reads an unreasonable amount on
 * the strength of an unauthenticated number.
 *
 * *out_total is the whole packet size, which is what the caller must have in
 * hand before calling tc_ssh_packet_decode. */
int tc_ssh_packet_decode_length(const tc_ssh_cipher *c,
                                const uint8_t hdr[TC_SSH_LENGTH_LEN],
                                size_t *out_total);

/* tc_ssh_packet_decode verifies and decrypts one whole packet, returning the
 * payload, and advances the sequence number on success only.
 *
 * `in` is the complete packet including the length field and the tag, of
 * exactly the size tc_ssh_packet_decode_length reported. The payload is
 * written to out, which may not alias in.
 *
 * A failed tag check returns TC_ERR_INVAL having written nothing and having
 * left the sequence number alone; the connection must then be dropped rather
 * than resynchronised, because there is no way to know where the next packet
 * begins. */
int tc_ssh_packet_decode(uint8_t *out, size_t cap, size_t *out_len,
                         const uint8_t *in, size_t in_len, tc_ssh_cipher *c);

#endif /* TC_SSHPACKET_H_ */
