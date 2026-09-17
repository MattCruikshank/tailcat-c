/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH data types of RFC 4251 section 5: byte, boolean, uint32, uint64,
 * string, mpint and name-list. Allocation-free, bounds-checked, no recursion.
 *
 * Everything above this file -- the binary packet protocol, key exchange,
 * userauth and the connection layer -- is built out of these seven types, so
 * this is where the whole SSH subset either is or is not safe against a
 * hostile peer. Every field of every packet an attacker sends is read through
 * the reader below.
 *
 * ---- sticky errors -------------------------------------------------------
 *
 * Both the reader and the writer latch a failure rather than reporting it per
 * call, and once latched every later call is a no-op returning a safe zero.
 * That is deliberate. Parsing an SSH packet means a run of a dozen reads, and
 * a design that returns a status from each one is a design where exactly one
 * of them eventually goes unchecked -- which is how a truncated packet turns
 * into a read of uninitialised stack. Here the caller reads the whole
 * structure and asks tc_ssh_rbuf_ok() once at the end; an overrun anywhere
 * poisons everything after it, so a single check at the end cannot be fooled.
 *
 * The same argument applies to the writer, where the failure is a buffer too
 * small rather than a packet too short.
 *
 * ---- what the reader refuses --------------------------------------------
 *
 * - A string whose length field exceeds the bytes remaining. Checked against
 *   what is actually left rather than against a maximum, so a 4GB length on a
 *   40-byte packet is refused without any arithmetic that could wrap.
 * - A string longer than the caller's stated limit, where one is given.
 * - An mpint that is not in the minimal two's-complement form RFC 4251
 *   requires: no leading 0x00 unless the next byte has its high bit set, and
 *   no leading 0xff for a negative number. Non-minimal forms are refused
 *   rather than normalised, because two encodings of one value is how a
 *   signature or a key fingerprint gets two answers.
 * - A negative mpint, anywhere. Nothing in the subset we implement has a use
 *   for one, and accepting it would mean carrying a sign through arithmetic
 *   that has no other reason to have it.
 */
#ifndef TC_SSHWIRE_H_
#define TC_SSHWIRE_H_

#include "tc/tc.h"

/* ---- writer ----------------------------------------------------------- */

typedef struct {
	uint8_t *buf;
	size_t cap;
	size_t len;
	/* Latched when a write did not fit. The buffer contents are undefined
	 * from that point on and must not be transmitted. */
	bool full;
} tc_ssh_wbuf;

void tc_ssh_wbuf_init(tc_ssh_wbuf *w, uint8_t *buf, size_t cap);

/* tc_ssh_wbuf_ok reports whether everything written so far fitted. A false
 * here means the buffer holds a partial structure, never a valid one. */
bool tc_ssh_wbuf_ok(const tc_ssh_wbuf *w);

/* tc_ssh_wbuf_len is how many bytes have been written, or 0 once full. */
size_t tc_ssh_wbuf_len(const tc_ssh_wbuf *w);

void tc_ssh_put_byte(tc_ssh_wbuf *w, uint8_t v);
void tc_ssh_put_bool(tc_ssh_wbuf *w, bool v);
void tc_ssh_put_u32(tc_ssh_wbuf *w, uint32_t v);
void tc_ssh_put_u64(tc_ssh_wbuf *w, uint64_t v);

/* tc_ssh_put_raw appends bytes with no length prefix, for payloads that
 * already carry their own framing. */
void tc_ssh_put_raw(tc_ssh_wbuf *w, const void *data, size_t len);

/* tc_ssh_put_string appends a uint32 length followed by the bytes. This is
 * the SSH "string" type, which is a byte string and not text: it is never
 * NUL-terminated and may contain any byte. */
void tc_ssh_put_string(tc_ssh_wbuf *w, const void *data, size_t len);

/* tc_ssh_put_cstring is tc_ssh_put_string for a NUL-terminated C string,
 * which is how every algorithm name and service name in the protocol
 * reaches this layer. The NUL is not written. */
void tc_ssh_put_cstring(tc_ssh_wbuf *w, const char *s);

/* tc_ssh_put_mpint appends a non-negative big-endian integer in RFC 4251's
 * minimal two's-complement form: leading zero bytes are dropped, a 0x00 is
 * prepended if the top bit would otherwise be set, and zero encodes as an
 * empty string.
 *
 * This is how the Diffie-Hellman shared secret enters the exchange hash, and
 * getting it wrong there produces a hash mismatch and nothing more specific,
 * so the rules are implemented here once rather than at each call site. */
void tc_ssh_put_mpint(tc_ssh_wbuf *w, const uint8_t *be, size_t len);

/* tc_ssh_put_namelist appends a comma-separated name-list as a string.
 * Names must be US-ASCII with no commas; a name that is not is a programming
 * error here, since every name-list we emit is a compile-time constant, and
 * it latches the full flag rather than emitting something ambiguous. */
void tc_ssh_put_namelist(tc_ssh_wbuf *w, const char *const *names,
                         size_t count);

/* ---- reader ----------------------------------------------------------- */

typedef struct {
	const uint8_t *buf;
	size_t len;
	size_t off;
	/* Latched on the first malformed or truncated read. */
	bool bad;
} tc_ssh_rbuf;

void tc_ssh_rbuf_init(tc_ssh_rbuf *r, const void *buf, size_t len);

/* tc_ssh_rbuf_ok reports whether every read so far succeeded. Call it once,
 * after reading a whole structure, and before using any of the values. */
bool tc_ssh_rbuf_ok(const tc_ssh_rbuf *r);

/* tc_ssh_rbuf_remaining is how many bytes are left unread, or 0 if bad. */
size_t tc_ssh_rbuf_remaining(const tc_ssh_rbuf *r);

/* tc_ssh_rbuf_fail latches the error flag, for a caller that has decided the
 * structure is wrong for a reason this layer cannot see -- an unexpected
 * message number, say. It keeps "is this packet good?" a single question. */
void tc_ssh_rbuf_fail(tc_ssh_rbuf *r);

uint8_t tc_ssh_get_byte(tc_ssh_rbuf *r);
bool tc_ssh_get_bool(tc_ssh_rbuf *r);
uint32_t tc_ssh_get_u32(tc_ssh_rbuf *r);
uint64_t tc_ssh_get_u64(tc_ssh_rbuf *r);

/* tc_ssh_get_raw returns a pointer to len bytes and advances past them. The
 * pointer is into the caller's buffer and stays valid as long as it does.
 * Returns NULL and latches on truncation. */
const uint8_t *tc_ssh_get_raw(tc_ssh_rbuf *r, size_t len);

/* tc_ssh_get_string returns a pointer to the string's bytes and its length.
 * max is the largest length the caller will accept; a longer one latches
 * rather than being truncated, because a caller that asked for at most n
 * bytes and silently got a prefix of something longer is a caller that will
 * compare the wrong thing. Pass SIZE_MAX for no limit beyond the buffer.
 *
 * Returns NULL on failure. A zero-length string returns a non-NULL pointer
 * with *out_len 0, so NULL is unambiguously an error. */
const uint8_t *tc_ssh_get_string(tc_ssh_rbuf *r, size_t max, size_t *out_len);

/* tc_ssh_get_string_eq reads a string and reports whether it equals s. The
 * comparison is not constant-time and must not be used on a secret; it is
 * for algorithm and service names, which are public. */
bool tc_ssh_get_string_eq(tc_ssh_rbuf *r, const char *s);

/* tc_ssh_get_cstring reads a string into a NUL-terminated buffer of cap
 * bytes, including the terminator. A string that does not fit, or that
 * contains a NUL byte, latches -- an embedded NUL is how a name that looks
 * like "sftp" to us looks like something else to a filesystem. */
bool tc_ssh_get_cstring(tc_ssh_rbuf *r, char *out, size_t cap);

/* tc_ssh_get_mpint reads a non-negative mpint into a fixed-width big-endian
 * buffer of exactly out_len bytes, left-padded with zeros.
 *
 * A value too large for out_len latches, as does a negative one and any
 * encoding that is not minimal. Fixed width is what the callers want: an
 * SSH mpint becomes a 32-byte scalar or a 32-byte coordinate, and the
 * padding rules belong here rather than at four call sites. */
bool tc_ssh_get_mpint(tc_ssh_rbuf *r, uint8_t *out, size_t out_len);

/* tc_ssh_namelist_has reports whether a comma-separated name-list contains
 * name. The list is the raw bytes of a name-list string, which arrives from
 * the peer and is therefore neither NUL-terminated nor trusted. */
bool tc_ssh_namelist_has(const uint8_t *list, size_t len, const char *name);

/* tc_ssh_namelist_first_supported returns the index into `ours` of the first
 * name we support that also appears in the peer's list, or -1 if there is no
 * overlap.
 *
 * The direction matters and RFC 4253 section 7.1 fixes it: the *client's*
 * preference order decides, not the server's. A server that picks its own
 * favourite from the intersection will negotiate a different algorithm than
 * the client computed the exchange hash for. */
int tc_ssh_namelist_first_supported(const uint8_t *peer, size_t peer_len,
                                    const char *const *ours, size_t count);

#endif /* TC_SSHWIRE_H_ */
