/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A small, strict, allocation-free CBOR (RFC 8949) codec -- just the subset
 * tailcat addresses use.
 *
 * Addresses arrive from untrusted places (a pasted string, a "tailcat=" TXT
 * record), so the reader is deliberately narrow. It rejects:
 *
 *   - indefinite-length items (tailcat's encoder, fxamacker/cbor, never
 *     emits them);
 *   - tags (major type 6);
 *   - floats and simple values other than false/true/null/undefined;
 *   - the reserved additional-info values 28..30;
 *   - text strings that are not valid UTF-8, matching fxamacker's default
 *     UTF8RejectInvalid;
 *   - any container whose element count cannot fit in the bytes remaining,
 *     which also keeps element counts from overflowing later arithmetic.
 *
 * It deliberately does NOT require shortest-form (canonical) integer
 * encoding, because Go's decoder accepts non-canonical input and refusing it
 * could make us reject an address that real tailcat accepts.
 *
 * There is no recursion anywhere in this file, so nesting depth cannot
 * exhaust the stack.
 */
#ifndef TC_CBOR_H_
#define TC_CBOR_H_

#include "tc/tc.h"

typedef enum {
	TC_CBOR_UINT,   /* major 0 */
	TC_CBOR_NINT,   /* major 1 */
	TC_CBOR_BYTES,  /* major 2 */
	TC_CBOR_TEXT,   /* major 3 */
	TC_CBOR_ARRAY,  /* major 4 */
	TC_CBOR_MAP,    /* major 5 */
	TC_CBOR_SIMPLE  /* major 7: false=20, true=21, null=22, undefined=23 */
} tc_cbor_type;

#define TC_CBOR_FALSE 20u
#define TC_CBOR_TRUE 21u
#define TC_CBOR_NULL 22u
#define TC_CBOR_UNDEFINED 23u

typedef struct {
	tc_cbor_type type;
	/* For UINT: the value. For NINT: n, where the number is -1 - n.
	 * For BYTES/TEXT: the length. For ARRAY: the element count. For MAP:
	 * the pair count. For SIMPLE: the simple value. */
	uint64_t val;
	/* For BYTES and TEXT only: a pointer into the reader's buffer. It stays
	 * valid as long as that buffer does, and is never NUL-terminated. */
	const uint8_t *data;
	size_t data_len;
} tc_cbor_item;

typedef struct {
	const uint8_t *buf;
	size_t len;
	size_t pos;
} tc_cbor_reader;

/* tc_cbor_reader_init prepares r to read len bytes from buf. */
void tc_cbor_reader_init(tc_cbor_reader *r, const uint8_t *buf, size_t len);

/* tc_cbor_remaining returns how many unread bytes are left. */
size_t tc_cbor_remaining(const tc_cbor_reader *r);

/* tc_cbor_read reads the next item's head (and, for BYTES/TEXT, its payload).
 * For ARRAY and MAP it reads only the header; the elements follow. */
int tc_cbor_read(tc_cbor_reader *r, tc_cbor_item *out);

/* tc_cbor_peek reads the next item without consuming it. */
int tc_cbor_peek(const tc_cbor_reader *r, tc_cbor_item *out);

/* tc_cbor_skip consumes exactly one complete item, including all of a
 * container's elements. Used to ignore map entries we do not know. */
int tc_cbor_skip(tc_cbor_reader *r);

/* Typed convenience readers. Each consumes one item and fails with
 * TC_ERR_INVAL if the item is not of the expected type. */

/* tc_cbor_read_int accepts UINT and NINT and returns the value, failing with
 * TC_ERR_RANGE if it does not fit an int64_t. */
int tc_cbor_read_int(tc_cbor_reader *r, int64_t *out);

/* tc_cbor_read_bool accepts only the simple values false and true. */
int tc_cbor_read_bool(tc_cbor_reader *r, bool *out);

/* tc_cbor_read_bytes_exact requires a byte string of exactly n bytes and
 * copies it to out. Used for the fixed-size 32-byte keys. */
int tc_cbor_read_bytes_exact(tc_cbor_reader *r, uint8_t *out, size_t n);

/* tc_cbor_read_text copies a text string into out as a NUL-terminated
 * string, failing with TC_ERR_NOSPACE if it does not fit in cap bytes
 * (including the NUL). Embedded NULs are rejected, since the result is used
 * as a C string. */
int tc_cbor_read_text(tc_cbor_reader *r, char *out, size_t cap);

/* ---- Writer ---------------------------------------------------------- */

/* The writer uses a sticky error: once a write fails, later writes are
 * no-ops and tc_cbor_writer_finish reports it. That keeps call sites free of
 * per-call error checks without losing the failure. */
typedef struct {
	uint8_t *buf;
	size_t cap;
	size_t len;
	int err;
} tc_cbor_writer;

void tc_cbor_writer_init(tc_cbor_writer *w, uint8_t *buf, size_t cap);

/* All writers emit shortest-form heads, matching fxamacker/cbor's default
 * encoding, so a decode/encode round trip of a tailcat address is
 * byte-identical. */
void tc_cbor_write_uint(tc_cbor_writer *w, uint64_t v);
void tc_cbor_write_int(tc_cbor_writer *w, int64_t v);
void tc_cbor_write_bool(tc_cbor_writer *w, bool v);
void tc_cbor_write_null(tc_cbor_writer *w);
void tc_cbor_write_bytes(tc_cbor_writer *w, const uint8_t *p, size_t n);
void tc_cbor_write_text(tc_cbor_writer *w, const char *s, size_t n);
void tc_cbor_write_array_header(tc_cbor_writer *w, uint64_t count);
void tc_cbor_write_map_header(tc_cbor_writer *w, uint64_t pairs);

/* tc_cbor_writer_finish returns the sticky error, or TC_OK, and stores the
 * number of bytes written in *len when it succeeds. */
int tc_cbor_writer_finish(const tc_cbor_writer *w, size_t *len);

/* tc_utf8_valid reports whether p[0:n] is well-formed UTF-8, rejecting
 * overlong forms, surrogates and values above U+10FFFF. Exposed for tests. */
bool tc_utf8_valid(const uint8_t *p, size_t n);

#endif /* TC_CBOR_H_ */
