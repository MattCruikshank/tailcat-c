/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See cbor.h for the scope and the strictness rules this implements.
 */

#include "tc/cbor.h"

#include <string.h>

#define MAJOR(b) ((unsigned)((b) >> 5))
#define AI(b) ((unsigned)((b) & 0x1fu))

enum {
	MT_UINT = 0,
	MT_NINT = 1,
	MT_BYTES = 2,
	MT_TEXT = 3,
	MT_ARRAY = 4,
	MT_MAP = 5,
	MT_TAG = 6,
	MT_SIMPLE = 7
};

void tc_cbor_reader_init(tc_cbor_reader *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->len = (buf == NULL) ? 0 : len;
	r->pos = 0;
}

size_t tc_cbor_remaining(const tc_cbor_reader *r)
{
	return r->len - r->pos;
}

bool tc_utf8_valid(const uint8_t *p, size_t n)
{
	size_t i = 0;
	while (i < n) {
		uint8_t c = p[i];
		size_t extra;
		uint32_t cp;

		if (c < 0x80u) {
			i++;
			continue;
		} else if ((c & 0xe0u) == 0xc0u) {
			extra = 1;
			cp = c & 0x1fu;
		} else if ((c & 0xf0u) == 0xe0u) {
			extra = 2;
			cp = c & 0x0fu;
		} else if ((c & 0xf8u) == 0xf0u) {
			extra = 3;
			cp = c & 0x07u;
		} else {
			return false; /* continuation byte, or a 5/6-byte form */
		}

		if (n - i - 1 < extra)
			return false;
		for (size_t k = 1; k <= extra; k++) {
			uint8_t cc = p[i + k];
			if ((cc & 0xc0u) != 0x80u)
				return false;
			cp = cp << 6 | (cc & 0x3fu);
		}
		/* Reject overlong encodings, UTF-16 surrogates and out-of-range. */
		if (extra == 1 && cp < 0x80u)
			return false;
		if (extra == 2 && cp < 0x800u)
			return false;
		if (extra == 3 && cp < 0x10000u)
			return false;
		if (cp > 0x10ffffu)
			return false;
		if (cp >= 0xd800u && cp <= 0xdfffu)
			return false;

		i += extra + 1;
	}
	return true;
}

/* read_head decodes one item head starting at *pos, advancing *pos. It does
 * not consume byte/text payloads. */
static int read_head(const uint8_t *buf, size_t len, size_t *pos,
                     unsigned *major, uint64_t *val)
{
	size_t p = *pos;
	if (p >= len)
		return TC_ERR_TRUNC;

	uint8_t ib = buf[p++];
	unsigned mt = MAJOR(ib);
	unsigned ai = AI(ib);
	uint64_t v;

	if (ai < 24u) {
		v = ai;
	} else if (ai >= 24u && ai <= 27u) {
		size_t nbytes = (size_t)1u << (ai - 24u); /* 1, 2, 4, 8 */
		if (len - p < nbytes)
			return TC_ERR_TRUNC;
		v = 0;
		for (size_t i = 0; i < nbytes; i++)
			v = v << 8 | buf[p + i];
		p += nbytes;
	} else if (ai == 31u) {
		/* Indefinite-length item, or a break stop code. */
		return TC_ERR_UNSUPPORTED;
	} else {
		/* 28..30 are reserved and must be rejected. */
		return TC_ERR_INVAL;
	}

	*pos = p;
	*major = mt;
	*val = v;
	return TC_OK;
}

static int read_item(const tc_cbor_reader *r, size_t *pos, tc_cbor_item *out)
{
	unsigned mt;
	uint64_t v;
	int rc = read_head(r->buf, r->len, pos, &mt, &v);
	if (rc != TC_OK)
		return rc;

	size_t remaining = r->len - *pos;

	out->data = NULL;
	out->data_len = 0;
	out->val = v;

	switch (mt) {
	case MT_UINT:
		out->type = TC_CBOR_UINT;
		return TC_OK;

	case MT_NINT:
		out->type = TC_CBOR_NINT;
		return TC_OK;

	case MT_BYTES:
	case MT_TEXT: {
		/* v is a length in bytes. Comparing it against the bytes
		 * remaining both validates it and proves it fits in a size_t. */
		if (v > (uint64_t)remaining)
			return TC_ERR_TRUNC;
		size_t n = (size_t)v;
		if (mt == MT_TEXT && !tc_utf8_valid(r->buf + *pos, n))
			return TC_ERR_INVAL;
		out->type = (mt == MT_BYTES) ? TC_CBOR_BYTES : TC_CBOR_TEXT;
		out->data = r->buf + *pos;
		out->data_len = n;
		*pos += n;
		return TC_OK;
	}

	case MT_ARRAY:
		/* Every element costs at least one byte, so a count larger than
		 * the bytes remaining is necessarily truncated. This bound is
		 * also what keeps tc_cbor_skip's accumulator from overflowing. */
		if (v > (uint64_t)remaining)
			return TC_ERR_TRUNC;
		out->type = TC_CBOR_ARRAY;
		return TC_OK;

	case MT_MAP:
		/* Each pair costs at least two bytes. */
		if (v > (uint64_t)remaining / 2u)
			return TC_ERR_TRUNC;
		out->type = TC_CBOR_MAP;
		return TC_OK;

	case MT_TAG:
		return TC_ERR_UNSUPPORTED;

	case MT_SIMPLE:
	default:
		/* ai 25/26/27 are float16/32/64, which read_head decoded as if
		 * they were integer payloads; reject those along with any simple
		 * value we do not expect. */
		if (v < TC_CBOR_FALSE || v > TC_CBOR_UNDEFINED)
			return TC_ERR_UNSUPPORTED;
		out->type = TC_CBOR_SIMPLE;
		return TC_OK;
	}
}

int tc_cbor_read(tc_cbor_reader *r, tc_cbor_item *out)
{
	size_t pos = r->pos;
	int rc = read_item(r, &pos, out);
	if (rc != TC_OK)
		return rc;
	r->pos = pos;
	return TC_OK;
}

int tc_cbor_peek(const tc_cbor_reader *r, tc_cbor_item *out)
{
	size_t pos = r->pos;
	return read_item(r, &pos, out);
}

int tc_cbor_skip(tc_cbor_reader *r)
{
	/* Iterative, so deep nesting costs no stack. pending counts the items
	 * still owed to us; it stays bounded by the buffer length because
	 * read_item rejects container counts larger than the bytes remaining. */
	uint64_t pending = 1;

	while (pending > 0) {
		tc_cbor_item it;
		int rc = tc_cbor_read(r, &it);
		if (rc != TC_OK)
			return rc;
		pending--;

		if (it.type == TC_CBOR_ARRAY)
			pending += it.val;
		else if (it.type == TC_CBOR_MAP)
			pending += it.val * 2u;
	}
	return TC_OK;
}

int tc_cbor_read_int(tc_cbor_reader *r, int64_t *out)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;

	if (it.type == TC_CBOR_UINT) {
		if (it.val > (uint64_t)INT64_MAX)
			return TC_ERR_RANGE;
		*out = (int64_t)it.val;
		return TC_OK;
	}
	if (it.type == TC_CBOR_NINT) {
		/* The encoded value n means -1 - n. The most negative result is
		 * INT64_MIN, reached when n == INT64_MAX. */
		if (it.val > (uint64_t)INT64_MAX)
			return TC_ERR_RANGE;
		*out = -1 - (int64_t)it.val;
		return TC_OK;
	}
	return TC_ERR_INVAL;
}

int tc_cbor_read_bool(tc_cbor_reader *r, bool *out)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;
	if (it.type != TC_CBOR_SIMPLE ||
	    (it.val != TC_CBOR_FALSE && it.val != TC_CBOR_TRUE))
		return TC_ERR_INVAL;
	*out = (it.val == TC_CBOR_TRUE);
	return TC_OK;
}

int tc_cbor_read_bytes_exact(tc_cbor_reader *r, uint8_t *out, size_t n)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;
	if (it.type != TC_CBOR_BYTES)
		return TC_ERR_INVAL;
	if (it.data_len != n)
		return TC_ERR_INVAL;
	memcpy(out, it.data, n);
	return TC_OK;
}

int tc_cbor_read_text(tc_cbor_reader *r, char *out, size_t cap)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;
	if (it.type != TC_CBOR_TEXT)
		return TC_ERR_INVAL;
	if (cap == 0 || it.data_len > cap - 1)
		return TC_ERR_NOSPACE;
	/* The value becomes a C string, so an embedded NUL would silently
	 * truncate it. Refuse rather than truncate. */
	if (memchr(it.data, 0, it.data_len) != NULL)
		return TC_ERR_INVAL;
	memcpy(out, it.data, it.data_len);
	out[it.data_len] = 0;
	return TC_OK;
}

/* ---- Writer ---------------------------------------------------------- */

void tc_cbor_writer_init(tc_cbor_writer *w, uint8_t *buf, size_t cap)
{
	w->buf = buf;
	w->cap = (buf == NULL) ? 0 : cap;
	w->len = 0;
	w->err = TC_OK;
}

static void put(tc_cbor_writer *w, const void *p, size_t n)
{
	if (w->err != TC_OK)
		return;
	if (n > w->cap - w->len) {
		w->err = TC_ERR_NOSPACE;
		return;
	}
	memcpy(w->buf + w->len, p, n);
	w->len += n;
}

static void write_head(tc_cbor_writer *w, unsigned major, uint64_t v)
{
	uint8_t b[9];
	size_t n;
	uint8_t mt = (uint8_t)(major << 5);

	if (v < 24u) {
		b[0] = (uint8_t)(mt | (uint8_t)v);
		n = 1;
	} else if (v <= 0xffu) {
		b[0] = (uint8_t)(mt | 24u);
		b[1] = (uint8_t)v;
		n = 2;
	} else if (v <= 0xffffu) {
		b[0] = (uint8_t)(mt | 25u);
		b[1] = (uint8_t)(v >> 8);
		b[2] = (uint8_t)v;
		n = 3;
	} else if (v <= 0xffffffffu) {
		b[0] = (uint8_t)(mt | 26u);
		for (size_t i = 0; i < 4; i++)
			b[1 + i] = (uint8_t)(v >> (24u - 8u * i));
		n = 5;
	} else {
		b[0] = (uint8_t)(mt | 27u);
		for (size_t i = 0; i < 8; i++)
			b[1 + i] = (uint8_t)(v >> (56u - 8u * i));
		n = 9;
	}
	put(w, b, n);
}

void tc_cbor_write_uint(tc_cbor_writer *w, uint64_t v)
{
	write_head(w, MT_UINT, v);
}

void tc_cbor_write_int(tc_cbor_writer *w, int64_t v)
{
	if (v >= 0) {
		write_head(w, MT_UINT, (uint64_t)v);
	} else {
		/* -1 - v, computed so that INT64_MIN does not overflow. */
		uint64_t n = (uint64_t)(-(v + 1));
		write_head(w, MT_NINT, n);
	}
}

void tc_cbor_write_bool(tc_cbor_writer *w, bool v)
{
	write_head(w, MT_SIMPLE, v ? TC_CBOR_TRUE : TC_CBOR_FALSE);
}

void tc_cbor_write_null(tc_cbor_writer *w)
{
	write_head(w, MT_SIMPLE, TC_CBOR_NULL);
}

void tc_cbor_write_bytes(tc_cbor_writer *w, const uint8_t *p, size_t n)
{
	write_head(w, MT_BYTES, (uint64_t)n);
	put(w, p, n);
}

void tc_cbor_write_text(tc_cbor_writer *w, const char *s, size_t n)
{
	write_head(w, MT_TEXT, (uint64_t)n);
	put(w, s, n);
}

void tc_cbor_write_array_header(tc_cbor_writer *w, uint64_t count)
{
	write_head(w, MT_ARRAY, count);
}

void tc_cbor_write_map_header(tc_cbor_writer *w, uint64_t pairs)
{
	write_head(w, MT_MAP, pairs);
}

int tc_cbor_writer_finish(const tc_cbor_writer *w, size_t *len)
{
	if (w->err != TC_OK)
		return w->err;
	if (len != NULL)
		*len = w->len;
	return TC_OK;
}
