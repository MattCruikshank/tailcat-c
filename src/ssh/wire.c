/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4251 section 5 data types. See tc/sshwire.h for the reasoning.
 */

#include "tc/sshwire.h"

#include <string.h>

/* ---- writer ----------------------------------------------------------- */

void tc_ssh_wbuf_init(tc_ssh_wbuf *w, uint8_t *buf, size_t cap)
{
	if (w == NULL)
		return;
	w->buf = buf;
	w->cap = (buf == NULL) ? 0 : cap;
	w->len = 0;
	w->full = (buf == NULL && cap != 0);
}

bool tc_ssh_wbuf_ok(const tc_ssh_wbuf *w)
{
	return w != NULL && !w->full;
}

size_t tc_ssh_wbuf_len(const tc_ssh_wbuf *w)
{
	if (w == NULL || w->full)
		return 0;
	return w->len;
}

/* reserve returns where to write n bytes, or NULL having latched. The
 * subtraction rather than an addition is deliberate: cap - len cannot
 * overflow, and len + n could. */
static uint8_t *reserve(tc_ssh_wbuf *w, size_t n)
{
	if (w == NULL || w->full)
		return NULL;
	if (n > w->cap - w->len) {
		w->full = true;
		return NULL;
	}
	uint8_t *p = w->buf + w->len;
	w->len += n;
	return p;
}

void tc_ssh_put_byte(tc_ssh_wbuf *w, uint8_t v)
{
	uint8_t *p = reserve(w, 1);
	if (p != NULL)
		p[0] = v;
}

void tc_ssh_put_bool(tc_ssh_wbuf *w, bool v)
{
	/* RFC 4251: any non-zero byte is true, but senders must emit 1. */
	tc_ssh_put_byte(w, v ? 1u : 0u);
}

void tc_ssh_put_u32(tc_ssh_wbuf *w, uint32_t v)
{
	uint8_t *p = reserve(w, 4);
	if (p == NULL)
		return;
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

void tc_ssh_put_u64(tc_ssh_wbuf *w, uint64_t v)
{
	tc_ssh_put_u32(w, (uint32_t)(v >> 32));
	tc_ssh_put_u32(w, (uint32_t)v);
}

void tc_ssh_put_raw(tc_ssh_wbuf *w, const void *data, size_t len)
{
	if (len == 0)
		return;
	if (data == NULL) {
		if (w != NULL)
			w->full = true;
		return;
	}
	uint8_t *p = reserve(w, len);
	if (p != NULL)
		memcpy(p, data, len);
}

void tc_ssh_put_string(tc_ssh_wbuf *w, const void *data, size_t len)
{
	/* A length that does not fit in the uint32 the wire format uses is a
	 * caller error rather than something to truncate. */
	if (len > 0xffffffffu) {
		if (w != NULL)
			w->full = true;
		return;
	}
	tc_ssh_put_u32(w, (uint32_t)len);
	tc_ssh_put_raw(w, data, len);
}

void tc_ssh_put_cstring(tc_ssh_wbuf *w, const char *s)
{
	if (s == NULL) {
		if (w != NULL)
			w->full = true;
		return;
	}
	tc_ssh_put_string(w, s, strlen(s));
}

void tc_ssh_put_mpint(tc_ssh_wbuf *w, const uint8_t *be, size_t len)
{
	if (be == NULL && len != 0) {
		if (w != NULL)
			w->full = true;
		return;
	}

	/* Minimal form: drop leading zero bytes. Zero itself becomes empty. */
	size_t i = 0;
	while (i < len && be[i] == 0)
		i++;
	size_t n = len - i;
	if (n == 0) {
		tc_ssh_put_u32(w, 0);
		return;
	}

	/* The value is non-negative by contract, so a set top bit would read as
	 * negative in two's complement and needs a leading zero byte. */
	bool pad = (be[i] & 0x80u) != 0;
	tc_ssh_put_u32(w, (uint32_t)(n + (pad ? 1u : 0u)));
	if (pad)
		tc_ssh_put_byte(w, 0);
	tc_ssh_put_raw(w, be + i, n);
}

void tc_ssh_put_namelist(tc_ssh_wbuf *w, const char *const *names,
                         size_t count)
{
	if (w == NULL)
		return;
	if (names == NULL && count != 0) {
		w->full = true;
		return;
	}

	size_t total = 0;
	for (size_t i = 0; i < count; i++) {
		if (names[i] == NULL) {
			w->full = true;
			return;
		}
		for (const char *p = names[i]; *p != '\0'; p++) {
			/* A comma would split one name into two and anything outside
			 * printable US-ASCII is not a name RFC 4251 allows. Both are
			 * bugs here rather than input, since we only emit constants. */
			if (*p == ',' || (unsigned char)*p < 0x21u ||
			    (unsigned char)*p > 0x7eu) {
				w->full = true;
				return;
			}
			total++;
		}
	}
	if (count > 1)
		total += count - 1; /* the separators */

	tc_ssh_put_u32(w, (uint32_t)total);
	for (size_t i = 0; i < count; i++) {
		if (i > 0)
			tc_ssh_put_byte(w, ',');
		tc_ssh_put_raw(w, names[i], strlen(names[i]));
	}
}

/* ---- reader ----------------------------------------------------------- */

void tc_ssh_rbuf_init(tc_ssh_rbuf *r, const void *buf, size_t len)
{
	if (r == NULL)
		return;
	r->buf = (const uint8_t *)buf;
	r->len = (buf == NULL) ? 0 : len;
	r->off = 0;
	r->bad = (buf == NULL && len != 0);
}

bool tc_ssh_rbuf_ok(const tc_ssh_rbuf *r)
{
	return r != NULL && !r->bad;
}

size_t tc_ssh_rbuf_remaining(const tc_ssh_rbuf *r)
{
	if (r == NULL || r->bad)
		return 0;
	return r->len - r->off;
}

void tc_ssh_rbuf_fail(tc_ssh_rbuf *r)
{
	if (r != NULL)
		r->bad = true;
}

/* take returns a pointer to n bytes and advances, or NULL having latched. */
static const uint8_t *take(tc_ssh_rbuf *r, size_t n)
{
	if (r == NULL || r->bad)
		return NULL;
	if (n > r->len - r->off) {
		r->bad = true;
		return NULL;
	}
	const uint8_t *p = r->buf + r->off;
	r->off += n;
	return p;
}

uint8_t tc_ssh_get_byte(tc_ssh_rbuf *r)
{
	const uint8_t *p = take(r, 1);
	return (p == NULL) ? 0u : p[0];
}

bool tc_ssh_get_bool(tc_ssh_rbuf *r)
{
	/* RFC 4251: zero is false, every other value is true. */
	return tc_ssh_get_byte(r) != 0u;
}

uint32_t tc_ssh_get_u32(tc_ssh_rbuf *r)
{
	const uint8_t *p = take(r, 4);
	if (p == NULL)
		return 0u;
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

uint64_t tc_ssh_get_u64(tc_ssh_rbuf *r)
{
	uint64_t hi = tc_ssh_get_u32(r);
	uint64_t lo = tc_ssh_get_u32(r);
	return hi << 32 | lo;
}

const uint8_t *tc_ssh_get_raw(tc_ssh_rbuf *r, size_t len)
{
	if (len == 0)
		return (r != NULL && !r->bad) ? r->buf + r->off : NULL;
	return take(r, len);
}

const uint8_t *tc_ssh_get_string(tc_ssh_rbuf *r, size_t max, size_t *out_len)
{
	if (out_len != NULL)
		*out_len = 0;

	uint32_t n = tc_ssh_get_u32(r);
	if (r == NULL || r->bad)
		return NULL;

	/* Checked against what is left rather than against a constant, so a
	 * length field of 0xffffffff on a short packet is refused here and no
	 * later arithmetic ever sees it. */
	if ((size_t)n > r->len - r->off) {
		r->bad = true;
		return NULL;
	}
	if ((size_t)n > max) {
		r->bad = true;
		return NULL;
	}

	const uint8_t *p = r->buf + r->off;
	r->off += n;
	if (out_len != NULL)
		*out_len = n;
	return p;
}

bool tc_ssh_get_string_eq(tc_ssh_rbuf *r, const char *s)
{
	size_t n = 0;
	const uint8_t *p = tc_ssh_get_string(r, SIZE_MAX, &n);
	if (p == NULL || s == NULL)
		return false;
	size_t want = strlen(s);
	return n == want && (n == 0 || memcmp(p, s, n) == 0);
}

bool tc_ssh_get_cstring(tc_ssh_rbuf *r, char *out, size_t cap)
{
	if (out == NULL || cap == 0) {
		tc_ssh_rbuf_fail(r);
		return false;
	}
	out[0] = '\0';

	size_t n = 0;
	const uint8_t *p = tc_ssh_get_string(r, cap - 1, &n);
	if (p == NULL)
		return false;

	/* An embedded NUL would make this string mean one thing to us and
	 * another to anything that later treats it as a C string -- a filename,
	 * a user name. Refused rather than trimmed. */
	if (memchr(p, 0, n) != NULL) {
		tc_ssh_rbuf_fail(r);
		return false;
	}

	memcpy(out, p, n);
	out[n] = '\0';
	return true;
}

bool tc_ssh_get_mpint(tc_ssh_rbuf *r, uint8_t *out, size_t out_len)
{
	if (out == NULL || out_len == 0) {
		tc_ssh_rbuf_fail(r);
		return false;
	}
	memset(out, 0, out_len);

	size_t n = 0;
	const uint8_t *p = tc_ssh_get_string(r, SIZE_MAX, &n);
	if (p == NULL)
		return false;

	if (n == 0)
		return true; /* zero, and out is already zeroed */

	/* Negative values are refused outright: nothing in this subset has a use
	 * for one, so accepting it would only create a sign to lose track of. */
	if ((p[0] & 0x80u) != 0) {
		tc_ssh_rbuf_fail(r);
		return false;
	}

	/* Minimal form. A leading 0x00 is legal only to clear a high bit in the
	 * byte after it; any other leading zero is a second encoding of a value
	 * that already has one, and two encodings of one key is two
	 * fingerprints for one key. */
	if (n > 1 && p[0] == 0 && (p[1] & 0x80u) == 0) {
		tc_ssh_rbuf_fail(r);
		return false;
	}

	size_t i = (p[0] == 0) ? 1 : 0;
	size_t digits = n - i;
	if (digits > out_len) {
		tc_ssh_rbuf_fail(r);
		return false;
	}
	memcpy(out + (out_len - digits), p + i, digits);
	return true;
}

/* ---- name-lists ------------------------------------------------------- */

/* next_name walks a comma-separated list, returning each element in turn.
 * *off is the cursor; it ends at len when the list is exhausted. An empty
 * list (len 0) yields nothing, which is what RFC 4251 says it means. */
static bool next_name(const uint8_t *list, size_t len, size_t *off,
                      const uint8_t **name, size_t *name_len)
{
	if (*off >= len)
		return false;
	size_t start = *off;
	size_t i = start;
	while (i < len && list[i] != ',')
		i++;
	*name = list + start;
	*name_len = i - start;
	*off = (i < len) ? i + 1 : len;
	return true;
}

bool tc_ssh_namelist_has(const uint8_t *list, size_t len, const char *name)
{
	if (name == NULL || (list == NULL && len != 0))
		return false;
	size_t want = strlen(name);
	size_t off = 0;
	const uint8_t *n = NULL;
	size_t n_len = 0;
	while (next_name(list, len, &off, &n, &n_len))
		if (n_len == want && (want == 0 || memcmp(n, name, want) == 0))
			return true;
	return false;
}

int tc_ssh_namelist_first_supported(const uint8_t *peer, size_t peer_len,
                                    const char *const *ours, size_t count)
{
	if (ours == NULL || (peer == NULL && peer_len != 0))
		return -1;
	/* Our order decides, not the peer's -- see the header. */
	for (size_t i = 0; i < count; i++) {
		if (ours[i] == NULL)
			continue;
		if (tc_ssh_namelist_has(peer, peer_len, ours[i]))
			return (int)i;
	}
	return -1;
}
