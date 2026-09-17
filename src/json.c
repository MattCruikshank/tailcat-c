/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See json.h for the scope and the strictness rules this implements.
 */

#include "tc/json.h"

#include <string.h>

void tc_json_reader_init(tc_json_reader *r, const char *buf, size_t len)
{
	memset(r, 0, sizeof *r);
	r->buf = buf;
	r->len = (buf == NULL) ? 0 : len;
}

static bool is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void skip_ws(tc_json_reader *r)
{
	while (r->pos < r->len && is_ws(r->buf[r->pos]))
		r->pos++;
}

static bool at_end(const tc_json_reader *r)
{
	return r->pos >= r->len;
}

static char peek(const tc_json_reader *r)
{
	return r->buf[r->pos];
}

/* ---- strings --------------------------------------------------------- */

static int hexnib(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* scan_string validates a string starting at the opening quote and reports
 * the slice between the quotes. Escapes are validated here but expanded only
 * by tc_json_string_copy, so an ignored member costs nothing. */
static int scan_string(tc_json_reader *r, const char **out, size_t *out_len)
{
	if (at_end(r) || peek(r) != '"')
		return TC_ERR_INVAL;
	r->pos++;

	size_t start = r->pos;
	while (!at_end(r)) {
		unsigned char c = (unsigned char)r->buf[r->pos];

		if (c == '"') {
			*out = r->buf + start;
			*out_len = r->pos - start;
			r->pos++;
			return TC_OK;
		}
		if (c < 0x20)
			return TC_ERR_INVAL; /* unescaped control character */

		if (c == '\\') {
			r->pos++;
			if (at_end(r))
				return TC_ERR_TRUNC;
			char e = r->buf[r->pos];
			switch (e) {
			case '"': case '\\': case '/': case 'b':
			case 'f': case 'n': case 'r': case 't':
				r->pos++;
				break;
			case 'u':
				if (r->len - r->pos < 5)
					return TC_ERR_TRUNC;
				for (size_t i = 1; i <= 4; i++)
					if (hexnib(r->buf[r->pos + i]) < 0)
						return TC_ERR_INVAL;
				r->pos += 5;
				break;
			default:
				return TC_ERR_INVAL;
			}
			continue;
		}

		/* Validate UTF-8 as we go, so a malformed name cannot reach a
		 * caller that will treat it as text. */
		size_t extra;
		if (c < 0x80u) {
			extra = 0;
		} else if ((c & 0xe0u) == 0xc0u) {
			extra = 1;
		} else if ((c & 0xf0u) == 0xe0u) {
			extra = 2;
		} else if ((c & 0xf8u) == 0xf0u) {
			extra = 3;
		} else {
			return TC_ERR_INVAL;
		}
		if (r->len - r->pos - 1 < extra)
			return TC_ERR_TRUNC;
		uint32_t cp = c & (uint32_t)(0xffu >> (extra + 2));
		if (extra == 0)
			cp = c;
		for (size_t k = 1; k <= extra; k++) {
			unsigned char cc = (unsigned char)r->buf[r->pos + k];
			if ((cc & 0xc0u) != 0x80u)
				return TC_ERR_INVAL;
			cp = cp << 6 | (cc & 0x3fu);
		}
		if (extra == 1 && cp < 0x80u)
			return TC_ERR_INVAL;
		if (extra == 2 && cp < 0x800u)
			return TC_ERR_INVAL;
		if (extra == 3 && cp < 0x10000u)
			return TC_ERR_INVAL;
		if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu))
			return TC_ERR_INVAL;

		r->pos += extra + 1;
	}
	return TC_ERR_TRUNC;
}

/* utf8_put writes a code point, returning how many bytes it took. */
static size_t utf8_put(char *out, uint32_t cp)
{
	if (cp < 0x80u) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800u) {
		out[0] = (char)(0xc0u | cp >> 6);
		out[1] = (char)(0x80u | (cp & 0x3fu));
		return 2;
	}
	if (cp < 0x10000u) {
		out[0] = (char)(0xe0u | cp >> 12);
		out[1] = (char)(0x80u | (cp >> 6 & 0x3fu));
		out[2] = (char)(0x80u | (cp & 0x3fu));
		return 3;
	}
	out[0] = (char)(0xf0u | cp >> 18);
	out[1] = (char)(0x80u | (cp >> 12 & 0x3fu));
	out[2] = (char)(0x80u | (cp >> 6 & 0x3fu));
	out[3] = (char)(0x80u | (cp & 0x3fu));
	return 4;
}

int tc_json_string_copy(const tc_json_event *ev, char *out, size_t cap)
{
	if (ev == NULL || out == NULL || cap == 0)
		return TC_ERR_INVAL;
	if (ev->type != TC_JSON_KEY && ev->type != TC_JSON_STRING)
		return TC_ERR_INVAL;

	size_t n = 0;
	for (size_t i = 0; i < ev->str_len;) {
		char c = ev->str[i];

		if (c != '\\') {
			if (c == '\0')
				return TC_ERR_INVAL;
			if (n + 1 >= cap)
				return TC_ERR_NOSPACE;
			out[n++] = c;
			i++;
			continue;
		}

		i++; /* the backslash; scan_string proved a valid escape follows */
		char e = ev->str[i++];
		char simple = 0;
		switch (e) {
		case '"':  simple = '"';  break;
		case '\\': simple = '\\'; break;
		case '/':  simple = '/';  break;
		case 'b':  simple = '\b'; break;
		case 'f':  simple = '\f'; break;
		case 'n':  simple = '\n'; break;
		case 'r':  simple = '\r'; break;
		case 't':  simple = '\t'; break;
		default:   break;
		}
		if (simple != 0 || e == '"' || e == '\\' || e == '/') {
			if (n + 1 >= cap)
				return TC_ERR_NOSPACE;
			out[n++] = simple;
			continue;
		}

		/* \uXXXX */
		uint32_t cp = 0;
		for (size_t k = 0; k < 4; k++)
			cp = cp << 4 | (uint32_t)hexnib(ev->str[i + k]);
		i += 4;

		if (cp >= 0xd800u && cp <= 0xdbffu) {
			/* A high surrogate must be followed by its low half. */
			if (i + 6 > ev->str_len || ev->str[i] != '\\' ||
			    ev->str[i + 1] != 'u')
				return TC_ERR_INVAL;
			uint32_t lo = 0;
			for (size_t k = 0; k < 4; k++) {
				int h = hexnib(ev->str[i + 2 + k]);
				if (h < 0)
					return TC_ERR_INVAL;
				lo = lo << 4 | (uint32_t)h;
			}
			if (lo < 0xdc00u || lo > 0xdfffu)
				return TC_ERR_INVAL;
			i += 6;
			cp = 0x10000u + ((cp - 0xd800u) << 10) + (lo - 0xdc00u);
		} else if (cp >= 0xdc00u && cp <= 0xdfffu) {
			return TC_ERR_INVAL; /* lone low surrogate */
		}
		if (cp == 0)
			return TC_ERR_INVAL; /* would truncate the C string */

		char tmp[4];
		size_t w = utf8_put(tmp, cp);
		if (n + w >= cap)
			return TC_ERR_NOSPACE;
		memcpy(out + n, tmp, w);
		n += w;
	}

	out[n] = '\0';
	return TC_OK;
}

bool tc_json_key_is(const tc_json_event *ev, const char *name)
{
	if (ev == NULL || name == NULL || ev->type != TC_JSON_KEY)
		return false;

	/* Fast path: no escapes means a direct comparison. */
	if (memchr(ev->str, '\\', ev->str_len) == NULL) {
		size_t n = strlen(name);
		return n == ev->str_len && memcmp(ev->str, name, n) == 0;
	}

	char buf[256];
	if (tc_json_string_copy(ev, buf, sizeof buf) != TC_OK)
		return false;
	return strcmp(buf, name) == 0;
}

/* ---- numbers --------------------------------------------------------- */

/* scan_number validates the JSON number grammar and reports an integer value
 * when the text is one that fits. */
static int scan_number(tc_json_reader *r, tc_json_event *ev)
{
	size_t start = r->pos;
	bool neg = false;

	if (!at_end(r) && peek(r) == '-') {
		neg = true;
		r->pos++;
	}
	if (at_end(r))
		return TC_ERR_TRUNC;

	/* An integer part is required, and a leading zero may not be followed by
	 * more digits. */
	if (peek(r) == '0') {
		r->pos++;
	} else if (peek(r) >= '1' && peek(r) <= '9') {
		while (!at_end(r) && peek(r) >= '0' && peek(r) <= '9')
			r->pos++;
	} else {
		return TC_ERR_INVAL;
	}

	bool integral = true;
	if (!at_end(r) && peek(r) == '.') {
		integral = false;
		r->pos++;
		if (at_end(r) || peek(r) < '0' || peek(r) > '9')
			return TC_ERR_INVAL;
		while (!at_end(r) && peek(r) >= '0' && peek(r) <= '9')
			r->pos++;
	}
	if (!at_end(r) && (peek(r) == 'e' || peek(r) == 'E')) {
		integral = false;
		r->pos++;
		if (!at_end(r) && (peek(r) == '+' || peek(r) == '-'))
			r->pos++;
		if (at_end(r) || peek(r) < '0' || peek(r) > '9')
			return TC_ERR_INVAL;
		while (!at_end(r) && peek(r) >= '0' && peek(r) <= '9')
			r->pos++;
	}

	ev->type = TC_JSON_NUMBER;
	ev->is_integer = false;
	ev->num = 0;

	if (integral) {
		/* Accumulate with an overflow check rather than strtoll, so a
		 * 40-digit number is reported as non-integer instead of saturating
		 * to something that looks plausible. */
		uint64_t mag = 0;
		bool overflow = false;
		for (size_t i = start + (neg ? 1u : 0u); i < r->pos; i++) {
			uint64_t d = (uint64_t)(r->buf[i] - '0');
			if (mag > (UINT64_MAX - d) / 10u) {
				overflow = true;
				break;
			}
			mag = mag * 10u + d;
		}
		uint64_t limit = neg ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
		if (!overflow && mag <= limit) {
			ev->is_integer = true;
			/* INT64_MAX+1 is the one magnitude only the negative side can
			 * hold, and it is exactly where the obvious -(int64_t)mag is
			 * undefined: the cast overflows before the negation runs. */
			if (!neg)
				ev->num = (int64_t)mag;
			else if (mag == (uint64_t)INT64_MAX + 1u)
				ev->num = INT64_MIN;
			else
				ev->num = -(int64_t)mag;
		}
	}
	return TC_OK;
}

/* ---- the event loop -------------------------------------------------- */

static int lit(tc_json_reader *r, const char *word)
{
	size_t n = strlen(word);
	if (r->len - r->pos < n || memcmp(r->buf + r->pos, word, n) != 0)
		return TC_ERR_INVAL;
	r->pos += n;
	return TC_OK;
}

/* read_value parses whatever value starts at the cursor. */
static int read_value(tc_json_reader *r, tc_json_event *ev)
{
	if (at_end(r))
		return TC_ERR_TRUNC;

	switch (peek(r)) {
	case '{':
	case '[': {
		bool obj = peek(r) == '{';
		if (r->depth >= TC_JSON_MAX_DEPTH)
			return TC_ERR_TOOMANY;
		r->pos++;
		r->in_object[r->depth] = obj;
		r->seen[r->depth] = false;
		r->depth++;
		ev->type = obj ? TC_JSON_OBJECT_BEGIN : TC_JSON_ARRAY_BEGIN;
		return TC_OK;
	}
	case '"':
		ev->type = TC_JSON_STRING;
		return scan_string(r, &ev->str, &ev->str_len);
	case 't':
		if (lit(r, "true") != TC_OK)
			return TC_ERR_INVAL;
		ev->type = TC_JSON_BOOL;
		ev->bval = true;
		return TC_OK;
	case 'f':
		if (lit(r, "false") != TC_OK)
			return TC_ERR_INVAL;
		ev->type = TC_JSON_BOOL;
		ev->bval = false;
		return TC_OK;
	case 'n':
		if (lit(r, "null") != TC_OK)
			return TC_ERR_INVAL;
		ev->type = TC_JSON_NULL;
		return TC_OK;
	default:
		return scan_number(r, ev);
	}
}

int tc_json_next(tc_json_reader *r, tc_json_event *out)
{
	if (r == NULL || out == NULL)
		return TC_ERR_INVAL;

	memset(out, 0, sizeof *out);

	if (r->done) {
		out->type = TC_JSON_END;
		return TC_OK;
	}

	skip_ws(r);

	/* At the top level, the document is one value and then nothing. */
	if (r->depth == 0) {
		if (r->seen[0]) {
			if (!at_end(r))
				return TC_ERR_INVAL; /* trailing garbage */
			r->done = true;
			out->type = TC_JSON_END;
			return TC_OK;
		}
		r->seen[0] = true;
		int rc = read_value(r, out);
		if (rc != TC_OK)
			return rc;
		if (r->depth == 0) {
			/* A bare scalar document: nothing may follow. */
			skip_ws(r);
			if (!at_end(r))
				return TC_ERR_INVAL;
			r->done = true;
		}
		return TC_OK;
	}

	unsigned lvl = r->depth - 1;
	bool obj = r->in_object[lvl];

	if (at_end(r))
		return TC_ERR_TRUNC;

	/* A closing bracket ends the level, but only if we are not midway
	 * through a member. */
	if ((obj && peek(r) == '}') || (!obj && peek(r) == ']')) {
		if (r->expect_value)
			return TC_ERR_INVAL; /* a key with no value */
		r->pos++;
		r->depth--;
		out->type = obj ? TC_JSON_OBJECT_END : TC_JSON_ARRAY_END;

		if (r->depth == 0) {
			skip_ws(r);
			if (!at_end(r))
				return TC_ERR_INVAL;
			r->done = true;
		} else {
			r->seen[r->depth - 1] = true;
		}
		return TC_OK;
	}

	if (r->expect_value) {
		r->expect_value = false;
		int rc = read_value(r, out);
		if (rc == TC_OK && out->type != TC_JSON_OBJECT_BEGIN &&
		    out->type != TC_JSON_ARRAY_BEGIN)
			r->seen[lvl] = true;
		return rc;
	}

	/* Between elements: a comma is required after the first, and forbidden
	 * before it. That rejects both `[1 2]` and `[,1]` and `[1,]`. */
	if (r->seen[lvl]) {
		if (peek(r) != ',')
			return TC_ERR_INVAL;
		r->pos++;
		skip_ws(r);
		if (at_end(r))
			return TC_ERR_TRUNC;
		if ((obj && peek(r) == '}') || (!obj && peek(r) == ']'))
			return TC_ERR_INVAL; /* trailing comma */
	}

	if (obj) {
		int rc = scan_string(r, &out->str, &out->str_len);
		if (rc != TC_OK)
			return rc;
		skip_ws(r);
		if (at_end(r))
			return TC_ERR_TRUNC;
		if (peek(r) != ':')
			return TC_ERR_INVAL;
		r->pos++;
		out->type = TC_JSON_KEY;
		r->expect_value = true;
		return TC_OK;
	}

	int rc = read_value(r, out);
	if (rc == TC_OK && out->type != TC_JSON_OBJECT_BEGIN &&
	    out->type != TC_JSON_ARRAY_BEGIN)
		r->seen[lvl] = true;
	return rc;
}

int tc_json_skip_value(tc_json_reader *r)
{
	tc_json_event ev;
	int rc = tc_json_next(r, &ev);
	if (rc != TC_OK)
		return rc;

	if (ev.type != TC_JSON_OBJECT_BEGIN && ev.type != TC_JSON_ARRAY_BEGIN)
		return TC_OK;

	/* Iterative, matching the reader's own discipline: the depth at entry is
	 * the floor, and we read until we come back to it. */
	unsigned target = r->depth - 1;
	while (r->depth > target) {
		rc = tc_json_next(r, &ev);
		if (rc != TC_OK)
			return rc;
		if (ev.type == TC_JSON_END)
			return TC_ERR_TRUNC;
	}
	return TC_OK;
}

/* ---- writing ----------------------------------------------------------- */

static const char hexdig[] = "0123456789abcdef";

/* utf8_len decodes one UTF-8 sequence at p, returning its length in bytes and
 * storing the code point, or 0 if the bytes are not valid UTF-8.
 *
 * Strict on purpose: overlong encodings, surrogates and anything above
 * U+10FFFF are rejected, because each of those is a way to smuggle a
 * character past a check that decoded more leniently than the next reader
 * does. */
static size_t utf8_len(const unsigned char *p, size_t avail, uint32_t *cp)
{
	if (avail == 0)
		return 0;
	unsigned char c = p[0];
	size_t n;
	uint32_t v;

	if (c < 0x80u) {
		*cp = c;
		return 1;
	} else if ((c & 0xe0u) == 0xc0u) {
		n = 2;
		v = c & 0x1fu;
	} else if ((c & 0xf0u) == 0xe0u) {
		n = 3;
		v = c & 0x0fu;
	} else if ((c & 0xf8u) == 0xf0u) {
		n = 4;
		v = c & 0x07u;
	} else {
		return 0;
	}
	if (avail < n)
		return 0;
	for (size_t i = 1; i < n; i++) {
		if ((p[i] & 0xc0u) != 0x80u)
			return 0;
		v = (v << 6) | (uint32_t)(p[i] & 0x3fu);
	}
	/* Overlong, surrogate, or out of range. */
	if ((n == 2 && v < 0x80u) || (n == 3 && v < 0x800u) ||
	    (n == 4 && v < 0x10000u))
		return 0;
	if (v >= 0xd800u && v <= 0xdfffu)
		return 0;
	if (v > 0x10ffffu)
		return 0;
	*cp = v;
	return n;
}

int tc_json_escape(char *out, size_t cap, const char *s)
{
	size_t w = 0;

	if (out == NULL || cap == 0 || s == NULL)
		return TC_ERR_INVAL;

#define PUT(ch)                                                               \
	do {                                                                      \
		if (w + 1 >= cap)                                                     \
			return TC_ERR_NOSPACE;                                            \
		out[w++] = (ch);                                                      \
	} while (0)
#define PUT2(a, b)                                                            \
	do {                                                                      \
		PUT(a);                                                               \
		PUT(b);                                                               \
	} while (0)

	const unsigned char *p = (const unsigned char *)s;
	size_t len = strlen(s);
	for (size_t i = 0; i < len;) {
		unsigned char c = p[i];

		if (c < 0x80u) {
			i++;
			switch (c) {
			case '"':
				PUT2('\\', '"');
				continue;
			case '\\':
				PUT2('\\', '\\');
				continue;
			case '\n':
				PUT2('\\', 'n');
				continue;
			case '\r':
				PUT2('\\', 'r');
				continue;
			case '\t':
				PUT2('\\', 't');
				continue;
			default:
				break;
			}
			/* Go escapes these three by default so that the result can sit
			 * inside a <script> without ending it. */
			if (c >= 0x20u && c != '<' && c != '>' && c != '&') {
				PUT((char)c);
				continue;
			}
			PUT2('\\', 'u');
			PUT2('0', '0');
			PUT2(hexdig[(c >> 4) & 0xfu], hexdig[c & 0xfu]);
			continue;
		}

		uint32_t cp = 0;
		size_t n = utf8_len(p + i, len - i, &cp);
		if (n == 0) {
			/* One replacement per bad byte, as Go does, so the output stays
			 * a valid JSON string no matter what arrived. */
			PUT2('\\', 'u');
			PUT2('f', 'f');
			PUT2('f', 'd');
			i++;
			continue;
		}
		if (cp == 0x2028u || cp == 0x2029u) {
			PUT2('\\', 'u');
			PUT2('2', '0');
			PUT2('2', hexdig[cp & 0xfu]);
			i += n;
			continue;
		}
		for (size_t k = 0; k < n; k++)
			PUT((char)p[i + k]);
		i += n;
	}

#undef PUT
#undef PUT2
	out[w] = '\0';
	return TC_OK;
}
