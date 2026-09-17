/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A strict, allocation-free JSON reader (RFC 8259).
 *
 * Same discipline as src/cbor.c, and for the same reason: the DERP map is
 * fetched over the network from a host we do not control, so this parses
 * attacker-influenced bytes. It is a pull parser emitting one event at a
 * time, with an explicit depth stack rather than recursion, so nesting cannot
 * exhaust the stack.
 *
 * Deliberately narrow. It rejects:
 *
 *   - anything after the top-level value except whitespace;
 *   - trailing commas, comments, single quotes, unquoted keys;
 *   - control characters inside strings, which RFC 8259 forbids unescaped;
 *   - invalid escapes, lone surrogates, and malformed UTF-8;
 *   - nesting deeper than TC_JSON_MAX_DEPTH.
 *
 * Numbers are validated against the JSON grammar but only exposed as
 * integers. The DERP map's Latitude and Longitude are the only fractional
 * values in it and nothing reads them, so carrying a double through here
 * would add rounding behaviour and no capability. A non-integer number
 * parses fine and is reported with `is_integer` false.
 */
#ifndef TC_JSON_H_
#define TC_JSON_H_

#include "tc/tc.h"

#ifndef TC_JSON_MAX_DEPTH
#define TC_JSON_MAX_DEPTH 32
#endif

typedef enum {
	TC_JSON_END = 0, /* no more events: the document is complete */
	TC_JSON_OBJECT_BEGIN,
	TC_JSON_OBJECT_END,
	TC_JSON_ARRAY_BEGIN,
	TC_JSON_ARRAY_END,
	TC_JSON_KEY,    /* a member name; a value event follows */
	TC_JSON_STRING,
	TC_JSON_NUMBER,
	TC_JSON_BOOL,
	TC_JSON_NULL
} tc_json_type;

typedef struct {
	tc_json_type type;

	/* For KEY and STRING: the raw slice between the quotes, escapes not yet
	 * expanded. Use tc_json_string_copy to get the text. Points into the
	 * reader's buffer. */
	const char *str;
	size_t str_len;

	/* For NUMBER. A value that is not an integer, or does not fit an
	 * int64_t, sets is_integer false and leaves num undefined. */
	int64_t num;
	bool is_integer;

	/* For BOOL. */
	bool bval;
} tc_json_event;

typedef struct {
	const char *buf;
	size_t len;
	size_t pos;
	unsigned depth;
	/* One bit per level: true if that level is an object. Needed to know
	 * whether the next token is a member name or a value. */
	bool in_object[TC_JSON_MAX_DEPTH];
	/* Whether the current level has seen at least one member or element, so
	 * a comma is required before the next one and forbidden before the
	 * first. */
	bool seen[TC_JSON_MAX_DEPTH];
	bool expect_value; /* a KEY was just emitted */
	bool done;
} tc_json_reader;

void tc_json_reader_init(tc_json_reader *r, const char *buf, size_t len);

/* tc_json_next produces the next event. At the end of a well-formed document
 * it yields TC_JSON_END; calling again keeps yielding it. */
int tc_json_next(tc_json_reader *r, tc_json_event *out);

/* tc_json_skip_value consumes one complete value, including all members or
 * elements if it is an object or array.
 *
 * Call it immediately after a KEY to ignore that member, which is how a
 * parser stays compatible with a document that gains fields later. */
int tc_json_skip_value(tc_json_reader *r);

/* tc_json_string_copy expands the escapes in a KEY or STRING event into out
 * as a NUL-terminated string.
 *
 * Rejects an embedded NUL, since the result is used as a C string, and
 * rejects lone surrogates. \uXXXX pairs become UTF-8. */
int tc_json_string_copy(const tc_json_event *ev, char *out, size_t cap);

/* tc_json_key_is compares a KEY event against a literal, after expanding
 * escapes. Convenient and avoids a buffer at every call site. */
bool tc_json_key_is(const tc_json_event *ev, const char *name);

/* ---- writing ----------------------------------------------------------- */

/* tc_json_escape writes s into out as the *contents* of a JSON string --
 * escaped, NUL-terminated, without the surrounding quotes.
 *
 * `tailcat-c parse` prints JSON built from a tailcat address, and an address
 * is something a stranger hands you. The hostnames and region names inside
 * one are attacker-chosen strings going straight into a document someone is
 * about to pipe to jq. Quoting them by hand is how that goes wrong.
 *
 * The escaping deliberately matches Go's encoding/json byte for byte,
 * because the output is checked against the real `tailcat parse` and any
 * difference would be a test failure rather than a judgement call:
 *
 *   - `"` and `\` are backslash-escaped; newline, return and tab get their
 *     short forms; every other control byte becomes \u00XX.
 *   - `<`, `>` and `&` become <, > and &. Go escapes these by
 *     default so that JSON can be embedded in HTML without closing a tag.
 *   - U+2028 and U+2029 are escaped: they are line terminators to a
 *     JavaScript parser but not to a JSON one.
 *   - Invalid UTF-8 becomes �, one escape per bad byte, so the result
 *     is always a well-formed JSON string whatever the input was.
 *
 * Returns TC_ERR_NOSPACE if it does not fit, in which case out is
 * unspecified. Worst case is six bytes of output per input byte, plus the
 * NUL. */
int tc_json_escape(char *out, size_t cap, const char *s);

#endif /* TC_JSON_H_ */
