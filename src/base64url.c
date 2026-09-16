/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Unpadded base64url, bug-compatible with Go's encoding/base64.RawURLEncoding.
 * See base64url.h for the two deliberate leniencies.
 */

#include "tc/base64url.h"

#include <string.h>

static const char kEnc[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* kDec maps a byte to its 6-bit value, or 0xff if it is not in the alphabet.
 * Built to mirror kEnc exactly; '-' is 62 and '_' is 63. */
static const uint8_t kDec[256] = {
	['A'] =  0, ['B'] =  1, ['C'] =  2, ['D'] =  3, ['E'] =  4, ['F'] =  5,
	['G'] =  6, ['H'] =  7, ['I'] =  8, ['J'] =  9, ['K'] = 10, ['L'] = 11,
	['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
	['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
	['Y'] = 24, ['Z'] = 25,
	['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
	['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
	['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
	['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
	['y'] = 50, ['z'] = 51,
	['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57,
	['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
	['-'] = 62, ['_'] = 63,
	/* Everything else defaults to 0, so we cannot use 0 as the sentinel.
	 * tc_dec6() special-cases the one character that legitimately maps to 0. */
};

/* tc_dec6 returns the 6-bit value of c, or -1 if c is not in the alphabet. */
static int tc_dec6(unsigned char c)
{
	if (c == 'A')
		return 0;
	uint8_t v = kDec[c];
	return v == 0 ? -1 : (int)v;
}

size_t tc_base64url_encoded_len(size_t n)
{
	return n / 3 * 4 + (n % 3 == 0 ? 0 : n % 3 + 1);
}

size_t tc_base64url_decoded_max(size_t n)
{
	return n / 4 * 3 + (n % 4 == 0 ? 0 : n % 4 - 1 > 2 ? 2 : n % 4 - 1);
}

int tc_base64url_encode(char *out, size_t cap, const uint8_t *in, size_t n,
                        size_t *out_len)
{
	if (out == NULL || (in == NULL && n != 0))
		return TC_ERR_INVAL;

	size_t need = tc_base64url_encoded_len(n);
	if (cap < need + 1)
		return TC_ERR_NOSPACE;

	size_t o = 0, i = 0;
	for (; n - i >= 3; i += 3) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 |
		             (uint32_t)in[i + 2];
		out[o++] = kEnc[v >> 18 & 0x3f];
		out[o++] = kEnc[v >> 12 & 0x3f];
		out[o++] = kEnc[v >> 6 & 0x3f];
		out[o++] = kEnc[v & 0x3f];
	}
	switch (n - i) {
	case 2: {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
		out[o++] = kEnc[v >> 18 & 0x3f];
		out[o++] = kEnc[v >> 12 & 0x3f];
		out[o++] = kEnc[v >> 6 & 0x3f];
		break;
	}
	case 1: {
		uint32_t v = (uint32_t)in[i] << 16;
		out[o++] = kEnc[v >> 18 & 0x3f];
		out[o++] = kEnc[v >> 12 & 0x3f];
		break;
	}
	default:
		break;
	}
	out[o] = '\0';
	if (out_len != NULL)
		*out_len = o;
	return TC_OK;
}

int tc_base64url_decode(uint8_t *out, size_t cap, const char *in, size_t n,
                        size_t *out_len)
{
	if ((out == NULL && cap != 0) || (in == NULL && n != 0))
		return TC_ERR_INVAL;

	uint32_t acc = 0;   /* accumulated bits, left-aligned in the low 24 */
	unsigned nbits = 0; /* how many of them are valid */
	size_t o = 0;

	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '\r' || c == '\n')
			continue; /* Go skips these; see the header comment. */
		int v = tc_dec6(c);
		if (v < 0)
			return TC_ERR_INVAL; /* includes '=', which Raw rejects */

		acc = acc << 6 | (uint32_t)v;
		nbits += 6;
		if (nbits >= 8) {
			nbits -= 8;
			if (o >= cap)
				return TC_ERR_NOSPACE;
			out[o++] = (uint8_t)(acc >> nbits & 0xff);
		}
	}
	/* A leftover of exactly 6 bits means the input had a trailing group of
	 * one character, which encodes nothing. Go rejects that as corrupt. */
	if (nbits == 6)
		return TC_ERR_INVAL;

	if (out_len != NULL)
		*out_len = o;
	return TC_OK;
}
