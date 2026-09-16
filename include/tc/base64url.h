/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Unpadded base64url, matching Go's encoding/base64.RawURLEncoding, which is
 * what tailcat addresses use.
 */
#ifndef TC_BASE64URL_H_
#define TC_BASE64URL_H_

#include "tc/tc.h"

/* tc_base64url_encoded_len returns the number of characters
 * tc_base64url_encode writes for n input bytes, excluding the NUL. */
size_t tc_base64url_encoded_len(size_t n);

/* tc_base64url_decoded_max returns an upper bound on the number of bytes
 * tc_base64url_decode can write for n input characters. */
size_t tc_base64url_decoded_max(size_t n);

/* tc_base64url_encode writes the unpadded base64url form of in[0:n] to out,
 * NUL-terminating it. cap is the size of out including room for the NUL.
 * On success *out_len, if non-NULL, gets the length excluding the NUL. */
int tc_base64url_encode(char *out, size_t cap, const uint8_t *in, size_t n,
                        size_t *out_len);

/* tc_base64url_decode decodes in[0:n] into out, writing at most cap bytes and
 * storing the count in *out_len.
 *
 * Like Go's decoder this skips '\r' and '\n' anywhere in the input, so an
 * address that got line-wrapped in transit still parses. Unlike a strict
 * decoder it does not reject a final quantum whose unused low bits are
 * non-zero; Go accepts those too, and rejecting them would make us refuse
 * addresses real tailcat emits. Padding ('=') is rejected: this is the Raw
 * encoding. */
int tc_base64url_decode(uint8_t *out, size_t cap, const char *in, size_t n,
                        size_t *out_len);

#endif /* TC_BASE64URL_H_ */
