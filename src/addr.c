/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See addr.h for the wire format and the elision rules this mirrors.
 */

#include "tc/addr.h"

#include "tc/base64url.h"
#include "tc/cbor.h"

#include <stdio.h>
#include <string.h>

#define ADDR_PREFIX "tc"
#define ADDR_PREFIX_LEN (sizeof ADDR_PREFIX - 1)

/* ---- parsing --------------------------------------------------------- */

/* key_of returns the single-character CBOR key of the item the reader is
 * positioned on, or 0 if it is not a one-character text string. Unknown keys
 * are skipped rather than rejected, so an address written by a newer tailcat
 * that added a field still parses here. */
static int read_key(tc_cbor_reader *r, char *out)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;
	if (it.type != TC_CBOR_TEXT)
		return TC_ERR_INVAL;
	*out = (it.data_len == 1) ? (char)it.data[0] : 0;
	return TC_OK;
}

/* A CBOR null where a struct was expected must be rejected rather than
 * treated as an empty struct: addresses come from untrusted places and Go's
 * ParseAddr rejects null regions and nodes explicitly. */
static int expect_map(tc_cbor_reader *r, uint64_t *pairs)
{
	tc_cbor_item it;
	int rc = tc_cbor_read(r, &it);
	if (rc != TC_OK)
		return rc;
	if (it.type != TC_CBOR_MAP)
		return TC_ERR_INVAL;
	*pairs = it.val;
	return TC_OK;
}

/* read_port reads an integer and range-checks it as a TCP/UDP port. Go stores
 * these as int and does not validate, but an out-of-range port here can only
 * come from a malformed address. */
static int read_port(tc_cbor_reader *r, int32_t *out)
{
	int64_t v = 0;
	int rc = tc_cbor_read_int(r, &v);
	if (rc != TC_OK)
		return rc;
	/* DERPPort/STUNPort use -1 to mean "disabled" in tailcfg. */
	if (v < -1 || v > 65535)
		return TC_ERR_RANGE;
	*out = (int32_t)v;
	return TC_OK;
}

static int parse_node(tc_cbor_reader *r, tc_derp_node *n)
{
	uint64_t pairs = 0;
	int rc = expect_map(r, &pairs);
	if (rc != TC_OK)
		return rc;

	memset(n, 0, sizeof *n);

	for (uint64_t i = 0; i < pairs; i++) {
		char k = 0;
		rc = read_key(r, &k);
		if (rc != TC_OK)
			return rc;

		switch (k) {
		case 'n':
			rc = tc_cbor_read_text(r, n->name, sizeof n->name);
			break;
		case 'i':
			rc = tc_cbor_read_int(r, &n->region_id);
			break;
		case 'h':
			rc = tc_cbor_read_text(r, n->hostname, sizeof n->hostname);
			break;
		case 't':
			rc = tc_cbor_read_text(r, n->cert_name, sizeof n->cert_name);
			break;
		case '4':
			rc = tc_cbor_read_text(r, n->ipv4, sizeof n->ipv4);
			break;
		case '6':
			rc = tc_cbor_read_text(r, n->ipv6, sizeof n->ipv6);
			break;
		case 's':
			rc = read_port(r, &n->stun_port);
			break;
		case 'd':
			rc = read_port(r, &n->derp_port);
			break;
		case 'x':
			rc = tc_cbor_read_bool(r, &n->insecure_for_tests);
			break;
		default:
			rc = tc_cbor_skip(r);
			break;
		}
		if (rc != TC_OK)
			return rc;
	}
	return TC_OK;
}

static int parse_region(tc_cbor_reader *r, tc_derp_region *reg)
{
	uint64_t pairs = 0;
	int rc = expect_map(r, &pairs);
	if (rc != TC_OK)
		return rc;

	memset(reg, 0, sizeof *reg);

	for (uint64_t i = 0; i < pairs; i++) {
		char k = 0;
		rc = read_key(r, &k);
		if (rc != TC_OK)
			return rc;

		switch (k) {
		case 'i':
			rc = tc_cbor_read_int(r, &reg->region_id);
			break;
		case 'c':
			rc = tc_cbor_read_text(r, reg->region_code,
			                       sizeof reg->region_code);
			break;
		case 'm':
			rc = tc_cbor_read_text(r, reg->region_name,
			                       sizeof reg->region_name);
			break;
		case 'N': {
			tc_cbor_item it;
			rc = tc_cbor_read(r, &it);
			if (rc != TC_OK)
				break;
			if (it.type != TC_CBOR_ARRAY) {
				rc = TC_ERR_INVAL;
				break;
			}
			if (it.val > (uint64_t)TC_ADDR_MAX_NODES) {
				rc = TC_ERR_TOOMANY;
				break;
			}
			reg->num_nodes = (size_t)it.val;
			for (size_t j = 0; j < reg->num_nodes; j++) {
				rc = parse_node(r, &reg->nodes[j]);
				if (rc != TC_OK)
					break;
			}
			break;
		}
		default:
			rc = tc_cbor_skip(r);
			break;
		}
		if (rc != TC_OK)
			return rc;
	}
	return TC_OK;
}

/* restore_elided fills in the fields ConnInfo.Addr drops before encoding.
 * Kept in one place so it is obvious this is the exact inverse of elide(). */
static void restore_elided(tc_conn_info *ci)
{
	for (size_t ri = 0; ri < ci->num_regions; ri++) {
		tc_derp_region *reg = &ci->regions[ri];

		if (reg->region_id == 0)
			reg->region_id = (int64_t)ri + 1;

		if (reg->region_code[0] == 0) {
			/* Go uses fmt.Sprint(RegionID); snprintf truncates rather than
			 * overflowing, and an int64 always fits in this buffer. */
			(void)snprintf(reg->region_code, sizeof reg->region_code,
			               "%lld", (long long)reg->region_id);
		}

		for (size_t ni = 0; ni < reg->num_nodes; ni++) {
			tc_derp_node *n = &reg->nodes[ni];
			if (n->name[0] == 0) {
				/* netcheck identifies nodes by name, so every node needs a
				 * distinct one; the hostname supplies it. */
				memcpy(n->name, n->hostname, sizeof n->name);
			}
			if (n->region_id == 0)
				n->region_id = reg->region_id;
		}
	}
}

int tc_addr_parse(tc_conn_info *out, const char *addr, size_t addr_len)
{
	if (out == NULL || (addr == NULL && addr_len != 0))
		return TC_ERR_INVAL;

	if (addr_len < ADDR_PREFIX_LEN ||
	    memcmp(addr, ADDR_PREFIX, ADDR_PREFIX_LEN) != 0)
		return TC_ERR_INVAL;

	const char *b64 = addr + ADDR_PREFIX_LEN;
	size_t b64_len = addr_len - ADDR_PREFIX_LEN;

	if (tc_base64url_decoded_max(b64_len) > TC_ADDR_CBOR_MAX)
		return TC_ERR_TOOMANY;

	uint8_t cbor[TC_ADDR_CBOR_MAX];
	size_t cbor_len = 0;
	int rc = tc_base64url_decode(cbor, sizeof cbor, b64, b64_len, &cbor_len);
	if (rc != TC_OK)
		return rc;

	tc_cbor_reader r;
	tc_cbor_reader_init(&r, cbor, cbor_len);

	uint64_t pairs = 0;
	rc = expect_map(&r, &pairs);
	if (rc != TC_OK)
		return rc;

	memset(out, 0, sizeof *out);
	bool saw_server_public = false;

	for (uint64_t i = 0; i < pairs; i++) {
		char k = 0;
		rc = read_key(&r, &k);
		if (rc != TC_OK)
			return rc;

		switch (k) {
		case 'p':
			rc = tc_cbor_read_bytes_exact(&r, out->server_public,
			                              sizeof out->server_public);
			saw_server_public = (rc == TC_OK);
			break;
		case 'k':
			rc = tc_cbor_read_bytes_exact(&r, out->server_disco_public,
			                              sizeof out->server_disco_public);
			out->has_disco_public = (rc == TC_OK);
			break;
		case 'q':
			rc = tc_cbor_read_bytes_exact(&r, out->preshared_key,
			                              sizeof out->preshared_key);
			out->has_preshared_key = (rc == TC_OK);
			break;
		case 'i':
			rc = tc_cbor_read_int(&r, &out->region_id);
			break;
		case 'r': {
			tc_cbor_item it;
			rc = tc_cbor_read(&r, &it);
			if (rc != TC_OK)
				break;
			if (it.type != TC_CBOR_ARRAY) {
				rc = TC_ERR_INVAL;
				break;
			}
			if (it.val > (uint64_t)TC_ADDR_MAX_REGIONS) {
				rc = TC_ERR_TOOMANY;
				break;
			}
			out->num_regions = (size_t)it.val;
			for (size_t j = 0; j < out->num_regions; j++) {
				rc = parse_region(&r, &out->regions[j]);
				if (rc != TC_OK)
					break;
			}
			break;
		}
		default:
			rc = tc_cbor_skip(&r);
			break;
		}
		if (rc != TC_OK) {
			tc_memzero_explicit(out, sizeof *out);
			return rc;
		}
	}

	/* The server's WireGuard public key is the one field with no default:
	 * without it the address names nobody. */
	if (!saw_server_public) {
		tc_memzero_explicit(out, sizeof *out);
		return TC_ERR_INVAL;
	}

	/* Trailing bytes mean the address is not what it claims to be. */
	if (tc_cbor_remaining(&r) != 0) {
		tc_memzero_explicit(out, sizeof *out);
		return TC_ERR_INVAL;
	}

	restore_elided(out);
	tc_memzero_explicit(cbor, sizeof cbor);
	return TC_OK;
}

/* ---- encoding -------------------------------------------------------- */

/* Field presence mirrors Go's `omitempty`: zero numbers, empty strings,
 * false booleans and absent optionals are left out of the map entirely, and
 * the map header counts only what is written. */
static uint64_t node_pair_count(const tc_derp_node *n, const char *name)
{
	uint64_t c = 0;
	if (name[0] != 0)
		c++; /* n */
	if (n->hostname[0] != 0)
		c++; /* h */
	if (n->cert_name[0] != 0)
		c++; /* t */
	if (n->ipv4[0] != 0)
		c++; /* 4 */
	if (n->ipv6[0] != 0)
		c++; /* 6 */
	if (n->stun_port != 0)
		c++; /* s */
	if (n->derp_port != 0)
		c++; /* d */
	if (n->insecure_for_tests)
		c++; /* x */
	return c;
}

static void write_text_field(tc_cbor_writer *w, char key, const char *s)
{
	if (s[0] == 0)
		return;
	tc_cbor_write_text(w, &key, 1);
	tc_cbor_write_text(w, s, strlen(s));
}

static void encode_node(tc_cbor_writer *w, const tc_derp_node *n)
{
	/* The encoder drops a node's region ID entirely, and drops its name
	 * whenever it has a hostname (the name is re-derived on parse). */
	const char *name = (n->hostname[0] != 0) ? "" : n->name;

	tc_cbor_write_map_header(w, node_pair_count(n, name));

	write_text_field(w, 'n', name);
	write_text_field(w, 'h', n->hostname);
	write_text_field(w, 't', n->cert_name);
	write_text_field(w, '4', n->ipv4);
	write_text_field(w, '6', n->ipv6);
	if (n->stun_port != 0) {
		tc_cbor_write_text(w, "s", 1);
		tc_cbor_write_int(w, n->stun_port);
	}
	if (n->derp_port != 0) {
		tc_cbor_write_text(w, "d", 1);
		tc_cbor_write_int(w, n->derp_port);
	}
	if (n->insecure_for_tests) {
		tc_cbor_write_text(w, "x", 1);
		tc_cbor_write_bool(w, true);
	}
}

static void encode_region(tc_cbor_writer *w, const tc_derp_region *reg)
{
	/* Region ID, code and name are all elided by the encoder; only the node
	 * list survives, so the map has either zero or one pair. */
	uint64_t pairs = (reg->num_nodes != 0) ? 1u : 0u;
	tc_cbor_write_map_header(w, pairs);

	if (reg->num_nodes != 0) {
		tc_cbor_write_text(w, "N", 1);
		tc_cbor_write_array_header(w, reg->num_nodes);
		for (size_t i = 0; i < reg->num_nodes; i++)
			encode_node(w, &reg->nodes[i]);
	}
}

int tc_addr_encode(char *out, size_t cap, const tc_conn_info *ci,
                   size_t *out_len)
{
	if (out == NULL || ci == NULL)
		return TC_ERR_INVAL;
	if (ci->num_regions > TC_ADDR_MAX_REGIONS)
		return TC_ERR_TOOMANY;

	uint8_t cbor[TC_ADDR_CBOR_MAX];
	tc_cbor_writer w;
	tc_cbor_writer_init(&w, cbor, sizeof cbor);

	uint64_t pairs = 1; /* p is always written */
	if (ci->has_disco_public)
		pairs++;
	if (ci->has_preshared_key)
		pairs++;
	if (ci->num_regions != 0)
		pairs++;
	if (ci->region_id != 0)
		pairs++;

	/* Field order matches the Go struct's declaration order, which is the
	 * order fxamacker/cbor emits with its default options. Keeping it makes
	 * a parse/encode round trip byte-identical. */
	tc_cbor_write_map_header(&w, pairs);

	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, ci->server_public, sizeof ci->server_public);

	if (ci->has_disco_public) {
		tc_cbor_write_text(&w, "k", 1);
		tc_cbor_write_bytes(&w, ci->server_disco_public,
		                    sizeof ci->server_disco_public);
	}
	if (ci->has_preshared_key) {
		tc_cbor_write_text(&w, "q", 1);
		tc_cbor_write_bytes(&w, ci->preshared_key, sizeof ci->preshared_key);
	}
	if (ci->num_regions != 0) {
		tc_cbor_write_text(&w, "r", 1);
		tc_cbor_write_array_header(&w, ci->num_regions);
		for (size_t i = 0; i < ci->num_regions; i++)
			encode_region(&w, &ci->regions[i]);
	}
	if (ci->region_id != 0) {
		tc_cbor_write_text(&w, "i", 1);
		tc_cbor_write_int(&w, ci->region_id);
	}

	size_t cbor_len = 0;
	int rc = tc_cbor_writer_finish(&w, &cbor_len);
	if (rc != TC_OK) {
		tc_memzero_explicit(cbor, sizeof cbor);
		return rc;
	}

	size_t need = ADDR_PREFIX_LEN + tc_base64url_encoded_len(cbor_len);
	if (cap < need + 1) {
		tc_memzero_explicit(cbor, sizeof cbor);
		return TC_ERR_NOSPACE;
	}

	memcpy(out, ADDR_PREFIX, ADDR_PREFIX_LEN);
	size_t b64_len = 0;
	rc = tc_base64url_encode(out + ADDR_PREFIX_LEN, cap - ADDR_PREFIX_LEN,
	                         cbor, cbor_len, &b64_len);
	tc_memzero_explicit(cbor, sizeof cbor);
	if (rc != TC_OK)
		return rc;

	if (out_len != NULL)
		*out_len = ADDR_PREFIX_LEN + b64_len;
	return TC_OK;
}
