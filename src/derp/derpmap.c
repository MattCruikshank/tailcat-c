/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See derpmap.h. Fetch, parse, cache, and pick a region.
 */

#include "tc/derpmap.h"

#include "tc/crypto.h"
#include "tc/derp.h"
#include "tc/http.h"
#include "tc/json.h"
#include "tc/noise.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static _Thread_local char g_err[256];

const char *tc_derpmap_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

/* ---- parsing --------------------------------------------------------- */

/* read_int accepts a JSON integer, or a string holding one. The map uses
 * numbers, but region keys are strings and being lenient here costs nothing. */
static int read_int(tc_json_reader *r, int64_t *out)
{
	tc_json_event ev;
	int rc = tc_json_next(r, &ev);
	if (rc != TC_OK)
		return rc;
	if (ev.type == TC_JSON_NUMBER) {
		if (!ev.is_integer)
			return TC_ERR_RANGE;
		*out = ev.num;
		return TC_OK;
	}
	if (ev.type == TC_JSON_STRING) {
		char buf[32];
		if (tc_json_string_copy(&ev, buf, sizeof buf) != TC_OK)
			return TC_ERR_INVAL;
		char *end = NULL;
		long long v = strtoll(buf, &end, 10);
		if (end == buf || *end != '\0')
			return TC_ERR_INVAL;
		*out = (int64_t)v;
		return TC_OK;
	}
	return TC_ERR_INVAL;
}

static int read_str(tc_json_reader *r, char *out, size_t cap)
{
	tc_json_event ev;
	int rc = tc_json_next(r, &ev);
	if (rc != TC_OK)
		return rc;
	if (ev.type != TC_JSON_STRING)
		return TC_ERR_INVAL;
	return tc_json_string_copy(&ev, out, cap);
}

/* read_port reads a port, range-checked. */
static int read_port(tc_json_reader *r, int32_t *out)
{
	int64_t v = 0;
	int rc = read_int(r, &v);
	if (rc != TC_OK)
		return rc;
	if (v < -1 || v > 65535)
		return TC_ERR_RANGE;
	*out = (int32_t)v;
	return TC_OK;
}

/* parse_node reads one entry of a region's Nodes array. `keep` false means
 * the node is beyond our limits and should be consumed but discarded. */
static int parse_node(tc_json_reader *r, tc_derp_node *n, bool keep)
{
	tc_json_event ev;
	int rc = tc_json_next(r, &ev);
	if (rc != TC_OK)
		return rc;
	if (ev.type != TC_JSON_OBJECT_BEGIN)
		return TC_ERR_INVAL;

	tc_derp_node scratch;
	if (!keep)
		n = &scratch;
	memset(n, 0, sizeof *n);

	for (;;) {
		rc = tc_json_next(r, &ev);
		if (rc != TC_OK)
			return rc;
		if (ev.type == TC_JSON_OBJECT_END)
			return TC_OK;
		if (ev.type != TC_JSON_KEY)
			return TC_ERR_INVAL;

		if (tc_json_key_is(&ev, "Name"))
			rc = read_str(r, n->name, sizeof n->name);
		else if (tc_json_key_is(&ev, "HostName"))
			rc = read_str(r, n->hostname, sizeof n->hostname);
		else if (tc_json_key_is(&ev, "CertName"))
			rc = read_str(r, n->cert_name, sizeof n->cert_name);
		else if (tc_json_key_is(&ev, "IPv4"))
			rc = read_str(r, n->ipv4, sizeof n->ipv4);
		else if (tc_json_key_is(&ev, "IPv6"))
			rc = read_str(r, n->ipv6, sizeof n->ipv6);
		else if (tc_json_key_is(&ev, "STUNPort"))
			rc = read_port(r, &n->stun_port);
		else if (tc_json_key_is(&ev, "DERPPort"))
			rc = read_port(r, &n->derp_port);
		else if (tc_json_key_is(&ev, "RegionID"))
			rc = read_int(r, &n->region_id);
		else
			rc = tc_json_skip_value(r); /* CanPort80, STUNOnly, anything new */

		if (rc != TC_OK)
			return rc;
	}
}

static int parse_region(tc_json_reader *r, tc_derp_region *reg, bool keep)
{
	tc_json_event ev;
	int rc = tc_json_next(r, &ev);
	if (rc != TC_OK)
		return rc;
	if (ev.type != TC_JSON_OBJECT_BEGIN)
		return TC_ERR_INVAL;

	static tc_derp_region scratch; /* too big for a stack frame */
	if (!keep)
		reg = &scratch;
	memset(reg, 0, sizeof *reg);

	for (;;) {
		rc = tc_json_next(r, &ev);
		if (rc != TC_OK)
			return rc;
		if (ev.type == TC_JSON_OBJECT_END)
			return TC_OK;
		if (ev.type != TC_JSON_KEY)
			return TC_ERR_INVAL;

		if (tc_json_key_is(&ev, "RegionID")) {
			rc = read_int(r, &reg->region_id);
		} else if (tc_json_key_is(&ev, "RegionCode")) {
			rc = read_str(r, reg->region_code, sizeof reg->region_code);
		} else if (tc_json_key_is(&ev, "RegionName")) {
			rc = read_str(r, reg->region_name, sizeof reg->region_name);
		} else if (tc_json_key_is(&ev, "Nodes")) {
			rc = tc_json_next(r, &ev);
			if (rc != TC_OK)
				return rc;
			if (ev.type == TC_JSON_NULL)
				continue; /* a region with no relays */
			if (ev.type != TC_JSON_ARRAY_BEGIN)
				return TC_ERR_INVAL;
			for (;;) {
				tc_json_event peeked;
				tc_json_reader save = *r;
				rc = tc_json_next(r, &peeked);
				if (rc != TC_OK)
					return rc;
				if (peeked.type == TC_JSON_ARRAY_END)
					break;
				*r = save; /* put the element back for parse_node */

				bool keep_node = reg->num_nodes < TC_ADDR_MAX_NODES;
				rc = parse_node(r, &reg->nodes[keep_node ? reg->num_nodes : 0],
				                keep_node);
				if (rc != TC_OK)
					return rc;
				if (keep_node)
					reg->num_nodes++;
			}
			rc = TC_OK;
		} else {
			/* Latitude, Longitude, and whatever gets added later. */
			rc = tc_json_skip_value(r);
		}
		if (rc != TC_OK)
			return rc;
	}
}

int tc_derpmap_parse(tc_derp_map *out, const char *json, size_t len)
{
	if (out == NULL || json == NULL)
		return TC_ERR_INVAL;

	memset(out, 0, sizeof *out);
	g_err[0] = '\0';

	tc_json_reader r;
	tc_json_event ev;
	tc_json_reader_init(&r, json, len);

	int rc = tc_json_next(&r, &ev);
	if (rc != TC_OK || ev.type != TC_JSON_OBJECT_BEGIN) {
		FAILF("the DERP map is not a JSON object");
		return TC_ERR_INVAL;
	}

	bool saw_regions = false;
	for (;;) {
		rc = tc_json_next(&r, &ev);
		if (rc != TC_OK) {
			FAILF("malformed DERP map: %s", tc_strerror(rc));
			return rc;
		}
		if (ev.type == TC_JSON_OBJECT_END)
			break;
		if (ev.type != TC_JSON_KEY)
			return TC_ERR_INVAL;

		if (!tc_json_key_is(&ev, "Regions")) {
			rc = tc_json_skip_value(&r);
			if (rc != TC_OK)
				return rc;
			continue;
		}
		saw_regions = true;

		rc = tc_json_next(&r, &ev);
		if (rc != TC_OK)
			return rc;
		if (ev.type != TC_JSON_OBJECT_BEGIN) {
			FAILF("Regions is not an object");
			return TC_ERR_INVAL;
		}

		for (;;) {
			rc = tc_json_next(&r, &ev);
			if (rc != TC_OK)
				return rc;
			if (ev.type == TC_JSON_OBJECT_END)
				break;
			if (ev.type != TC_JSON_KEY)
				return TC_ERR_INVAL;

			/* The member name is the region number as a string; the object
			 * repeats it as RegionID, so it is only a fallback. */
			char keybuf[32];
			int64_t key_id = 0;
			bool have_key_id =
			    tc_json_string_copy(&ev, keybuf, sizeof keybuf) == TC_OK &&
			    keybuf[0] != '\0';
			if (have_key_id) {
				char *end = NULL;
				long long v = strtoll(keybuf, &end, 10);
				have_key_id = (end != keybuf && *end == '\0');
				key_id = (int64_t)v;
			}

			bool keep = out->num_regions < TC_DERPMAP_MAX_REGIONS;
			tc_derp_region *reg =
			    &out->regions[keep ? out->num_regions : 0];
			rc = parse_region(&r, reg, keep);
			if (rc != TC_OK) {
				FAILF("malformed region: %s", tc_strerror(rc));
				return rc;
			}
			if (!keep)
				continue;
			if (reg->region_id == 0 && have_key_id)
				reg->region_id = key_id;
			if (reg->region_code[0] == '\0')
				(void)snprintf(reg->region_code, sizeof reg->region_code,
				               "%lld", (long long)reg->region_id);
			/* A region with no relay is useless to us. */
			if (reg->num_nodes > 0)
				out->num_regions++;
		}
	}

	if (!saw_regions || out->num_regions == 0) {
		FAILF("the DERP map contains no usable regions");
		return TC_ERR_INVAL;
	}
	return TC_OK;
}

const tc_derp_region *tc_derpmap_find(const tc_derp_map *m, int64_t region_id)
{
	if (m == NULL)
		return NULL;
	for (size_t i = 0; i < m->num_regions; i++)
		if (m->regions[i].region_id == region_id)
			return &m->regions[i];
	return NULL;
}

/* ---- fetching and caching -------------------------------------------- */

/* Cosmopolitan's PTHREAD_MUTEX_INITIALIZER does not name every member, so
 * -Wmissing-field-initializers fires on a correct use of the standard macro;
 * the unnamed members are zero-initialised, which is what it intends. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
#pragma GCC diagnostic pop
static tc_derp_map g_cache;
static char g_cache_url[512];
static time_t g_cache_at;

/* The map is a few kilobytes; this is generous and still bounded. */
#define DERPMAP_MAX_BYTES (512u * 1024u)

int tc_derpmap_fetch(tc_derp_map *out, const char *url, bool insecure,
                     int timeout_ms)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	if (url == NULL)
		url = TC_DERPMAP_DEFAULT_URL;

	g_err[0] = '\0';

	pthread_mutex_lock(&g_cache_lock);
	bool fresh = g_cache_at != 0 && strcmp(g_cache_url, url) == 0 &&
	             difftime(time(NULL), g_cache_at) < TC_DERPMAP_CACHE_SECONDS;
	if (fresh)
		*out = g_cache;
	pthread_mutex_unlock(&g_cache_lock);
	if (fresh)
		return TC_OK;

	uint8_t *body = (uint8_t *)malloc(DERPMAP_MAX_BYTES);
	if (body == NULL) {
		FAILF("out of memory");
		return TC_ERR_INVAL;
	}

	size_t body_len = 0;
	int status = 0;
	tc_http_options opts;
	memset(&opts, 0, sizeof opts);
	opts.insecure_skip_verify = insecure;
	opts.timeout_ms = timeout_ms;

	int rc = tc_http_get(url, body, DERPMAP_MAX_BYTES, &body_len, &status,
	                     &opts);
	if (rc != TC_OK) {
		FAILF("fetching %.80s: %s", url, tc_http_error_string());
		free(body);
		return rc;
	}
	if (status < 200 || status >= 300) {
		FAILF("%.120s returned HTTP %d", url, status);
		free(body);
		return TC_ERR_INVAL;
	}

	rc = tc_derpmap_parse(out, (const char *)body, body_len);
	free(body);
	if (rc != TC_OK)
		return rc;

	pthread_mutex_lock(&g_cache_lock);
	g_cache = *out;
	(void)snprintf(g_cache_url, sizeof g_cache_url, "%s", url);
	g_cache_at = time(NULL);
	pthread_mutex_unlock(&g_cache_lock);
	return TC_OK;
}

/* ---- region selection ------------------------------------------------ */

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

const tc_derp_region *tc_derpmap_pick_fastest(const tc_derp_map *m,
                                              size_t probe, int timeout_ms,
                                              bool insecure)
{
	if (m == NULL || m->num_regions == 0)
		return NULL;
	if (probe == 0 || probe > m->num_regions)
		probe = m->num_regions;
	if (timeout_ms <= 0)
		timeout_ms = 5000;

	/* A throwaway identity: we are measuring the path, not joining anything,
	 * and reusing the caller's key would tell every probed relay about it. */
	tc_wg_identity probe_id;
	if (tc_wg_identity_generate(&probe_id) != TC_OK)
		return &m->regions[0];

	const tc_derp_region *best = NULL;
	uint64_t best_ms = UINT64_MAX;

	for (size_t i = 0; i < probe; i++) {
		const tc_derp_region *reg = &m->regions[i];
		if (reg->num_nodes == 0)
			continue;
		const tc_derp_node *node = &reg->nodes[0];

		tc_derp_dial_opts opts;
		memset(&opts, 0, sizeof opts);
		opts.hostname = node->hostname;
		opts.dial_addr = (node->ipv4[0] != '\0') ? node->ipv4 : NULL;
		opts.port = (node->derp_port > 0) ? (uint16_t)node->derp_port : 0;
		opts.insecure_skip_verify = insecure || node->insecure_for_tests;
		opts.timeout_ms = timeout_ms;

		uint64_t t0 = now_ms();
		tc_derp_client c;
		if (tc_derp_connect(&c, &opts, probe_id.private_key,
		                    probe_id.public_key) != TC_OK)
			continue;
		uint64_t dt = now_ms() - t0;
		tc_derp_close(&c);

		if (dt < best_ms) {
			best_ms = dt;
			best = reg;
		}
	}

	/* If every probe failed, hand back the first region rather than nothing:
	 * a relay that refused a probe may still work, and failing here would
	 * turn a slow network into no service at all. */
	return (best != NULL) ? best : &m->regions[0];
}
