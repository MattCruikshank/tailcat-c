/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Fetching and parsing the DERP map: the list of relays a short tailcat
 * address refers to by region number.
 *
 * Without this, a short address is unusable and `serve` has to be told a
 * relay by hand. The document lives at https://tailcat.dev/derpmap.json and
 * looks like:
 *
 *   {"Regions": {"301": {"RegionID":301, "RegionCode":"nyc",
 *                        "RegionName":"New York City",
 *                        "Latitude":…, "Longitude":…,
 *                        "Nodes":[{"Name":"301a", "RegionID":301,
 *                                  "HostName":"tc301a.ipn.dev",
 *                                  "IPv4":…, "IPv6":…, "CanPort80":true}]}}}
 *
 * Unknown fields are skipped, so a document that gains members later still
 * parses. Latitude and Longitude are ignored: nothing here needs them, and
 * skipping them keeps floating point out of the parser entirely.
 */
#ifndef TC_DERPMAP_H_
#define TC_DERPMAP_H_

#include "tc/addr.h"

/* The published map, which is also what upstream defaults to. */
#define TC_DERPMAP_DEFAULT_URL "https://tailcat.dev/derpmap.json"

/* Upstream caches for an hour; so do we. */
#define TC_DERPMAP_CACHE_SECONDS 3600

#ifndef TC_DERPMAP_MAX_REGIONS
#define TC_DERPMAP_MAX_REGIONS 32
#endif

/* A whole map. Several hundred kilobytes with the limits above, so heap
 * allocate it rather than putting one on a stack. */
typedef struct {
	tc_derp_region regions[TC_DERPMAP_MAX_REGIONS];
	size_t num_regions;
} tc_derp_map;

/* tc_derpmap_parse decodes a DERP map document.
 *
 * Regions beyond TC_DERPMAP_MAX_REGIONS, and nodes beyond
 * TC_ADDR_MAX_NODES, are dropped rather than failing the whole document: a
 * map that grows past our limits should still be usable for the regions we
 * can hold. A malformed document is rejected outright. */
int tc_derpmap_parse(tc_derp_map *out, const char *json, size_t len);

/* tc_derpmap_fetch retrieves and parses the map, using a process-wide cache.
 * url may be NULL for the default. */
int tc_derpmap_fetch(tc_derp_map *out, const char *url, bool insecure,
                     int timeout_ms);

/* tc_derpmap_find returns the region with the given ID, or NULL. */
const tc_derp_region *tc_derpmap_find(const tc_derp_map *m, int64_t region_id);

/* tc_derpmap_pick_fastest measures the round trip to up to `probe` regions
 * and returns the quickest to answer, or NULL.
 *
 * It times a DERP connection (TCP, TLS and the relay's key exchange), which
 * is NOT what upstream does -- netcheck sends STUN probes and measures the
 * UDP path. This measures the path we actually use for a relayed session,
 * which is the right thing for the relay-only case, but it will choose
 * differently from upstream on networks where TCP and UDP diverge. Revisit
 * when STUN arrives.
 *
 * Probing is sequential and each attempt is bounded, so the worst case is
 * probe * timeout_ms. */
const tc_derp_region *tc_derpmap_pick_fastest(const tc_derp_map *m,
                                              size_t probe, int timeout_ms,
                                              bool insecure);

/* tc_derpmap_error_string describes the last failure on this thread. */
const char *tc_derpmap_error_string(void);

#endif /* TC_DERPMAP_H_ */
