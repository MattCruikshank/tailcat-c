/* SPDX-License-Identifier: BSD-3-Clause
 *
 * DERP map parsing. The sample is the shape of the real document at
 * https://tailcat.dev/derpmap.json; `make live-derpmap` fetches the actual
 * one and parses that.
 */

#include "tc/derpmap.h"

#include "tctest.h"

#include <stdlib.h>

static const char kMap[] =
	"{\"Regions\":{"
	"\"301\":{\"RegionID\":301,\"RegionCode\":\"nyc\","
	"\"RegionName\":\"New York City\",\"Latitude\":40.7128,"
	"\"Longitude\":-73.9936,\"Nodes\":["
	"{\"Name\":\"301a\",\"RegionID\":301,\"HostName\":\"tc301a.ipn.dev\","
	"\"IPv4\":\"199.38.181.166\",\"IPv6\":\"2607:f740:f::26b\","
	"\"CanPort80\":true}]},"
	"\"302\":{\"RegionID\":302,\"RegionCode\":\"sfo\","
	"\"RegionName\":\"San Francisco\",\"Nodes\":["
	"{\"Name\":\"302a\",\"HostName\":\"tc302a.ipn.dev\","
	"\"STUNPort\":3478,\"DERPPort\":8443},"
	"{\"Name\":\"302b\",\"HostName\":\"tc302b.ipn.dev\"}]},"
	"\"303\":{\"RegionID\":303,\"RegionCode\":\"fra\",\"Nodes\":["
	"{\"HostName\":\"tc303a.ipn.dev\"}]}"
	"}}";

static tc_derp_map *map_new(void)
{
	tc_derp_map *m = (tc_derp_map *)malloc(sizeof *m);
	return m;
}

static void test_parses_a_map(void)
{
	TCT_CASE("parses a realistic DERP map");
	tc_derp_map *m = map_new();
	TCT_TRUE(m != NULL);
	TCT_EQ_INT(tc_derpmap_parse(m, kMap, sizeof kMap - 1), TC_OK);
	TCT_EQ_INT(m->num_regions, 3);

	const tc_derp_region *nyc = tc_derpmap_find(m, 301);
	TCT_TRUE(nyc != NULL);
	TCT_EQ_STR(nyc->region_code, "nyc");
	TCT_EQ_STR(nyc->region_name, "New York City");
	TCT_EQ_INT(nyc->num_nodes, 1);
	TCT_EQ_STR(nyc->nodes[0].hostname, "tc301a.ipn.dev");
	TCT_EQ_STR(nyc->nodes[0].name, "301a");
	TCT_EQ_STR(nyc->nodes[0].ipv4, "199.38.181.166");
	TCT_EQ_STR(nyc->nodes[0].ipv6, "2607:f740:f::26b");

	TCT_CASE("multiple nodes and explicit ports");
	const tc_derp_region *sfo = tc_derpmap_find(m, 302);
	TCT_TRUE(sfo != NULL);
	TCT_EQ_INT(sfo->num_nodes, 2);
	TCT_EQ_INT(sfo->nodes[0].stun_port, 3478);
	TCT_EQ_INT(sfo->nodes[0].derp_port, 8443);
	TCT_EQ_STR(sfo->nodes[1].hostname, "tc302b.ipn.dev");
	/* Absent ports stay zero, which callers read as "the default". */
	TCT_EQ_INT(sfo->nodes[1].derp_port, 0);

	TCT_CASE("an unknown region is not found");
	TCT_TRUE(tc_derpmap_find(m, 999) == NULL);
	TCT_TRUE(tc_derpmap_find(NULL, 301) == NULL);

	TCT_CASE("Latitude and Longitude are skipped, not choked on");
	/* They are the only fractional numbers in the document, and nothing
	 * reads them -- so the parser needs no floating point at all. */
	TCT_EQ_INT(nyc->region_id, 301);

	free(m);
}

static void test_tolerates_change(void)
{
	TCT_CASE("unknown fields are ignored");
	/* A map that gains members must keep working, or every deployment of
	 * this binary breaks the day upstream adds a field. */
	static const char kFuture[] =
		"{\"OmitDefaultRegions\":true,"
		"\"Regions\":{\"1\":{\"RegionID\":1,\"RegionCode\":\"a\","
		"\"SomethingNew\":{\"deep\":[1,2,{\"x\":null}]},"
		"\"Nodes\":[{\"HostName\":\"a.example\",\"FutureFlag\":false,"
		"\"Extra\":[[[]]]}]}},"
		"\"TrailingUnknown\":[1,2,3]}";

	tc_derp_map *m = map_new();
	TCT_EQ_INT(tc_derpmap_parse(m, kFuture, sizeof kFuture - 1), TC_OK);
	TCT_EQ_INT(m->num_regions, 1);
	TCT_EQ_STR(m->regions[0].nodes[0].hostname, "a.example");
	free(m);

	TCT_CASE("a region id comes from the member name when absent");
	static const char kNoId[] =
		"{\"Regions\":{\"77\":{\"Nodes\":[{\"HostName\":\"x.example\"}]}}}";
	m = map_new();
	TCT_EQ_INT(tc_derpmap_parse(m, kNoId, sizeof kNoId - 1), TC_OK);
	TCT_EQ_INT(m->regions[0].region_id, 77);
	/* And a missing code falls back to the number. */
	TCT_EQ_STR(m->regions[0].region_code, "77");
	free(m);

	TCT_CASE("a region with no relays is dropped");
	static const char kEmpty[] =
		"{\"Regions\":{\"1\":{\"RegionID\":1,\"Nodes\":[]},"
		"\"2\":{\"RegionID\":2,\"Nodes\":null},"
		"\"3\":{\"RegionID\":3,\"Nodes\":[{\"HostName\":\"y.example\"}]}}}";
	m = map_new();
	TCT_EQ_INT(tc_derpmap_parse(m, kEmpty, sizeof kEmpty - 1), TC_OK);
	TCT_EQ_INT(m->num_regions, 1);
	TCT_EQ_INT(m->regions[0].region_id, 3);
	free(m);
}

static void test_rejects(void)
{
	tc_derp_map *m = map_new();

	TCT_CASE("rejects malformed documents");
	static const char *const bad[] = {
		"",
		"[]",
		"null",
		"{}",                                  /* no Regions */
		"{\"Regions\":[]}",                    /* Regions not an object */
		"{\"Regions\":{}}",                    /* no usable regions */
		"{\"Regions\":{\"1\":{\"Nodes\":[]}}}", /* no relays anywhere */
		"{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"a\"}]}}",  /* truncated */
		"{\"Regions\":{\"1\":{\"RegionID\":\"notanumber\","
		"\"Nodes\":[{\"HostName\":\"a\"}]}}}",
		"{\"Regions\":{\"1\":{\"Nodes\":[{\"DERPPort\":99999,"
		"\"HostName\":\"a\"}]}}}",             /* port out of range */
		"{\"Regions\":{\"1\":{\"Nodes\":\"notanarray\"}}}",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		if (tc_derpmap_parse(m, bad[i], strlen(bad[i])) == TC_OK)
			TCT_FAILF("accepted a bad map: %s", bad[i]);
		tct_checks++;
	}

	TCT_CASE("every prefix of a valid map is refused");
	for (size_t n = 1; n < sizeof kMap - 1; n += 7) {
		if (tc_derpmap_parse(m, kMap, n) == TC_OK)
			TCT_FAILF("accepted a %zu byte prefix", n);
		tct_checks++;
	}

	free(m);
}

static void test_limits(void)
{
	TCT_CASE("more regions than we hold are dropped, not fatal");
	/* A map that outgrows our limits should still be usable for what fits,
	 * rather than leaving the tool with no relays at all. */
	static char big[262144];
	size_t n = 0;
	n += (size_t)snprintf(big + n, sizeof big - n, "{\"Regions\":{");
	for (int i = 1; i <= TC_DERPMAP_MAX_REGIONS + 20; i++)
		n += (size_t)snprintf(big + n, sizeof big - n,
		                      "%s\"%d\":{\"RegionID\":%d,\"Nodes\":"
		                      "[{\"HostName\":\"r%d.example\"}]}",
		                      i == 1 ? "" : ",", i, i, i);
	n += (size_t)snprintf(big + n, sizeof big - n, "}}");

	tc_derp_map *m = map_new();
	TCT_EQ_INT(tc_derpmap_parse(m, big, n), TC_OK);
	TCT_EQ_INT(m->num_regions, TC_DERPMAP_MAX_REGIONS);
	TCT_EQ_INT(m->regions[0].region_id, 1);

	TCT_CASE("more nodes than we hold are dropped, not fatal");
	n = 0;
	n += (size_t)snprintf(big + n, sizeof big - n,
	                      "{\"Regions\":{\"1\":{\"RegionID\":1,\"Nodes\":[");
	for (int i = 0; i < TC_ADDR_MAX_NODES + 10; i++)
		n += (size_t)snprintf(big + n, sizeof big - n,
		                      "%s{\"HostName\":\"n%d.example\"}",
		                      i == 0 ? "" : ",", i);
	n += (size_t)snprintf(big + n, sizeof big - n, "]}}}");

	TCT_EQ_INT(tc_derpmap_parse(m, big, n), TC_OK);
	TCT_EQ_INT(m->regions[0].num_nodes, TC_ADDR_MAX_NODES);
	TCT_EQ_STR(m->regions[0].nodes[0].hostname, "n0.example");

	TCT_CASE("an over-long hostname is refused rather than truncated");
	n = 0;
	n += (size_t)snprintf(big + n, sizeof big - n,
	                      "{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"");
	for (size_t i = 0; i < TC_DNS_NAME_MAX + 20; i++)
		big[n++] = 'a';
	n += (size_t)snprintf(big + n, sizeof big - n, "\"}]}}}");
	TCT_TRUE(tc_derpmap_parse(m, big, n) != TC_OK);

	free(m);
}

int main(void)
{
	test_parses_a_map();
	test_tolerates_change();
	test_rejects();
	test_limits();
	return tct_report("derpmap");
}
