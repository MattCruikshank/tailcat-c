/* SPDX-License-Identifier: BSD-3-Clause
 *
 * tailcat addresses.
 *
 * An address is the string "tc" followed by the unpadded base64url encoding
 * of a CBOR map describing how to reach a server: its WireGuard public key,
 * its disco (path-discovery) public key, an optional WireGuard pre-shared
 * key, and either an embedded DERP region or a bare DERP region ID.
 *
 * The CBOR field names are single characters and are the wire format; they
 * must never change or be reused. They mirror wire.go in the Go
 * implementation:
 *
 *   ConnInfo: p=ServerPublic  k=ServerDiscoPublic  q=PresharedKey
 *             r=Region        i=RegionID
 *   Region:   i=RegionID  c=RegionCode  m=RegionName  N=Nodes
 *   Node:     n=Name  i=RegionID  h=HostName  t=CertName  4=IPv4  6=IPv6
 *             s=STUNPort  d=DERPPort  x=InsecureForTests
 *
 * SECURITY: when PresharedKey is present the whole address is a secret --
 * anyone holding it can join the tunnel. Treat it like a private key.
 *
 * Addresses arrive from untrusted places (a pasted string, a "tailcat=" TXT
 * record), so parsing is bounded and allocation-free. Anything that exceeds
 * the fixed limits below is rejected with TC_ERR_TOOMANY rather than
 * truncated.
 */
#ifndef TC_ADDR_H_
#define TC_ADDR_H_

#include "tc/tc.h"

/* Real addresses carry one region with one or two nodes: the Go
 * implementation notes a maximum of one region, and Resolve() truncates to
 * two nodes to keep addresses short. These limits leave headroom without
 * making tc_conn_info unreasonably large. Override at build time if needed. */
#ifndef TC_ADDR_MAX_REGIONS
#define TC_ADDR_MAX_REGIONS 2
#endif
#ifndef TC_ADDR_MAX_NODES
#define TC_ADDR_MAX_NODES 8
#endif

/* String field capacities, including the NUL. */
#define TC_DNS_NAME_MAX 256 /* a DNS name is at most 253 octets */
#define TC_REGION_CODE_MAX 64
#define TC_REGION_NAME_MAX 64
#define TC_IP_STR_MAX 46 /* INET6_ADDRSTRLEN */

/* Bounds on the encoded forms. */
#define TC_ADDR_CBOR_MAX 16384
#define TC_ADDR_STR_MAX 24576

typedef struct {
	char name[TC_DNS_NAME_MAX];
	char hostname[TC_DNS_NAME_MAX];
	/* Expected TLS certificate name when it differs from hostname, which is
	 * used for SNI. Empty means the cert should match hostname. */
	char cert_name[TC_DNS_NAME_MAX];
	char ipv4[TC_IP_STR_MAX];
	char ipv6[TC_IP_STR_MAX];
	int64_t region_id;
	int32_t stun_port;
	int32_t derp_port;
	bool insecure_for_tests;
} tc_derp_node;

typedef struct {
	int64_t region_id;
	char region_code[TC_REGION_CODE_MAX];
	char region_name[TC_REGION_NAME_MAX];
	tc_derp_node nodes[TC_ADDR_MAX_NODES];
	size_t num_nodes;
} tc_derp_region;

/* tc_conn_info is several kilobytes; prefer the heap or a file-scope buffer
 * over a small thread stack. */
typedef struct {
	uint8_t server_public[TC_NODE_KEY_LEN];

	uint8_t server_disco_public[TC_DISCO_KEY_LEN];
	bool has_disco_public;

	/* Mixed into the WireGuard handshake. Independent of the node keys, so
	 * a DERP operator that sees both peers' public keys still cannot join
	 * the tunnel. Absent means the pre-shared-key layer is off, which older
	 * clients relied on. */
	uint8_t preshared_key[TC_PSK_LEN];
	bool has_preshared_key;

	/* Either regions is non-empty (self-contained, works offline) or
	 * region_id names one of the relays in the published DERP map, which
	 * the client must then fetch. */
	tc_derp_region regions[TC_ADDR_MAX_REGIONS];
	size_t num_regions;
	int64_t region_id;
} tc_conn_info;

/* tc_addr_parse decodes a tailcat address into *out.
 *
 * It restores the fields the encoder elides, exactly as Go's ParseAddr does:
 * a region with no ID gets its 1-based index, a region with no code gets the
 * decimal form of its ID, a node with no name inherits its hostname (netcheck
 * identifies nodes by name, so they must be distinct), and a node with no
 * region ID inherits its region's.
 *
 * addr_len is the length of addr, which need not be NUL-terminated.
 * *out is fully overwritten on success and left unspecified on failure. */
int tc_addr_parse(tc_conn_info *out, const char *addr, size_t addr_len);

/* tc_addr_parse_raw is tc_addr_parse without the restoration: the fields the
 * encoder elided are left zero and empty rather than derived.
 *
 * It exists for `tailcat-c parse`, which reports what an address *contains*.
 * Upstream draws the same distinction -- its parse command calls
 * ParseAddrRaw -- and it matters, because the restored values are guesses
 * that happen to be right. A region with no ID encoded gets its 1-based
 * index; printing "RegionID: 1" would claim the address said something it
 * did not. Every other caller wants tc_addr_parse, because connecting needs
 * the derived values and does not care where they came from.
 *
 * The result must not be handed to tc_addr_encode expecting a byte-identical
 * round trip of a *restored* structure -- but a raw parse re-encodes to the
 * same address, because eliding what was never there is a no-op. */
int tc_addr_parse_raw(tc_conn_info *out, const char *addr, size_t addr_len);

/* tc_addr_encode writes the address form of *ci to out as a NUL-terminated
 * string, storing the length excluding the NUL in *out_len when non-NULL.
 *
 * It applies the same elisions as Go's ConnInfo.Addr: per-region IDs, codes
 * and names are dropped, node region IDs are dropped, and a node's name is
 * dropped when it has a hostname. So encoding the result of tc_addr_parse
 * reproduces the original address byte for byte. */
int tc_addr_encode(char *out, size_t cap, const tc_conn_info *ci,
                   size_t *out_len);

#endif /* TC_ADDR_H_ */
