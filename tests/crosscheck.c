/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Reads "<address>TAB<json>" lines produced by tools/genaddrs (which uses the
 * real Go tailcat library) and requires that, for every one:
 *
 *   - the C parser accepts it, and
 *   - re-encoding the parsed form reproduces the Go-generated address byte
 *     for byte.
 *
 * Byte-identical re-encoding is a strong check: it pins field order, the
 * omitempty rules, shortest-form CBOR integers and the elide/restore
 * transforms all at once. Any drift in any of them shows up here.
 */

#include "tc/addr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char line[262144];

int main(void)
{
	static tc_conn_info ci;
	char reenc[TC_ADDR_STR_MAX];
	unsigned long total = 0, failed = 0;

	while (fgets(line, sizeof line, stdin) != NULL) {
		/* Trim the trailing newline, then cut at the tab. */
		size_t n = strlen(line);
		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = '\0';
		if (n == 0)
			continue;

		char *tab = strchr(line, '\t');
		if (tab != NULL)
			*tab = '\0';

		const char *addr = line;
		size_t addr_len = strlen(addr);
		total++;

		int rc = tc_addr_parse(&ci, addr, addr_len);
		if (rc != TC_OK) {
			failed++;
			fprintf(stderr, "PARSE FAILED (%s): %s\n", tc_strerror(rc), addr);
			continue;
		}

		rc = tc_addr_encode(reenc, sizeof reenc, &ci, NULL);
		if (rc != TC_OK) {
			failed++;
			fprintf(stderr, "ENCODE FAILED (%s): %s\n", tc_strerror(rc), addr);
			continue;
		}

		if (strcmp(addr, reenc) != 0) {
			failed++;
			fprintf(stderr, "MISMATCH\n  go: %s\n   c: %s\n", addr, reenc);
		}
	}

	if (total == 0) {
		fprintf(stderr, "crosscheck: no input\n");
		return 1;
	}
	if (failed != 0) {
		printf("FAIL crosscheck              %lu/%lu addresses differ\n",
		       failed, total);
		return 1;
	}
	printf("ok   crosscheck              %lu Go-generated addresses re-encode identically\n",
	       total);
	return 0;
}
