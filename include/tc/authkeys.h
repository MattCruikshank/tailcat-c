/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Who may log in: `--ssh-authorized-keys`, and the three places it reads from.
 *
 * Upstream takes one flag that means any of three things, and it is worth
 * saying why that is not the muddle it looks like. The three forms are
 * distinguishable by inspection and they fail in different, obvious ways:
 *
 *   - a literal key       `--ssh-authorized-keys "ssh-ed25519 AAAAC3..."`
 *   - a file              `--ssh-authorized-keys ~/.ssh/authorized_keys`
 *   - a GitHub account    `--ssh-authorized-keys alice@github`
 *
 * The last one fetches https://github.com/alice.keys, which is a public
 * endpoint GitHub provides for exactly this. It is a network call made on the
 * strength of a command-line argument, so it is reported rather than silent,
 * it is TLS-verified like everything else here, and a failure is fatal --
 * starting a server with an empty key list because a fetch timed out is how
 * `serve ssh` becomes a server nobody can log into, or worse, one whose
 * operator thinks three people can.
 *
 * ---- only ed25519 -------------------------------------------------------
 *
 * Lines naming any other algorithm are skipped, not refused: a real
 * authorized_keys file has RSA and ECDSA keys in it, and refusing the file
 * because of them would make the common case fail. But a file whose lines
 * were *all* skipped yields no keys, and an empty list is fatal above -- so
 * "your keys are all RSA" surfaces as a refusal to start rather than as a
 * server that silently admits nobody.
 *
 * This is a real limitation and not a simplification: the SSH server here
 * verifies ed25519 signatures and nothing else, so an RSA key in the list
 * would be a key that can never authenticate.
 */
#ifndef TC_AUTHKEYS_H_
#define TC_AUTHKEYS_H_

#include "tc/tc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Enough for a large team's authorized_keys, and small enough that the list
 * is a fixed allocation rather than a growing one. */
#define TC_AUTHKEYS_MAX 64

typedef struct {
	uint8_t key[TC_AUTHKEYS_MAX][32];
	size_t count;
	/* Lines that named an algorithm we cannot verify. Counted so the caller
	 * can say "3 keys, 2 skipped (not ed25519)" rather than leaving someone
	 * to wonder where their RSA key went. */
	size_t skipped;
} tc_authkeys;

void tc_authkeys_init(tc_authkeys *ks);

/* tc_authkeys_parse_line reads one authorized_keys line.
 *
 * Returns TC_OK and fills out on an ed25519 key, TC_ERR_UNSUPPORTED for a
 * well-formed line naming another algorithm, TC_ERR_NOTFOUND for a blank or
 * comment line, and TC_ERR_INVAL for a line that is malformed.
 *
 * Leading options -- `no-pty,from="10.0.0.0/8" ssh-ed25519 AAAA...` -- are
 * *refused*, not ignored. Every one of them is a restriction, and a server
 * that reads the key while discarding `command="..."` has quietly granted
 * more than the file says. Skipping the line would be no better: the same
 * key without its restriction is the thing being asked for. So the line is
 * malformed as far as this program is concerned, and it says so.
 */
int tc_authkeys_parse_line(const char *line, uint8_t out[32]);

/* tc_authkeys_add_text reads many lines. Returns TC_ERR_TOOMANY if the list
 * fills. Malformed lines are an error; unsupported and blank ones are not. */
int tc_authkeys_add_text(tc_authkeys *ks, const char *text);

/* tc_authkeys_add_spec handles one --ssh-authorized-keys argument in any of
 * the three forms. `fetch` may be NULL to refuse the network form, which is
 * what the tests use.
 *
 * Returns TC_ERR_NOTFOUND if the spec named a file that is not there, which
 * the caller should report with the path rather than as a parse failure. */
typedef int (*tc_authkeys_fetch_fn)(void *ctx, const char *url, char *out,
                                    size_t cap);
int tc_authkeys_add_spec(tc_authkeys *ks, const char *spec,
                         tc_authkeys_fetch_fn fetch, void *ctx);

/* tc_authkeys_error_string describes the last failure on this thread, or "".
 * The message names the line number for a file, because "bad key" against a
 * forty-line authorized_keys is not a usable diagnostic. */
const char *tc_authkeys_error_string(void);

/* tc_authkeys_github_url writes the URL a `<user>@github` spec resolves to.
 * Exposed so a test can check the URL without making the request, and so the
 * caller can print it before fetching. Returns TC_ERR_INVAL for a username
 * that is not one GitHub could have issued. */
int tc_authkeys_github_url(char *out, size_t cap, const char *user);

#endif /* TC_AUTHKEYS_H_ */
