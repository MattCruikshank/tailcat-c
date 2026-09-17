/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Which clients a server will talk to.
 *
 * Until now the address has been the only credential: anyone holding it can
 * connect, because holding it means holding the server's public key and the
 * pre-shared key. That is a real credential and for a lot of uses it is
 * enough -- but it is a *bearer* credential, so it is exactly as secret as
 * the least careful place it has been pasted, and it cannot be narrowed after
 * the fact. `serve exit-node` makes that sharper: anyone with the address can
 * then reach anything the serving machine can.
 *
 * An allow list adds the missing half. It names the client node keys that may
 * connect, so the address stops being sufficient on its own.
 *
 * ---- where it is enforced ----------------------------------------------
 *
 * At the meow, which is the first thing a client says and the first point at
 * which we learn who it claims to be. A refused client is never added as a
 * peer, so its WireGuard handshake has nothing to complete against.
 *
 * The key is not merely claimed, either: the relay tells us which node key
 * the packet arrived under, and the meow's own contents must agree with it
 * before we look at all. Beyond that, a client that is admitted still has to
 * complete a Noise handshake it can only complete by holding the private key
 * -- so the allow list narrows *who may try*, and the tunnel still decides
 * who succeeds.
 *
 * ---- silence, not a refusal --------------------------------------------
 *
 * A client that is not on the list gets no answer at all, rather than an
 * error. It retries and gives up, exactly as it would against an address that
 * does not exist. That is upstream's behaviour and it is the right one: an
 * explicit "you are not allowed" tells an unauthorised caller that they found
 * a real server, which is the one thing they did not already know.
 *
 * ---- "none" ------------------------------------------------------------
 *
 * Upstream spells "allow nobody" as `--allow=none`, and implements it by
 * putting the all-zero node key on the list: a key no client can hold, so the
 * list is non-empty and matches nobody. That is Go's `nil map` versus `empty
 * map` distinction wearing a disguise -- upstream needs the list to be
 * non-nil for the filter to engage at all.
 *
 * We take the spelling and not the trick. `active` says whether a list was
 * given, so "none" is simply an active list with nothing on it, and there is
 * no sentinel key to reason about.
 *
 * The all-zero key is refused outright in any case, list or no list. No real
 * client can hold it -- it is the X25519 identity element, with no private
 * key behind it -- but "no client can" is a weaker guarantee than "we do not
 * accept it", and the difference costs one comparison.
 */
#ifndef TC_ALLOWLIST_H_
#define TC_ALLOWLIST_H_

#include "tc/tc.h"

#ifndef TC_ALLOW_MAX
#define TC_ALLOW_MAX 32
#endif

typedef struct {
	uint8_t keys[TC_ALLOW_MAX][TC_NODE_KEY_LEN];
	size_t num;
	/* False means no list was given and every client is allowed. Kept
	 * separate from num == 0, which means a list that admits nobody. */
	bool active;
} tc_allowlist;

/* tc_allow_parse reads a comma-separated list of "nodekey:<64 hex>" entries,
 * or the single word "none".
 *
 * Folds into a list the caller has cleared, so a flag may be given more than
 * once. Whitespace around entries is ignored; an empty entry is an error
 * rather than a silent skip, because "a,,b" is more likely a shell quoting
 * accident than an intention.
 *
 * tc_allow_error_string describes the last failure. */
int tc_allow_parse(tc_allowlist *l, const char *spec);

/* tc_allow_permits reports whether a client may connect.
 *
 * Constant-time against the key material. The comparison is not secret and
 * an attacker already knows their own key, so this is defence in depth rather
 * than a load-bearing property -- but a public-key comparison that leaks
 * where it stopped matching is a bad habit to leave in a codebase that has a
 * constant-time helper sitting right there. */
bool tc_allow_permits(const tc_allowlist *l, const uint8_t key[32]);

const char *tc_allow_error_string(void);

#endif /* TC_ALLOWLIST_H_ */
