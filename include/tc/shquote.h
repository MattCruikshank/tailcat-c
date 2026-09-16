/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Quoting a command line for OpenSSH's ProxyCommand.
 *
 * `tailcat-c ssh` works the way upstream's does: it execs the system ssh
 * client with a ProxyCommand that runs tailcat-c itself in pipe mode, so ssh
 * sees an ordinary destination while the bytes actually go over the tunnel.
 *
 * OpenSSH does not exec that command directly. It hands it to a shell, so
 * every argument has to survive one round of shell parsing -- and before
 * that, OpenSSH expands its own `%` tokens, so a literal percent has to be
 * doubled. Getting this wrong is not a cosmetic bug: the arguments include a
 * path this program did not choose, and a command line assembled by naive
 * concatenation is a shell injection with extra steps.
 *
 * Hence a separate, tested file for what is otherwise four lines of string
 * building.
 */
#ifndef TC_SHQUOTE_H_
#define TC_SHQUOTE_H_

#include "tc/tc.h"

/* tc_proxycmd_join builds the ProxyCommand string from argv[0..n).
 *
 * POSIX form: every argument is wrapped in single quotes, embedded single
 * quotes become '"'"', and percent signs are doubled for OpenSSH's token
 * expansion, which turns %% back into % before the shell sees it.
 *
 * Windows form: Win32-OpenSSH runs a ProxyCommand through cmd.exe, which
 * expands %VAR% and sometimes !VAR! even inside quotes. There is no escape
 * that survives both cmd.exe and the argv parser on the other side, so those
 * characters are refused rather than mangled.
 *
 * Returns TC_ERR_INVAL for an argument holding a control character (which no
 * quoting makes safe), and TC_ERR_NOSPACE if the result does not fit. */
int tc_proxycmd_join(char *out, size_t cap, const char *const *args, size_t n,
                     bool windows);

/* tc_ssh_dest_host is the short, stable hostname given to ssh in place of the
 * real address: "tailcat-" followed by 16 hex digits.
 *
 * ssh substitutes the destination into %n in ControlPath, and that expansion
 * has to fit inside an AF_UNIX socket path. A tailcat address alone can be
 * longer than that, so connection multiplexing fails before tailcat-c is ever
 * invoked. The real address still reaches us as its own ProxyCommand
 * argument, so this string only ever labels the connection for ssh's
 * bookkeeping.
 *
 * It must be a deterministic function of the address rather than a truncation
 * or a counter: ssh keys its control socket on the expanded path, so the same
 * address has to produce the same name every time or multiplexing silently
 * stops reusing the right connection. out needs 26 bytes. */
int tc_ssh_dest_host(char *out, size_t cap, const char *addr);

#endif /* TC_SHQUOTE_H_ */
