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

/* The option letters that take a value, per tool.
 *
 * Two tables and not one, because the same letter means different things:
 * scp's `-P` is the port and its `-p` preserves timestamps, while ssh's `-p`
 * is the port and it has no `-P`. A scanner using ssh's table on an scp
 * command line eats the argument after `-p`, which is the first operand.
 *
 * From the SYNOPSIS of each manual page, OpenSSH 9.x. */
#define TC_SSH_VALUE_FLAGS "BbcDEeFIiJLlmOoPpQRSWw"
#define TC_SCP_VALUE_FLAGS "cDFiJloPSX"

/* tc_flag_scan counts the leading arguments that are options, including any
 * value an option takes.
 *
 * `takes_value` is one of the tables above. A value may be attached or
 * separate -- `-i key` and `-ikey` and `-vikey` all work -- and clustered
 * booleans do too, as in `-rv`. An unknown letter is assumed boolean, which
 * is the safe way round: the failure is then a legible complaint about a flag
 * rather than a silently mis-split command line.
 *
 * Returns n when every argument is an option. */
size_t tc_flag_scan(const char *const *args, size_t n, const char *takes_value);

/* tc_ssh_dest_index finds the destination among ssh's arguments.
 *
 * `ssh -i key -o Foo=bar host cmd` puts the destination fourth. Reading
 * argument zero as the address -- which is what this program did until a live
 * test tried to pass an identity file -- turns an ordinary invocation into
 * "-i is neither a tailcat address nor a DNS name".
 *
 * The flag letters are OpenSSH's own, split into those that take a value and
 * those that do not, because a value may be attached (`-i key` or `-ikey`)
 * and getting that wrong either skips the destination or eats it. Clustered
 * booleans work too: `-vvv`, `-tt`.
 *
 * An unknown flag is assumed to be boolean, which is the safe way round. A
 * value-taking flag this does not know about would make it read that value as
 * the destination and refuse with a message naming it -- wrong, but legible.
 * The other way round it would silently treat the real destination as a flag's
 * argument and dial whatever came next.
 *
 * Returns n when there is no destination at all. */
size_t tc_ssh_dest_index(const char *const *args, size_t n);

#endif /* TC_SHQUOTE_H_ */
