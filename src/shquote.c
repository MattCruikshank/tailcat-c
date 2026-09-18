/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See shquote.h.
 */

#include "tc/shquote.h"

#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>

/* app appends one byte, reporting whether it fitted. */
static bool app(char *out, size_t cap, size_t *off, char c)
{
	if (*off + 1 >= cap)
		return false;
	out[(*off)++] = c;
	out[*off] = '\0';
	return true;
}

static bool app_str(char *out, size_t cap, size_t *off, const char *s)
{
	for (; *s != '\0'; s++)
		if (!app(out, cap, off, *s))
			return false;
	return true;
}

static bool has_control(const char *s)
{
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;
		if (c < 0x20 || c == 0x7f)
			return true;
	}
	return false;
}

static int join_posix(char *out, size_t cap, const char *const *args, size_t n)
{
	size_t off = 0;
	out[0] = '\0';

	for (size_t i = 0; i < n; i++) {
		if (i > 0 && !app(out, cap, &off, ' '))
			return TC_ERR_NOSPACE;
		if (!app(out, cap, &off, '\''))
			return TC_ERR_NOSPACE;
		for (const char *p = args[i]; *p != '\0'; p++) {
			if (*p == '\'') {
				/* Close the quote, emit an escaped quote, reopen. There is no
				 * way to write a single quote inside single quotes. */
				if (!app_str(out, cap, &off, "'\"'\"'"))
					return TC_ERR_NOSPACE;
			} else if (*p == '%') {
				/* Doubled for OpenSSH's own token expansion, which reduces
				 * %% to % before the shell ever sees the command. A single %
				 * would be read as the start of a token like %h. */
				if (!app_str(out, cap, &off, "%%"))
					return TC_ERR_NOSPACE;
			} else if (!app(out, cap, &off, *p)) {
				return TC_ERR_NOSPACE;
			}
		}
		if (!app(out, cap, &off, '\''))
			return TC_ERR_NOSPACE;
	}
	return TC_OK;
}

static int join_windows(char *out, size_t cap, const char *const *args,
                        size_t n)
{
	size_t off = 0;
	out[0] = '\0';

	for (size_t i = 0; i < n; i++) {
		const char *a = args[i];
		/* cmd.exe expands %VAR% and, with delayed expansion enabled, !VAR!,
		 * even inside double quotes; and a double quote means different
		 * things to cmd.exe and to the argv parser on the other side. No
		 * escape survives both, so these are refused rather than mangled. */
		if (strpbrk(a, "\"%!") != NULL)
			return TC_ERR_INVAL;

		if (i > 0 && !app(out, cap, &off, ' '))
			return TC_ERR_NOSPACE;
		if (!app(out, cap, &off, '"'))
			return TC_ERR_NOSPACE;
		if (!app_str(out, cap, &off, a))
			return TC_ERR_NOSPACE;
		/* Trailing backslashes would otherwise escape the closing quote for
		 * the Windows argv parser, so each is doubled. */
		size_t trail = 0;
		size_t len = strlen(a);
		while (trail < len && a[len - 1 - trail] == '\\')
			trail++;
		for (size_t k = 0; k < trail; k++)
			if (!app(out, cap, &off, '\\'))
				return TC_ERR_NOSPACE;
		if (!app(out, cap, &off, '"'))
			return TC_ERR_NOSPACE;
	}
	return TC_OK;
}

int tc_proxycmd_join(char *out, size_t cap, const char *const *args, size_t n,
                     bool windows)
{
	if (out == NULL || args == NULL || cap == 0)
		return TC_ERR_INVAL;
	for (size_t i = 0; i < n; i++) {
		if (args[i] == NULL)
			return TC_ERR_INVAL;
		/* No quoting makes a newline or a NUL safe in a command line: they
		 * end the command rather than appearing in it. */
		if (has_control(args[i]))
			return TC_ERR_INVAL;
	}
	return windows ? join_windows(out, cap, args, n)
	               : join_posix(out, cap, args, n);
}

int tc_ssh_dest_host(char *out, size_t cap, const char *addr)
{
	if (out == NULL || addr == NULL || cap < 26)
		return TC_ERR_NOSPACE;

	const mbedtls_md_info_t *info =
	    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (info == NULL)
		return TC_ERR_UNSUPPORTED;

	unsigned char sum[32];
	if (mbedtls_md(info, (const unsigned char *)addr, strlen(addr), sum) != 0)
		return TC_ERR_INVAL;

	static const char kHex[] = "0123456789abcdef";
	size_t off = 0;
	const char kPrefix[] = "tailcat-";
	memcpy(out, kPrefix, sizeof kPrefix - 1);
	off = sizeof kPrefix - 1;
	for (size_t i = 0; i < 8; i++) {
		out[off++] = kHex[sum[i] >> 4];
		out[off++] = kHex[sum[i] & 0x0f];
	}
	out[off] = '\0';
	return TC_OK;
}

size_t tc_flag_scan(const char *const *args, size_t n,
                    const char *takes_value)
{
	const char *kTakesValue = takes_value;
	if (args == NULL || takes_value == NULL)
		return n;
	for (size_t i = 0; i < n; i++) {
		const char *a = args[i];
		if (a == NULL)
			return n;
		if (a[0] != '-' || a[1] == '\0')
			return i; /* a bare "-" is not a flag, and neither is a name */
		if (strcmp(a, "--") == 0)
			return i + 1 < n ? i + 1 : n;
		for (size_t k = 1; a[k] != '\0'; k++) {
			if (strchr(kTakesValue, a[k]) == NULL)
				continue; /* boolean; keep reading the cluster */
			if (a[k + 1] != '\0')
				break; /* the value is attached: -ikey, -p22 */
			i++;       /* the value is the next argument */
			break;
		}
	}
	return n;
}

size_t tc_ssh_dest_index(const char *const *args, size_t n)
{
	return tc_flag_scan(args, n, TC_SSH_VALUE_FLAGS);
}
