/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Key exchange: negotiation, the exchange hash, and key derivation.
 *
 * The exchange hash vectors come from Go, which matters most for one detail
 * that is easy to miss and expensive to get wrong: the shared secret enters H
 * as an **mpint** while the two ephemeral public keys enter as strings. Half
 * of all secrets have their top bit set and need a leading zero byte that a
 * string encoding would not add, so an implementation that uses a string here
 * interoperates about half the time -- which is far worse than never, because
 * it looks like a flaky network.
 *
 * Half the vectors below have that bit set and half do not, deliberately.
 */

#include "tc/sshkex.h"

#include "tc/sshwire.h"

#include "ssh_vectors.h"
#include "tctest.h"

#include <string.h>

static int unhex1(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = strlen(s);
	if ((n & 1) != 0 || n / 2 > cap)
		return SIZE_MAX;
	for (size_t i = 0; i < n; i += 2) {
		int hi = unhex1(s[i]), lo = unhex1(s[i + 1]);
		if (hi < 0 || lo < 0)
			return SIZE_MAX;
		out[i / 2] = (uint8_t)(hi << 4 | lo);
	}
	return n / 2;
}

#define BUFSZ 1024

static void test_exchange_hash(void)
{
	TCT_CASE("the exchange hash matches Go's, with K as an mpint");
	for (size_t i = 0; i < sizeof kSshKexVectors / sizeof *kSshKexVectors;
	     i++) {
		uint8_t vc[BUFSZ], vs[BUFSZ], ic[BUFSZ], is[BUFSZ], ks[BUFSZ];
		uint8_t qc[32], qs[32], secret[32], want[TC_SSH_HASH_LEN];
		size_t vc_len = unhex(kSshKexVectors[i].vc, vc, sizeof vc);
		size_t vs_len = unhex(kSshKexVectors[i].vs, vs, sizeof vs);
		size_t ic_len = unhex(kSshKexVectors[i].ic, ic, sizeof ic);
		size_t is_len = unhex(kSshKexVectors[i].is, is, sizeof is);
		size_t ks_len = unhex(kSshKexVectors[i].ks, ks, sizeof ks);
		if (vc_len == SIZE_MAX || vs_len == SIZE_MAX || ic_len == SIZE_MAX ||
		    is_len == SIZE_MAX || ks_len == SIZE_MAX ||
		    unhex(kSshKexVectors[i].qc, qc, sizeof qc) != 32 ||
		    unhex(kSshKexVectors[i].qs, qs, sizeof qs) != 32 ||
		    unhex(kSshKexVectors[i].secret, secret, sizeof secret) != 32 ||
		    unhex(kSshKexVectors[i].h, want, sizeof want) !=
		        TC_SSH_HASH_LEN) {
			TCT_FAILF("vector %zu: unusable", i);
			continue;
		}

		tc_ssh_exchange e;
		memset(&e, 0, sizeof e);
		e.v_client = (const char *)vc;
		e.v_client_len = vc_len;
		e.v_server = (const char *)vs;
		e.v_server_len = vs_len;
		e.i_client = ic;
		e.i_client_len = ic_len;
		e.i_server = is;
		e.i_server_len = is_len;
		e.k_server = ks;
		e.k_server_len = ks_len;
		e.q_client = qc;
		e.q_server = qs;
		e.secret = secret;
		e.secret_len = sizeof secret;

		uint8_t got[TC_SSH_HASH_LEN];
		if (tc_ssh_exchange_hash(got, &e) != TC_OK) {
			TCT_FAILF("vector %zu: would not hash", i);
			continue;
		}
		tct_checks++;
		TCT_EQ_MEM(got, want, TC_SSH_HASH_LEN);

		TCT_CASE("and the derived keys match too");
		uint8_t c2s[TC_SSH_CIPHER_KEY_LEN], s2c[TC_SSH_CIPHER_KEY_LEN];
		uint8_t want_c2s[TC_SSH_CIPHER_KEY_LEN];
		uint8_t want_s2c[TC_SSH_CIPHER_KEY_LEN];
		if (unhex(kSshKexVectors[i].c2s, want_c2s, sizeof want_c2s) !=
		        TC_SSH_CIPHER_KEY_LEN ||
		    unhex(kSshKexVectors[i].s2c, want_s2c, sizeof want_s2c) !=
		        TC_SSH_CIPHER_KEY_LEN) {
			TCT_FAILF("vector %zu: unusable key vectors", i);
			continue;
		}
		/* On the first exchange the session id is H itself. */
		if (tc_ssh_derive_keys(c2s, s2c, secret, sizeof secret, got, got) !=
		    TC_OK) {
			TCT_FAILF("vector %zu: would not derive", i);
			continue;
		}
		tct_checks++;
		TCT_EQ_MEM(c2s, want_c2s, TC_SSH_CIPHER_KEY_LEN);
		TCT_EQ_MEM(s2c, want_s2c, TC_SSH_CIPHER_KEY_LEN);

		TCT_CASE("and the two directions differ");
		/* Only the letter differs in the input, so a derivation that
		 * dropped it would produce one key for both directions -- and a
		 * cipher keyed identically in both directions with a sequence
		 * number that starts at zero on both sides reuses a keystream. */
		TCT_TRUE(memcmp(c2s, s2c, TC_SSH_CIPHER_KEY_LEN) != 0);
	}
}

static void test_hash_covers_everything(void)
{
	/* H is what the server signs, so anything an attacker could alter in
	 * flight must change it. Each field is perturbed in turn and the hash
	 * must move; a field left out of the hash is a field a man in the middle
	 * can rewrite undetected. */
	TCT_CASE("every field of the exchange changes the hash");
	uint8_t vc[] = "SSH-2.0-client", vs[] = "SSH-2.0-server";
	uint8_t ic[64], is[64], ks[51], qc[32], qs[32], secret[32];
	memset(ic, 0x11, sizeof ic);
	memset(is, 0x22, sizeof is);
	memset(ks, 0x33, sizeof ks);
	memset(qc, 0x44, sizeof qc);
	memset(qs, 0x55, sizeof qs);
	memset(secret, 0x66, sizeof secret);

	tc_ssh_exchange e;
	memset(&e, 0, sizeof e);
	e.v_client = (const char *)vc;
	e.v_client_len = sizeof vc - 1;
	e.v_server = (const char *)vs;
	e.v_server_len = sizeof vs - 1;
	e.i_client = ic;
	e.i_client_len = sizeof ic;
	e.i_server = is;
	e.i_server_len = sizeof is;
	e.k_server = ks;
	e.k_server_len = sizeof ks;
	e.q_client = qc;
	e.q_server = qs;
	e.secret = secret;
	e.secret_len = sizeof secret;

	uint8_t base[TC_SSH_HASH_LEN];
	TCT_EQ_INT(tc_ssh_exchange_hash(base, &e), TC_OK);

	uint8_t *fields[] = { ic, is, ks, qc, qs, secret };
	for (size_t i = 0; i < sizeof fields / sizeof *fields; i++) {
		fields[i][0] ^= 0x01;
		uint8_t h[TC_SSH_HASH_LEN];
		TCT_EQ_INT(tc_ssh_exchange_hash(h, &e), TC_OK);
		if (memcmp(h, base, sizeof h) == 0)
			TCT_FAILF("field %zu is not covered by the exchange hash", i);
		fields[i][0] ^= 0x01;
	}
	tct_checks++;

	TCT_CASE("and so do the version strings");
	vc[8] ^= 0x01;
	uint8_t h[TC_SSH_HASH_LEN];
	TCT_EQ_INT(tc_ssh_exchange_hash(h, &e), TC_OK);
	TCT_TRUE(memcmp(h, base, sizeof h) != 0);
	vc[8] ^= 0x01;
}

static void test_negotiation(void)
{
	TCT_CASE("our own KEXINIT negotiates against itself");
	uint8_t mine[BUFSZ];
	size_t mine_len = 0;
	TCT_EQ_INT(tc_ssh_kexinit_build(mine, sizeof mine, &mine_len), TC_OK);
	TCT_TRUE(mine[0] == TC_SSH_MSG_KEXINIT);

	tc_ssh_negotiated neg;
	TCT_EQ_INT(tc_ssh_kexinit_parse(&neg, mine, mine_len), TC_OK);
	TCT_EQ_INT(neg.kex, 0);
	TCT_EQ_INT(neg.hostkey, 0);
	TCT_EQ_INT(neg.cipher_c2s, 0);
	TCT_EQ_INT(neg.cipher_s2c, 0);
	TCT_EQ_INT(neg.comp_c2s, 0);
	TCT_EQ_INT(neg.comp_s2c, 0);
	TCT_TRUE(!neg.first_kex_packet_follows);

	TCT_CASE("two KEXINITs in a row differ, because the cookie is random");
	/* RFC 4253 7.1 requires a random cookie; without one an attacker can
	 * predict the whole of I_S and half the exchange hash input. */
	uint8_t again[BUFSZ];
	size_t again_len = 0;
	TCT_EQ_INT(tc_ssh_kexinit_build(again, sizeof again, &again_len), TC_OK);
	TCT_EQ_INT((int)again_len, (int)mine_len);
	TCT_TRUE(memcmp(mine, again, mine_len) != 0);
	/* The difference must be the cookie, not the algorithm lists. */
	TCT_EQ_MEM(mine + 1 + TC_SSH_COOKIE_LEN, again + 1 + TC_SSH_COOKIE_LEN,
	           mine_len - 1 - TC_SSH_COOKIE_LEN);

	TCT_CASE("a peer with nothing in common is refused, not downgraded");
	/* Built by hand: valid shape, no algorithm we know. There is nothing
	 * weaker to fall back to here, and that is the design. */
	uint8_t alien[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, alien, sizeof alien);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEXINIT);
	uint8_t cookie[TC_SSH_COOKIE_LEN];
	memset(cookie, 0, sizeof cookie);
	tc_ssh_put_raw(&w, cookie, sizeof cookie);
	static const char *const nope[] = { "diffie-hellman-group1-sha1" };
	for (int i = 0; i < 8; i++)
		tc_ssh_put_namelist(&w, nope, 1);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_u32(&w, 0);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	TCT_EQ_INT(tc_ssh_kexinit_parse(&neg, alien, tc_ssh_wbuf_len(&w)),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("a truncated KEXINIT is refused");
	for (size_t cut = 1; cut < mine_len; cut += 7)
		TCT_TRUE(tc_ssh_kexinit_parse(&neg, mine, cut) != TC_OK);
	tct_checks++;
}

static void test_guess_detection(void)
{
	/* RFC 4253 7.1: a peer may send its guessed kex packet straight after
	 * its KEXINIT. If the guess was wrong that packet must be discarded --
	 * and a server that forgets reads the guess as the real
	 * KEX_ECDH_INIT, taking an ephemeral key from the wrong message. */
	uint8_t buf[BUFSZ];
	tc_ssh_negotiated neg;

	TCT_CASE("a guess matching our choice is not discarded");
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, buf, sizeof buf);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEXINIT);
	uint8_t cookie[TC_SSH_COOKIE_LEN];
	memset(cookie, 0x5a, sizeof cookie);
	tc_ssh_put_raw(&w, cookie, sizeof cookie);
	/* Their first choice is our first choice. */
	static const char *const kex_good[] = { "curve25519-sha256",
		                                    "curve25519-sha256@libssh.org" };
	tc_ssh_put_namelist(&w, kex_good, 2);
	tc_ssh_put_namelist(&w, tc_ssh_hostkey_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_bool(&w, true); /* a guess follows */
	tc_ssh_put_u32(&w, 0);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	TCT_EQ_INT(tc_ssh_kexinit_parse(&neg, buf, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_TRUE(neg.first_kex_packet_follows);
	TCT_TRUE(!neg.guess_was_wrong);

	TCT_CASE("a guess for an algorithm we rank lower is discarded");
	/* Both names are algorithms we support, so comparing against the
	 * negotiated result alone would call this guess correct. It is not: the
	 * client guessed with its favourite and we chose ours. */
	tc_ssh_wbuf_init(&w, buf, sizeof buf);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEXINIT);
	tc_ssh_put_raw(&w, cookie, sizeof cookie);
	static const char *const kex_swapped[] = {
		"curve25519-sha256@libssh.org", "curve25519-sha256"
	};
	tc_ssh_put_namelist(&w, kex_swapped, 2);
	tc_ssh_put_namelist(&w, tc_ssh_hostkey_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_u32(&w, 0);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	TCT_EQ_INT(tc_ssh_kexinit_parse(&neg, buf, tc_ssh_wbuf_len(&w)), TC_OK);
	/* We still choose our own first preference... */
	TCT_EQ_INT(neg.kex, 0);
	/* ...so their guess was for something else and must be dropped. */
	TCT_TRUE(neg.guess_was_wrong);

	TCT_CASE("and no guess means nothing to discard");
	tc_ssh_wbuf_init(&w, buf, sizeof buf);
	tc_ssh_put_byte(&w, TC_SSH_MSG_KEXINIT);
	tc_ssh_put_raw(&w, cookie, sizeof cookie);
	tc_ssh_put_namelist(&w, kex_swapped, 2);
	tc_ssh_put_namelist(&w, tc_ssh_hostkey_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_cipher_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_mac_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, tc_ssh_comp_algs, 1);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_namelist(&w, NULL, 0);
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_u32(&w, 0);
	TCT_EQ_INT(tc_ssh_kexinit_parse(&neg, buf, tc_ssh_wbuf_len(&w)), TC_OK);
	TCT_TRUE(!neg.guess_was_wrong);
}

static void test_blobs(void)
{
	TCT_CASE("the host key blob is the RFC 8709 shape");
	uint8_t pub[32];
	memset(pub, 0x77, sizeof pub);
	uint8_t blob[128];
	size_t blob_len = 0;
	TCT_EQ_INT(tc_ssh_hostkey_blob(blob, sizeof blob, &blob_len, pub), TC_OK);
	TCT_EQ_INT((int)blob_len, 4 + 11 + 4 + 32);

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, blob_len);
	TCT_TRUE(tc_ssh_get_string_eq(&r, "ssh-ed25519"));
	size_t n = 0;
	const uint8_t *key = tc_ssh_get_string(&r, 32, &n);
	TCT_TRUE(key != NULL && n == 32);
	TCT_EQ_MEM(key, pub, 32);
	TCT_EQ_INT((int)tc_ssh_rbuf_remaining(&r), 0);

	TCT_CASE("a buffer one byte too small is refused, not truncated");
	TCT_EQ_INT(tc_ssh_hostkey_blob(blob, blob_len - 1, &blob_len, pub),
	           TC_ERR_NOSPACE);

	TCT_CASE("the signature blob likewise");
	uint8_t sig[64];
	memset(sig, 0x88, sizeof sig);
	TCT_EQ_INT(tc_ssh_signature_blob(blob, sizeof blob, &blob_len, sig),
	           TC_OK);
	TCT_EQ_INT((int)blob_len, 4 + 11 + 4 + 64);
}

int main(void)
{
	test_exchange_hash();
	test_hash_covers_everything();
	test_negotiation();
	test_guess_detection();
	test_blobs();
	return tct_report("sshkex");
}
