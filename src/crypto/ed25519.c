/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See ed25519.h.
 *
 * Three layers, each checkable on its own:
 *
 *   fe   arithmetic in GF(2^255 - 19), radix 2^51 across five uint64_t
 *   ge   points on the twisted Edwards curve, in extended coordinates
 *   sc   arithmetic modulo L, the order of the base point's subgroup
 *
 * The field layer carries limbs slightly larger than 2^51 between operations
 * and reduces lazily, which is the usual arrangement and the usual source of
 * bugs: every function below documents the size of what it accepts and what
 * it returns, because "it worked on the test vector" does not distinguish a
 * correct carry chain from one that happens not to have overflowed yet.
 */

#include "tc/ed25519.h"

#include "tc/crypto.h"

#include "mbedtls/sha512.h"

#include <string.h>

__extension__ typedef unsigned __int128 u128;

/* ---- fe: GF(2^255 - 19) -------------------------------------------------
 *
 * Five limbs of 51 bits. A "reduced" fe has every limb below 2^51; most
 * operations accept limbs up to about 2^54 and return reduced ones.
 */

typedef uint64_t fe[5];

static const uint64_t kMask51 = ((uint64_t)1 << 51) - 1;

static void fe_0(fe h)
{
	memset(h, 0, sizeof(fe));
}

static void fe_1(fe h)
{
	h[0] = 1;
	h[1] = h[2] = h[3] = h[4] = 0;
}

static void fe_copy(fe h, const fe f)
{
	memcpy(h, f, sizeof(fe));
}

/* fe_add accepts limbs below 2^54 and returns limbs below 2^55. */
static void fe_add(fe h, const fe f, const fe g)
{
	for (int i = 0; i < 5; i++)
		h[i] = f[i] + g[i];
}

/* fe_sub returns f - g. 2*p is added first so the result cannot go negative:
 * each limb of 2*p is well above any limb of g the callers here produce. */
static void fe_sub(fe h, const fe f, const fe g)
{
	static const uint64_t k2p[5] = { 0xfffffffffffdaULL, 0xffffffffffffeULL,
		                             0xffffffffffffeULL, 0xffffffffffffeULL,
		                             0xffffffffffffeULL };
	for (int i = 0; i < 5; i++)
		h[i] = f[i] + k2p[i] - g[i];
}

/* fe_carry normalises limbs to below 2^51 + a little. */
static void fe_carry(fe h)
{
	uint64_t c;
	c = h[0] >> 51;
	h[0] &= kMask51;
	h[1] += c;
	c = h[1] >> 51;
	h[1] &= kMask51;
	h[2] += c;
	c = h[2] >> 51;
	h[2] &= kMask51;
	h[3] += c;
	c = h[3] >> 51;
	h[3] &= kMask51;
	h[4] += c;
	c = h[4] >> 51;
	h[4] &= kMask51;
	/* 2^255 = 19 mod p, so the carry out of the top comes back multiplied. */
	h[0] += c * 19;
	c = h[0] >> 51;
	h[0] &= kMask51;
	h[1] += c;
}

/* fe_mul accepts limbs below 2^54 and returns reduced ones. */
static void fe_mul(fe h, const fe f, const fe g)
{
	const uint64_t g1_19 = 19 * g[1];
	const uint64_t g2_19 = 19 * g[2];
	const uint64_t g3_19 = 19 * g[3];
	const uint64_t g4_19 = 19 * g[4];

	u128 r0 = (u128)f[0] * g[0] + (u128)f[1] * g4_19 + (u128)f[2] * g3_19 +
	          (u128)f[3] * g2_19 + (u128)f[4] * g1_19;
	u128 r1 = (u128)f[0] * g[1] + (u128)f[1] * g[0] + (u128)f[2] * g4_19 +
	          (u128)f[3] * g3_19 + (u128)f[4] * g2_19;
	u128 r2 = (u128)f[0] * g[2] + (u128)f[1] * g[1] + (u128)f[2] * g[0] +
	          (u128)f[3] * g4_19 + (u128)f[4] * g3_19;
	u128 r3 = (u128)f[0] * g[3] + (u128)f[1] * g[2] + (u128)f[2] * g[1] +
	          (u128)f[3] * g[0] + (u128)f[4] * g4_19;
	u128 r4 = (u128)f[0] * g[4] + (u128)f[1] * g[3] + (u128)f[2] * g[2] +
	          (u128)f[3] * g[1] + (u128)f[4] * g[0];

	uint64_t c;
	h[0] = (uint64_t)r0 & kMask51;
	c = (uint64_t)(r0 >> 51);
	r1 += c;
	h[1] = (uint64_t)r1 & kMask51;
	c = (uint64_t)(r1 >> 51);
	r2 += c;
	h[2] = (uint64_t)r2 & kMask51;
	c = (uint64_t)(r2 >> 51);
	r3 += c;
	h[3] = (uint64_t)r3 & kMask51;
	c = (uint64_t)(r3 >> 51);
	r4 += c;
	h[4] = (uint64_t)r4 & kMask51;
	c = (uint64_t)(r4 >> 51);

	h[0] += c * 19;
	c = h[0] >> 51;
	h[0] &= kMask51;
	h[1] += c;
	c = h[1] >> 51;
	h[1] &= kMask51;
	h[2] += c;
}

static void fe_sq(fe h, const fe f)
{
	fe_mul(h, f, f);
}

static void fe_neg(fe h, const fe f)
{
	fe zero;
	fe_0(zero);
	fe_sub(h, zero, f);
}

/* fe_cmov sets f to g when b is 1, in constant time. */
static void fe_cmov(fe f, const fe g, uint64_t b)
{
	uint64_t mask = (uint64_t)0 - b;
	for (int i = 0; i < 5; i++)
		f[i] ^= mask & (f[i] ^ g[i]);
}

static void fe_from_bytes(fe h, const uint8_t s[32])
{
	uint64_t w[4];
	for (size_t i = 0; i < 4; i++) {
		uint64_t v = 0;
		for (size_t j = 8; j-- > 0;)
			v = (v << 8) | s[i * 8 + j];
		w[i] = v;
	}
	h[0] = w[0] & kMask51;
	h[1] = ((w[0] >> 51) | (w[1] << 13)) & kMask51;
	h[2] = ((w[1] >> 38) | (w[2] << 26)) & kMask51;
	h[3] = ((w[2] >> 25) | (w[3] << 39)) & kMask51;
	/* The top bit of the last byte is not part of the field element: in an
	 * Ed25519 point encoding it carries the sign of x. */
	h[4] = (w[3] >> 12) & kMask51;
}

/* fe_to_bytes writes the fully reduced canonical encoding. */
static void fe_to_bytes(uint8_t s[32], const fe f)
{
	fe t;
	fe_copy(t, f);
	fe_carry(t);

	/* One conditional subtraction of p, which is enough and provably so:
	 * fe_carry leaves every limb below 2^51 except possibly limb 1, which
	 * can reach 2^51 exactly, so t < 2^255 + 2^51 -- comfortably under
	 * 2p = 2^256 - 38. A second pass was here until a mutation test showed
	 * nothing could tell whether it ran, which is the definition of code
	 * nobody is checking. */
	{
		uint64_t q = (t[0] + 19) >> 51;
		q = (t[1] + q) >> 51;
		q = (t[2] + q) >> 51;
		q = (t[3] + q) >> 51;
		q = (t[4] + q) >> 51;
		t[0] += 19 * q;
		uint64_t c = t[0] >> 51;
		t[0] &= kMask51;
		t[1] += c;
		c = t[1] >> 51;
		t[1] &= kMask51;
		t[2] += c;
		c = t[2] >> 51;
		t[2] &= kMask51;
		t[3] += c;
		c = t[3] >> 51;
		t[3] &= kMask51;
		t[4] += c;
		t[4] &= kMask51;
	}

	uint64_t w0 = t[0] | (t[1] << 51);
	uint64_t w1 = (t[1] >> 13) | (t[2] << 38);
	uint64_t w2 = (t[2] >> 26) | (t[3] << 25);
	uint64_t w3 = (t[3] >> 39) | (t[4] << 12);
	uint64_t w[4] = { w0, w1, w2, w3 };
	for (size_t i = 0; i < 4; i++)
		for (size_t j = 0; j < 8; j++)
			s[i * 8 + j] = (uint8_t)(w[i] >> (8 * j));
}

static bool fe_is_zero(const fe f)
{
	uint8_t s[32];
	fe_to_bytes(s, f);
	uint8_t acc = 0;
	for (int i = 0; i < 32; i++)
		acc |= s[i];
	return acc == 0;
}

static bool fe_is_negative(const fe f)
{
	uint8_t s[32];
	fe_to_bytes(s, f);
	return (s[0] & 1) != 0;
}

static bool fe_equal(const fe a, const fe b)
{
	uint8_t x[32], y[32];
	fe_to_bytes(x, a);
	fe_to_bytes(y, b);
	return tc_ct_equal(x, y, 32);
}

/* fe_pow22523 computes f^((p-5)/8), the exponent the square root needs. */
static void fe_pow22523(fe out, const fe z)
{
	fe t0, t1, t2;
	int i;

	fe_sq(t0, z);
	fe_sq(t1, t0);
	fe_sq(t1, t1);
	fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 1; i < 5; i++)
		fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 1; i < 10; i++)
		fe_sq(t1, t1);
	fe_mul(t1, t1, t0);
	fe_sq(t2, t1);
	for (i = 1; i < 20; i++)
		fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	fe_sq(t1, t1);
	for (i = 1; i < 10; i++)
		fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 1; i < 50; i++)
		fe_sq(t1, t1);
	fe_mul(t1, t1, t0);
	fe_sq(t2, t1);
	for (i = 1; i < 100; i++)
		fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	fe_sq(t1, t1);
	for (i = 1; i < 50; i++)
		fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t0, t0);
	fe_sq(t0, t0);
	fe_mul(out, t0, z);
}

/* fe_invert computes f^(p-2), which is 1/f for non-zero f. */
static void fe_invert(fe out, const fe z)
{
	fe t0, t1, t2, t3;
	int i;

	fe_sq(t0, z);
	fe_sq(t1, t0);
	fe_sq(t1, t1);
	fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t2, t0);
	fe_mul(t1, t1, t2);
	fe_sq(t2, t1);
	for (i = 1; i < 5; i++)
		fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	fe_sq(t2, t1);
	for (i = 1; i < 10; i++)
		fe_sq(t2, t2);
	fe_mul(t2, t2, t1);
	fe_sq(t3, t2);
	for (i = 1; i < 20; i++)
		fe_sq(t3, t3);
	fe_mul(t2, t3, t2);
	fe_sq(t2, t2);
	for (i = 1; i < 10; i++)
		fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	fe_sq(t2, t1);
	for (i = 1; i < 50; i++)
		fe_sq(t2, t2);
	fe_mul(t2, t2, t1);
	fe_sq(t3, t2);
	for (i = 1; i < 100; i++)
		fe_sq(t3, t3);
	fe_mul(t2, t3, t2);
	fe_sq(t2, t2);
	for (i = 1; i < 50; i++)
		fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	fe_sq(t1, t1);
	for (i = 1; i < 5; i++)
		fe_sq(t1, t1);
	fe_mul(out, t1, t0);
}

/* ---- ge: points on -x^2 + y^2 = 1 + d x^2 y^2 ---------------------------
 *
 * Extended coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z and XY = ZT.
 */

typedef struct {
	fe X, Y, Z, T;
} ge;

/* d = -121665/121666, and 2d, as field elements. */
static const fe kD = { 929955233495203ULL, 466365720129213ULL,
	                   1662059464998953ULL, 2033849074728123ULL,
	                   1442794654840575ULL };
static const fe kD2 = { 1859910466990425ULL, 932731440258426ULL,
	                    1072319116312658ULL, 1815898335770999ULL,
	                    633789495995903ULL };
/* sqrt(-1), needed to recover x from y. */
static const fe kSqrtM1 = { 1718705420411056ULL, 234908883556509ULL,
	                        2233514472574048ULL, 2117202627021982ULL,
	                        765476049583133ULL };

/* The base point B. */
static const fe kBx = { 1738742601995546ULL, 1146398526822698ULL,
	                    2070867633025821ULL, 562264141797630ULL,
	                    587772402128613ULL };
static const fe kBy = { 1801439850948184ULL, 1351079888211148ULL,
	                    450359962737049ULL, 900719925474099ULL,
	                    1801439850948198ULL };

static void ge_zero(ge *p)
{
	fe_0(p->X);
	fe_1(p->Y);
	fe_1(p->Z);
	fe_0(p->T);
}

static void ge_base(ge *p)
{
	fe_copy(p->X, kBx);
	fe_copy(p->Y, kBy);
	fe_1(p->Z);
	fe_mul(p->T, kBx, kBy);
}

/* ge_add is the unified extended-coordinate addition. Unified matters: it is
 * correct when the two points are equal, so there is no doubling special case
 * to branch on and therefore none to leak. */
static void ge_add(ge *r, const ge *p, const ge *q)
{
	fe a, b, c, d, e, f, g, h, t;

	fe_sub(a, p->Y, p->X);
	fe_carry(a);
	fe_sub(t, q->Y, q->X);
	fe_carry(t);
	fe_mul(a, a, t);

	fe_add(b, p->Y, p->X);
	fe_carry(b);
	fe_add(t, q->Y, q->X);
	fe_carry(t);
	fe_mul(b, b, t);

	fe_mul(c, p->T, q->T);
	fe_mul(c, c, kD2);

	fe_mul(d, p->Z, q->Z);
	fe_add(d, d, d);
	fe_carry(d);

	fe_sub(e, b, a);
	fe_carry(e);
	fe_sub(f, d, c);
	fe_carry(f);
	fe_add(g, d, c);
	fe_carry(g);
	fe_add(h, b, a);
	fe_carry(h);

	fe_mul(r->X, e, f);
	fe_mul(r->Y, g, h);
	fe_mul(r->T, e, h);
	fe_mul(r->Z, f, g);
}

static void ge_double(ge *r, const ge *p)
{
	ge_add(r, p, p);
}

static void ge_cmov(ge *r, const ge *p, uint64_t b)
{
	fe_cmov(r->X, p->X, b);
	fe_cmov(r->Y, p->Y, b);
	fe_cmov(r->Z, p->Z, b);
	fe_cmov(r->T, p->T, b);
}

static void ge_neg(ge *r, const ge *p)
{
	fe_neg(r->X, p->X);
	fe_carry(r->X);
	fe_copy(r->Y, p->Y);
	fe_copy(r->Z, p->Z);
	fe_neg(r->T, p->T);
	fe_carry(r->T);
}

/* ge_scalarmult computes r = k*p in constant time.
 *
 * Double-and-add with a conditional add on *every* bit, so the sequence of
 * operations does not depend on the scalar. Slower than a windowed method and
 * far shorter; signing happens a handful of times per connection, so the
 * trade is not close. */
static void ge_scalarmult(ge *r, const uint8_t k[32], const ge *p)
{
	ge acc, sum;
	ge_zero(&acc);

	for (int i = 255; i >= 0; i--) {
		ge_double(&acc, &acc);
		ge_add(&sum, &acc, p);
		uint64_t bit = (k[i >> 3] >> (i & 7)) & 1;
		ge_cmov(&acc, &sum, bit);
	}
	*r = acc;
}

static void ge_scalarmult_base(ge *r, const uint8_t k[32])
{
	ge b;
	ge_base(&b);
	ge_scalarmult(r, k, &b);
}

static void ge_to_bytes(uint8_t s[32], const ge *p)
{
	fe recip, x, y;
	fe_invert(recip, p->Z);
	fe_mul(x, p->X, recip);
	fe_mul(y, p->Y, recip);
	fe_to_bytes(s, y);
	/* The sign of x rides in the top bit, which fe_to_bytes leaves clear. */
	s[31] = (uint8_t)(s[31] ^ (fe_is_negative(x) ? 0x80 : 0x00));
}

/* ge_from_bytes decodes a compressed point, recovering x from y.
 *
 * Returns false for anything that is not a point. A decoder that invented one
 * would be a decoder that accepts attacker-chosen garbage as a public key. */
static bool ge_from_bytes(ge *p, const uint8_t s[32])
{
	fe u, v, v3, vxx, check, x, y;

	fe_from_bytes(y, s);

	/* x^2 = (y^2 - 1) / (d y^2 + 1) */
	fe_sq(u, y);
	fe_mul(v, u, kD);
	fe one;
	fe_1(one);
	fe_sub(u, u, one); /* u = y^2 - 1 */
	fe_carry(u);
	fe_add(v, v, one); /* v = d y^2 + 1 */
	fe_carry(v);

	fe_sq(v3, v);
	fe_mul(v3, v3, v); /* v^3 */
	fe_sq(x, v3);
	fe_mul(x, x, v);
	fe_mul(x, x, u); /* u v^7 */

	fe_pow22523(x, x);
	fe_mul(x, x, v3);
	fe_mul(x, x, u); /* x = u v^3 (u v^7)^((p-5)/8) */

	fe_sq(vxx, x);
	fe_mul(vxx, vxx, v);
	fe_sub(check, vxx, u);
	fe_carry(check);
	if (!fe_is_zero(check)) {
		fe_add(check, vxx, u);
		fe_carry(check);
		if (!fe_is_zero(check))
			return false; /* not a square: not a point */
		fe_mul(x, x, kSqrtM1);
	}

	/* The encoding's top bit says which root was meant. */
	bool want_neg = (s[31] >> 7) != 0;
	if (fe_is_negative(x) != want_neg) {
		fe_neg(x, x);
		fe_carry(x);
	}
	/* x = 0 has only one root, so a request for the negative one is a
	 * non-canonical encoding of the same point. Rejected, because two byte
	 * strings that mean one key is a way to make a fingerprint ambiguous. */
	if (want_neg && fe_is_zero(x))
		return false;

	fe_copy(p->X, x);
	fe_copy(p->Y, y);
	fe_1(p->Z);
	fe_mul(p->T, x, y);
	return true;
}

/* ---- sc: arithmetic modulo L --------------------------------------------
 *
 * L = 2^252 + 27742317777372353535851937790883648493, the order of the
 * subgroup the base point generates.
 *
 * Reduction is schoolbook long division by repeated shift and conditional
 * subtract: 512 bits down to 253 takes 260 rounds of a 512-bit compare and
 * subtract. A windowed Barrett reduction would be perhaps fifty times faster
 * and is where implementations of this go wrong; at a handful of signatures
 * per connection, obviously correct wins outright.
 */

/* L, little-endian across 8 32-bit limbs. */
static const uint32_t kL[8] = { 0x5cf5d3edU, 0x5812631aU, 0xa2f79cd6U,
	                            0x14def9deU, 0x00000000U, 0x00000000U,
	                            0x00000000U, 0x10000000U };

/* sc_sub_l subtracts L from a 16-limb value at limb offset `sh`, if that
 * leaves it non-negative. Returns whether it subtracted. */
static bool sc_try_sub(uint32_t v[16], const uint32_t sub[16])
{
	/* Compare first: a borrow out of the top means sub was larger. */
	uint64_t borrow = 0;
	uint32_t tmp[16];
	for (int i = 0; i < 16; i++) {
		uint64_t d = (uint64_t)v[i] - sub[i] - borrow;
		tmp[i] = (uint32_t)d;
		borrow = (d >> 63) & 1;
	}
	if (borrow != 0)
		return false;
	memcpy(v, tmp, sizeof tmp);
	return true;
}

static void sc_shift_left(uint32_t v[16])
{
	uint32_t carry = 0;
	for (int i = 0; i < 16; i++) {
		uint32_t next = v[i] >> 31;
		v[i] = (v[i] << 1) | carry;
		carry = next;
	}
}

/* sc_reduce reduces a 64-byte little-endian value modulo L, in place, leaving
 * the 32-byte result in the low half. */
static void sc_reduce(uint8_t s[64])
{
	uint32_t v[16], m[16];
	for (int i = 0; i < 16; i++) {
		v[i] = (uint32_t)s[4 * i] | ((uint32_t)s[4 * i + 1] << 8) |
		       ((uint32_t)s[4 * i + 2] << 16) |
		       ((uint32_t)s[4 * i + 3] << 24);
	}

	/* m = L shifted left until its top bit sits at the top of a 512-bit
	 * value. L is 253 bits, the input is at most 512, so the largest useful
	 * shift is 512 - 253 = 259 -- which puts L's top bit at index 511,
	 * exactly the last one there is. Shifting one further would push it out
	 * of the buffer and quietly divide by the wrong number. */
	memset(m, 0, sizeof m);
	for (int i = 0; i < 8; i++)
		m[i] = kL[i];
	for (int i = 0; i < 259; i++)
		sc_shift_left(m);

	/* 260 rounds: shifts 259 down to 0 inclusive. */
	for (int i = 0; i < 260; i++) {
		(void)sc_try_sub(v, m);
		/* Shift m right by one. */
		uint32_t carry = 0;
		for (int j = 15; j >= 0; j--) {
			uint32_t next = m[j] & 1;
			m[j] = (m[j] >> 1) | (carry << 31);
			carry = next;
		}
	}

	memset(s, 0, 64);
	for (int i = 0; i < 8; i++) {
		s[4 * i] = (uint8_t)v[i];
		s[4 * i + 1] = (uint8_t)(v[i] >> 8);
		s[4 * i + 2] = (uint8_t)(v[i] >> 16);
		s[4 * i + 3] = (uint8_t)(v[i] >> 24);
	}
}

/* sc_muladd computes s = (a*b + c) mod L, all 32-byte little-endian. */
static void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                      const uint8_t c[32])
{
	uint32_t av[8], bv[8];
	for (int i = 0; i < 8; i++) {
		av[i] = (uint32_t)a[4 * i] | ((uint32_t)a[4 * i + 1] << 8) |
		        ((uint32_t)a[4 * i + 2] << 16) |
		        ((uint32_t)a[4 * i + 3] << 24);
		bv[i] = (uint32_t)b[4 * i] | ((uint32_t)b[4 * i + 1] << 8) |
		        ((uint32_t)b[4 * i + 2] << 16) |
		        ((uint32_t)b[4 * i + 3] << 24);
	}

	uint64_t prod[16];
	memset(prod, 0, sizeof prod);
	for (int i = 0; i < 8; i++) {
		uint64_t carry = 0;
		for (int j = 0; j < 8; j++) {
			uint64_t t = prod[i + j] + (uint64_t)av[i] * bv[j] + carry;
			prod[i + j] = t & 0xffffffffULL;
			carry = t >> 32;
		}
		prod[i + 8] += carry;
	}

	uint8_t wide[64];
	memset(wide, 0, sizeof wide);
	for (int i = 0; i < 16; i++) {
		uint32_t w = (uint32_t)prod[i];
		wide[4 * i] = (uint8_t)w;
		wide[4 * i + 1] = (uint8_t)(w >> 8);
		wide[4 * i + 2] = (uint8_t)(w >> 16);
		wide[4 * i + 3] = (uint8_t)(w >> 24);
	}

	/* Add c before reducing: it is below L, so the sum still fits 512 bits. */
	uint32_t carry = 0;
	for (int i = 0; i < 8; i++) {
		uint32_t cw = (uint32_t)c[4 * i] | ((uint32_t)c[4 * i + 1] << 8) |
		              ((uint32_t)c[4 * i + 2] << 16) |
		              ((uint32_t)c[4 * i + 3] << 24);
		uint32_t ww = (uint32_t)wide[4 * i] |
		              ((uint32_t)wide[4 * i + 1] << 8) |
		              ((uint32_t)wide[4 * i + 2] << 16) |
		              ((uint32_t)wide[4 * i + 3] << 24);
		uint64_t t = (uint64_t)ww + cw + carry;
		uint32_t r = (uint32_t)t;
		carry = (uint32_t)(t >> 32);
		wide[4 * i] = (uint8_t)r;
		wide[4 * i + 1] = (uint8_t)(r >> 8);
		wide[4 * i + 2] = (uint8_t)(r >> 16);
		wide[4 * i + 3] = (uint8_t)(r >> 24);
	}
	for (int i = 8; i < 16 && carry != 0; i++) {
		uint32_t ww = (uint32_t)wide[4 * i] |
		              ((uint32_t)wide[4 * i + 1] << 8) |
		              ((uint32_t)wide[4 * i + 2] << 16) |
		              ((uint32_t)wide[4 * i + 3] << 24);
		uint64_t t = (uint64_t)ww + carry;
		uint32_t r = (uint32_t)t;
		carry = (uint32_t)(t >> 32);
		wide[4 * i] = (uint8_t)r;
		wide[4 * i + 1] = (uint8_t)(r >> 8);
		wide[4 * i + 2] = (uint8_t)(r >> 16);
		wide[4 * i + 3] = (uint8_t)(r >> 24);
	}

	sc_reduce(wide);
	memcpy(s, wide, 32);
}

/* sc_is_reduced reports whether a 32-byte scalar is below L. */
static bool sc_is_reduced(const uint8_t s[32])
{
	for (int i = 31; i >= 0; i--) {
		uint8_t lb = (uint8_t)(kL[i >> 2] >> (8 * (i & 3)));
		if (s[i] < lb)
			return true;
		if (s[i] > lb)
			return false;
	}
	return false; /* equal to L is not below it */
}

/* ---- the scheme --------------------------------------------------------- */

static void sha512(uint8_t out[64], const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen, const uint8_t *c,
                   size_t clen)
{
	mbedtls_sha512_context ctx;
	mbedtls_sha512_init(&ctx);
	(void)mbedtls_sha512_starts(&ctx, 0);
	if (alen > 0)
		(void)mbedtls_sha512_update(&ctx, a, alen);
	if (blen > 0)
		(void)mbedtls_sha512_update(&ctx, b, blen);
	if (clen > 0)
		(void)mbedtls_sha512_update(&ctx, c, clen);
	(void)mbedtls_sha512_finish(&ctx, out);
	mbedtls_sha512_free(&ctx);
}

/* expand derives the scalar and the nonce prefix from a seed. */
static void expand(uint8_t scalar[32], uint8_t prefix[32],
                   const uint8_t seed[32])
{
	uint8_t h[64];
	sha512(h, seed, 32, NULL, 0, NULL, 0);
	/* Clamped exactly as X25519 clamps: the low three bits cleared so the
	 * scalar is a multiple of the cofactor, bit 254 set so the leading bit
	 * is fixed, bit 255 cleared. */
	h[0] = (uint8_t)(h[0] & 248);
	h[31] = (uint8_t)((h[31] & 127) | 64);
	memcpy(scalar, h, 32);
	memcpy(prefix, h + 32, 32);
	tc_memzero_explicit(h, sizeof h);
}

int tc_ed25519_public_from_seed(uint8_t out_pub[TC_ED25519_PUBLIC_LEN],
                                const uint8_t seed[TC_ED25519_SEED_LEN])
{
	if (out_pub == NULL || seed == NULL)
		return TC_ERR_INVAL;

	uint8_t scalar[32], prefix[32];
	expand(scalar, prefix, seed);

	ge A;
	ge_scalarmult_base(&A, scalar);
	ge_to_bytes(out_pub, &A);

	tc_memzero_explicit(scalar, sizeof scalar);
	tc_memzero_explicit(prefix, sizeof prefix);
	return TC_OK;
}

int tc_ed25519_keypair(uint8_t out_seed[TC_ED25519_SEED_LEN],
                       uint8_t out_pub[TC_ED25519_PUBLIC_LEN])
{
	if (out_seed == NULL || out_pub == NULL)
		return TC_ERR_INVAL;
	if (tc_random_bytes(out_seed, TC_ED25519_SEED_LEN) != TC_OK)
		return TC_ERR_INVAL;
	return tc_ed25519_public_from_seed(out_pub, out_seed);
}

int tc_ed25519_sign(uint8_t out_sig[TC_ED25519_SIGNATURE_LEN],
                    const uint8_t seed[TC_ED25519_SEED_LEN],
                    const uint8_t pub[TC_ED25519_PUBLIC_LEN], const void *msg,
                    size_t msg_len)
{
	if (out_sig == NULL || seed == NULL || pub == NULL ||
	    (msg == NULL && msg_len > 0))
		return TC_ERR_INVAL;

	uint8_t scalar[32], prefix[32];
	expand(scalar, prefix, seed);

	/* r = H(prefix || M) mod L. The nonce is a function of the message and a
	 * secret, never of randomness -- so there is no RNG to fail and no way
	 * for two signatures to share one. */
	uint8_t hr[64];
	sha512(hr, prefix, 32, (const uint8_t *)msg, msg_len, NULL, 0);
	sc_reduce(hr);
	uint8_t r[32];
	memcpy(r, hr, 32);

	ge R;
	ge_scalarmult_base(&R, r);
	uint8_t Rbytes[32];
	ge_to_bytes(Rbytes, &R);

	/* k = H(R || A || M) mod L */
	uint8_t hk[64];
	sha512(hk, Rbytes, 32, pub, 32, (const uint8_t *)msg, msg_len);
	sc_reduce(hk);

	uint8_t S[32];
	sc_muladd(S, hk, scalar, r);

	memcpy(out_sig, Rbytes, 32);
	memcpy(out_sig + 32, S, 32);

	tc_memzero_explicit(scalar, sizeof scalar);
	tc_memzero_explicit(prefix, sizeof prefix);
	tc_memzero_explicit(hr, sizeof hr);
	tc_memzero_explicit(hk, sizeof hk);
	tc_memzero_explicit(r, sizeof r);
	tc_memzero_explicit(S, sizeof S);
	return TC_OK;
}

int tc_ed25519_verify(const uint8_t sig[TC_ED25519_SIGNATURE_LEN],
                      const uint8_t pub[TC_ED25519_PUBLIC_LEN],
                      const void *msg, size_t msg_len)
{
	if (sig == NULL || pub == NULL || (msg == NULL && msg_len > 0))
		return TC_ERR_INVAL;

	/* S must be canonically reduced. Without this a signature can be mauled
	 * into a different byte string that still verifies, which breaks
	 * anything that treats the signature bytes as an identifier. */
	if (!sc_is_reduced(sig + 32))
		return TC_ERR_INVAL;

	ge A;
	if (!ge_from_bytes(&A, pub))
		return TC_ERR_INVAL;
	/* A is used as -A below, because the check is [S]B - [k]A = R. */
	ge minusA;
	ge_neg(&minusA, &A);

	ge Rexpected;
	if (!ge_from_bytes(&Rexpected, sig))
		return TC_ERR_INVAL;

	uint8_t hk[64];
	sha512(hk, sig, 32, pub, 32, (const uint8_t *)msg, msg_len);
	sc_reduce(hk);

	ge sB, kA, sum;
	ge_scalarmult_base(&sB, sig + 32);
	ge_scalarmult(&kA, hk, &minusA);
	ge_add(&sum, &sB, &kA);

	/* Compared projectively rather than by encoding both: x1/z1 == x2/z2 is
	 * x1 z2 == x2 z1, which avoids two inversions and, more to the point,
	 * avoids caring whether the two happen to share a Z. */
	fe c1, c2;
	fe_mul(c1, sum.X, Rexpected.Z);
	fe_mul(c2, Rexpected.X, sum.Z);
	bool ok = fe_equal(c1, c2);
	fe_mul(c1, sum.Y, Rexpected.Z);
	fe_mul(c2, Rexpected.Y, sum.Z);
	ok = ok && fe_equal(c1, c2);

	return ok ? TC_OK : TC_ERR_INVAL;
}
