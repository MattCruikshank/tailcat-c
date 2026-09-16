# SPDX-License-Identifier: BSD-3-Clause
#
# tailcat-c -- builds with the Cosmopolitan C compiler into a single
# Actually Portable Executable that runs on Linux, macOS, Windows, FreeBSD,
# OpenBSD and NetBSD, on x86_64 and aarch64.
#
#   make            build the library and CLI
#   make test       build and run the unit tests
#   make clean
#
# Override CC to build with a host compiler instead (useful for sanitizers):
#   make CC=gcc SANITIZE=1 test

COSMOCC ?= $(HOME)/cosmocc/bin/cosmocc

# CC is a make builtin with a default of "cc", so "CC ?=" would silently do
# nothing and we would quietly build with the host compiler instead of
# cosmocc -- which defeats the entire point. Only override it when the value
# is make's own default, so an explicit "make CC=gcc" still wins.
ifeq ($(origin CC),default)
CC := $(COSMOCC)
endif

BUILD ?= build

# -Wconversion is deliberately on: this code parses attacker-controlled bytes
# and silent integer narrowing is exactly the bug class we care about.
WARNINGS := \
	-Wall -Wextra -Wpedantic -Wshadow -Wvla -Wundef -Wformat=2 \
	-Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls \
	-Wpointer-arith -Wwrite-strings -Wcast-qual -Wconversion \
	-Wsign-conversion -Wdouble-promotion

# Stack protection is NOT usable in a fat Cosmopolitan build, and we keep the
# fat build. Measured against cosmocc 14.1.0:
#   - aarch64 has no __stack_chk_guard at all, so any -fstack-protector-*
#     flag fails to link the aarch64 half;
#   - supplying that symbol ourselves makes it link, but the x86_64 binary
#     then segfaults, because cosmo only defines the guard in its -mtiny
#     runtime, not the default one.
# So it is off for cosmocc and on for host builds, which is where the
# sanitizer and fuzz targets run anyway.
#
# Do not add -moptlinux or -mtinylinux here either: both make the output
# Linux-only, which defeats the purpose.
HARDENING := -fno-common -D_FORTIFY_SOURCE=2
ifeq ($(findstring cosmocc,$(CC)),)
HARDENING += -fstack-protector-strong
endif

# Mbed TLS supplies X25519, ChaCha20-Poly1305 and the CSPRNG. It is a pinned
# submodule; third_party/mbedtls_config.h trims it to just those, which keeps
# code we never call out of the binary and out of the attack surface.
#
# Its sources are listed explicitly rather than globbed, so that adding a
# dependency is a visible change rather than something a wildcard picks up.
MBEDTLS_DIR := third_party/mbedtls
MBEDTLS_SRCS := \
	$(MBEDTLS_DIR)/library/platform.c \
	$(MBEDTLS_DIR)/library/platform_util.c \
	$(MBEDTLS_DIR)/library/constant_time.c \
	$(MBEDTLS_DIR)/library/chacha20.c \
	$(MBEDTLS_DIR)/library/poly1305.c \
	$(MBEDTLS_DIR)/library/chachapoly.c \
	$(MBEDTLS_DIR)/library/aes.c \
	$(MBEDTLS_DIR)/library/md.c \
	$(MBEDTLS_DIR)/library/sha256.c \
	$(MBEDTLS_DIR)/library/entropy.c \
	$(MBEDTLS_DIR)/library/entropy_poll.c \
	$(MBEDTLS_DIR)/library/ctr_drbg.c \
	$(MBEDTLS_DIR)/library/bignum.c \
	$(MBEDTLS_DIR)/library/bignum_core.c \
	$(MBEDTLS_DIR)/library/ecp.c \
	$(MBEDTLS_DIR)/library/ecp_curves.c \
	$(MBEDTLS_DIR)/library/ecdh.c

MBEDTLS_OBJS := $(MBEDTLS_SRCS:%.c=$(BUILD)/%.o)

MBEDTLS_INC := -I$(MBEDTLS_DIR)/include -Ithird_party
MBEDTLS_DEF := -DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>'

CFLAGS ?= -std=c11 -O2 -g
CFLAGS += $(WARNINGS) $(HARDENING) -Iinclude $(MBEDTLS_INC) $(MBEDTLS_DEF)

# Third-party code is not held to our warning set; -w here keeps a real
# warning in our own code from being lost in Mbed TLS's output.
MBEDTLS_CFLAGS := -std=c11 -O2 -g -w $(HARDENING) $(MBEDTLS_INC) $(MBEDTLS_DEF)

ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
MBEDTLS_CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

LIB_SRCS := \
	src/tc.c \
	src/base64url.c \
	src/cbor.c \
	src/addr.c \
	src/crypto/blake2s.c \
	src/crypto/kdf.c \
	src/crypto/x25519.c \
	src/crypto/aead.c \
	src/crypto/random.c

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o) $(MBEDTLS_OBJS)

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/test_%.c=$(BUILD)/test_%)

.PHONY: all test clean check-fat fuzz interop
all: $(LIB_OBJS)

$(BUILD)/$(MBEDTLS_DIR)/%.o: $(MBEDTLS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(MBEDTLS_CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_%: tests/test_%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests $< $(LIB_OBJS) $(LDFLAGS) -o $@

test: $(TEST_BINS) check-fat
	@fail=0; for t in $(TEST_BINS); do ./$$t || fail=1; done; exit $$fail

# Only meaningful for cosmocc output; skipped for host-compiler builds.
check-fat: $(TEST_BINS)
ifeq ($(findstring cosmocc,$(CC)),cosmocc)
	@sh scripts/check-fat.sh $(TEST_BINS)
else
	@echo "check-fat: skipped (CC=$(CC) is not cosmocc)"
endif

# Fuzz the address parser, which is the only code that sees attacker
# controlled bytes before any authentication. Built with the host compiler
# and sanitizers on purpose: cosmocc ships no libFuzzer and no ASan runtime,
# and a portable binary is not what we want for a crash hunt anyway.
FUZZ_ITERS ?= 200000
FUZZ_SAN := -fsanitize=address,undefined -fno-omit-frame-pointer \
	-fno-sanitize-recover=all
FUZZ_CC := gcc -std=c11 -O1 -g

# Mbed TLS is compiled separately so it can be built with -w: it is not held
# to our warning set, and a real warning in our code must not be lost in it.
# These objects are always gcc-built, unlike $(MBEDTLS_OBJS), which follow CC.
FUZZ_MBED_OBJS := $(MBEDTLS_SRCS:%.c=$(BUILD)/fuzzobj/%.o)

# Without this, make treats these as intermediates of the pattern rule and
# deletes them after every run, rebuilding all of Mbed TLS each time.
.SECONDARY: $(FUZZ_MBED_OBJS)

$(BUILD)/fuzzobj/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) -w $(MBEDTLS_INC) $(MBEDTLS_DEF) $(FUZZ_SAN) -c $< -o $@

$(BUILD)/fuzz_%: tests/fuzz_%.c $(LIB_SRCS) $(FUZZ_MBED_OBJS)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(WARNINGS) -Iinclude $(MBEDTLS_INC) $(MBEDTLS_DEF) $(FUZZ_SAN) \
		$< $(LIB_SRCS) $(FUZZ_MBED_OBJS) -o $@

FUZZ_BINS := $(patsubst tests/%.c,$(BUILD)/%,$(wildcard tests/fuzz_*.c))

fuzz: $(FUZZ_BINS)
	@fail=0; for f in $(FUZZ_BINS); do ./$$f $(FUZZ_ITERS) || fail=1; done; \
		exit $$fail

# Cross-check against the real Go implementation: generate addresses with the
# upstream tailcat library and require our parse/encode round trip to
# reproduce each one byte for byte.
INTEROP_COUNT ?= 2000
$(BUILD)/crosscheck: tests/crosscheck.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/crosscheck.c $(LIB_OBJS) $(LDFLAGS) -o $@

interop: $(BUILD)/crosscheck
	cd tools/genaddrs && GOFLAGS=-mod=mod go run . -count $(INTEROP_COUNT) \
		| ../../$(BUILD)/crosscheck

clean:
	rm -rf $(BUILD)
