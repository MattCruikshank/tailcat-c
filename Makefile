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

# Objects from two toolchains cannot share a directory. cosmocc emits a paired
# object in a sibling .aarch64/ directory beside each one, and a host-gcc
# object of the same name leaves that pair half-missing -- which surfaces much
# later as "linker input missing concomitant ... .aarch64/foo.o", an error that
# says nothing about the actual cause. Key the directory by toolchain so
# `make` and `make CC=gcc` can coexist without an explicit clean in between.
ifeq ($(findstring cosmocc,$(CC)),cosmocc)
BUILD := $(BUILD)/cosmo
else
BUILD := $(BUILD)/host
endif

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
	$(MBEDTLS_DIR)/library/error.c \
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
	$(MBEDTLS_DIR)/library/ecdh.c \
	$(MBEDTLS_DIR)/library/ecdsa.c \
	$(MBEDTLS_DIR)/library/sha512.c \
	$(MBEDTLS_DIR)/library/gcm.c \
	$(MBEDTLS_DIR)/library/cipher.c \
	$(MBEDTLS_DIR)/library/cipher_wrap.c \
	$(MBEDTLS_DIR)/library/base64.c \
	$(MBEDTLS_DIR)/library/pem.c \
	$(MBEDTLS_DIR)/library/asn1parse.c \
	$(MBEDTLS_DIR)/library/asn1write.c \
	$(MBEDTLS_DIR)/library/oid.c \
	$(MBEDTLS_DIR)/library/rsa.c \
	$(MBEDTLS_DIR)/library/rsa_alt_helpers.c \
	$(MBEDTLS_DIR)/library/pk.c \
	$(MBEDTLS_DIR)/library/pk_wrap.c \
	$(MBEDTLS_DIR)/library/pk_ecc.c \
	$(MBEDTLS_DIR)/library/pkparse.c \
	$(MBEDTLS_DIR)/library/x509.c \
	$(MBEDTLS_DIR)/library/x509_crt.c \
	$(MBEDTLS_DIR)/library/ssl_ciphersuites.c \
	$(MBEDTLS_DIR)/library/ssl_client.c \
	$(MBEDTLS_DIR)/library/ssl_msg.c \
	$(MBEDTLS_DIR)/library/ssl_tls.c \
	$(MBEDTLS_DIR)/library/ssl_tls12_client.c

MBEDTLS_OBJS := $(MBEDTLS_SRCS:%.c=$(BUILD)/%.o)

# -isystem, not -I: Mbed TLS's public headers do not compile warning-free
# under our warning set (redundant redeclarations, undefined macros in #if).
# Treating them as system headers suppresses that without weakening the
# warnings that apply to our own code. third_party keeps -I because
# mbedtls_config.h there is ours.
MBEDTLS_INC := -isystem $(MBEDTLS_DIR)/include -Ithird_party
MBEDTLS_DEF := -DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>'

# gnu11 rather than c11: strict ISO mode makes glibc hide the POSIX
# networking declarations (struct addrinfo, getaddrinfo), which the DERP
# transport needs. -Wpedantic stays on, so our own code is still held to ISO
# C -- this only exposes the platform headers we are entitled to.
CFLAGS ?= -std=gnu11 -O2 -g
CFLAGS += $(WARNINGS) $(HARDENING) -Iinclude $(MBEDTLS_INC) $(MBEDTLS_DEF)

# Third-party code is not held to our warning set; -w here keeps a real
# warning in our own code from being lost in Mbed TLS's output.
MBEDTLS_CFLAGS := -std=gnu11 -O2 -g -w $(HARDENING) $(MBEDTLS_INC) $(MBEDTLS_DEF)

ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
MBEDTLS_CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

LIB_SRCS := \
	src/tc.c \
	src/base64url.c \
	src/cbor.c \
	src/json.c \
	src/addr.c \
	src/crypto/blake2s.c \
	src/crypto/kdf.c \
	src/crypto/x25519.c \
	src/crypto/aead.c \
	src/crypto/salsa20.c \
	src/crypto/random.c \
	src/wg/noise.c \
	src/tailcat/meow.c \
	src/derp/frame.c \
	src/derp/client.c \
	src/derp/derpmap.c \
	src/net/tcp.c \
	src/net/http.c \
	src/net/tls.c \
	src/net/ca_bundle.c

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o) $(MBEDTLS_OBJS)

CLI := $(BUILD)/tailcat-c

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/test_%.c=$(BUILD)/test_%)

.PHONY: all test clean check-fat fuzz interop live live-wg live-tailcat live-cli
all: $(CLI)

$(CLI): src/cli/main.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) src/cli/main.c $(LIB_OBJS) $(LDFLAGS) -o $@

$(BUILD)/$(MBEDTLS_DIR)/%.o: $(MBEDTLS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(MBEDTLS_CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_%: tests/test_%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests $< $(LIB_OBJS) $(LDFLAGS) -o $@

test: $(TEST_BINS) $(CLI) check-fat
	@fail=0; for t in $(TEST_BINS); do ./$$t || fail=1; done; exit $$fail

# Only meaningful for cosmocc output; skipped for host-compiler builds.
check-fat: $(TEST_BINS) $(CLI)
ifeq ($(findstring cosmocc,$(CC)),cosmocc)
	@sh scripts/check-fat.sh $(TEST_BINS) $(CLI)
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
FUZZ_CC := gcc -std=gnu11 -O1 -g

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

# Live interoperability check against a real DERP relay. Kept out of `make
# test` on purpose: that has to pass offline and must not depend on someone
# else's server being up.
LIVE_HOST ?=
$(BUILD)/livederp: tests/livederp.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/livederp.c $(LIB_OBJS) $(LDFLAGS) -o $@

live: $(BUILD)/livederp
	./$(BUILD)/livederp $(LIVE_HOST)

# Interop against a real wireguard-go device. Like `live`, this is kept out of
# `make test`: it spawns a Go process and binds a UDP port.
$(BUILD)/livewg: tests/livewg.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/livewg.c $(LIB_OBJS) $(LDFLAGS) -o $@

live-wg: $(BUILD)/livewg
	LIVEWG=$(BUILD)/livewg sh scripts/live-wg.sh

# End-to-end against a real tailcat server: address, relay, meow, handshake.
$(BUILD)/livetailcat: tests/livetailcat.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/livetailcat.c $(LIB_OBJS) $(LDFLAGS) -o $@

live-cli: $(CLI)
	CLI=$(CLI) sh scripts/live-cli.sh

live-tailcat: $(BUILD)/livetailcat
	LIVETC=$(BUILD)/livetailcat sh scripts/live-tailcat.sh

clean:
	rm -rf build
