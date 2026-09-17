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
# -fno-sanitize-recover matters: UndefinedBehaviorSanitizer otherwise prints a
# diagnostic and carries on, so a finding scrolls past in a run that still
# reports every suite as passing. It found exactly one that way.
SAN := -fsanitize=address,undefined -fno-omit-frame-pointer \
	-fno-sanitize-recover=all
CFLAGS += $(SAN)
MBEDTLS_CFLAGS += $(SAN)

# A hook for one-off builds, because overriding CFLAGS wholesale on the
# command line silently discards the include paths and the warning set.
#
# Its first use is the cheapest possible test of the aarch64 half: plain
# `char` is signed on cosmo's x86_64 and *unsigned* on its aarch64, so
# `EXTRA_CFLAGS=-funsigned-char` runs the whole suite under the other half's
# character semantics without an emulator. See `make test-unsigned-char`.
CFLAGS += $(EXTRA_CFLAGS)
MBEDTLS_CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS += $(SAN)
endif

LIB_SRCS := \
	src/tc.c \
	src/base64url.c \
	src/cbor.c \
	src/endpoint.c \
	src/allowlist.c \
	src/portset.c \
	src/fwdspec.c \
	src/shquote.c \
	src/browser.c \
	src/keyfile.c \
	src/json.c \
	src/addr.c \
	src/crypto/blake2s.c \
	src/crypto/kdf.c \
	src/crypto/x25519.c \
	src/crypto/ed25519.c \
	src/crypto/aead.c \
	src/crypto/salsa20.c \
	src/crypto/random.c \
	src/wg/noise.c \
	src/wg/peer.c \
	src/tailcat/meow.c \
	src/derp/frame.c \
	src/derp/client.c \
	src/derp/derpmap.c \
	src/net/stun.c \
	src/net/udp.c \
	src/net/disco.c \
	src/net/netcheck.c \
	src/net/path.c \
	src/net/tcp.c \
	src/net/tcpmux.c \
	src/net/udpmux.c \
	src/net/nat64.c \
	src/net/socks.c \
	src/net/proxy.c \
	src/net/http.c \
	src/net/tls.c \
	src/net/ca_bundle.c \
	src/usage_text.c \
	src/ssh/wire.c \
	src/ssh/packet.c \
	src/ssh/kex.c \
	src/ssh/auth.c \
	src/ssh/channel.c \
	src/ssh/server.c \
	src/ssh/sftp.c \
	src/ssh/dropbox.c \
	src/ssh/client.c

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o) $(MBEDTLS_OBJS)

CLI := $(BUILD)/tailcat-c

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/test_%.c=$(BUILD)/test_%)

.PHONY: all usage-text test clean check-fat fuzz interop live live-wg live-tailcat live-cli live-serve live-rekey live-serve-ports live-multi live-forward live-browse live-ssh live-recv live-genkey live-stun live-netcheck live-direct live-exitnode live-allow live-socksudp live-sshd live-sshloop live-dropbox live-recv-serve live-ls diag1 diag3 diag5 test-unsigned-char test-aarch64
all: $(CLI)

# doc/usage.md is the source for src/usage_text.c, which is committed so that
# a build needs no Python. Deliberately not a prerequisite of the object file:
# a checkout sets mtimes in whatever order it likes, and a build graph that
# can decide to shell out to python3 is one that breaks on a machine without
# it. Regenerate by hand; level 1 fails if the two have drifted apart.
#
# It lives below `all` because make takes the first non-special target in
# the file as its default goal, and a rule placed above `all` silently
# becomes what a bare `make` does.
usage-text:
	python3 scripts/gen-usage.py


$(CLI): src/cli/main.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) src/cli/main.c $(LIB_OBJS) $(LDFLAGS) -o $@

# Header dependency tracking. Without it, editing a header rebuilds nothing,
# and an object compiled against an older definition of a struct is linked
# against one compiled against the newer -- which is not a link error, just a
# program where two files disagree about where the fields are. Adding one
# member to tc_stream produced exactly that, and it surfaced as a stack
# overflow three call frames away from the change.
DEPFLAGS = -MMD -MP

# Named explicitly, because -MMD will not find it. Mbed TLS reaches our
# config through its own build_info.h, which arrives via -isystem and is
# therefore a system header -- and -MMD stops at system headers, so the
# dependency chain never reaches third_party/mbedtls_config.h. Editing the
# config then rebuilds nothing, and the objects that were already there stay
# compiled against the old options. Enabling TLS 1.3 produced exactly that: a
# link full of missing ARIA and Camellia symbols from a cipher_wrap.o built
# under a config that no longer existed.
$(BUILD)/$(MBEDTLS_DIR)/%.o: $(MBEDTLS_DIR)/%.c third_party/mbedtls_config.h
	@mkdir -p $(dir $@)
	$(CC) $(MBEDTLS_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/test_%: tests/test_%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests $< $(LIB_OBJS) $(LDFLAGS) -o $@

# Names what failed, at the end.
#
# The previous version set a flag and exited non-zero, which meant a failure
# inside a fifteen-minute diagnostic showed up as "Makefile:NNN: test Error 1"
# with the useful output scrolled past -- and a binary that died without
# printing left nothing at all. A summary that names the binary and its exit
# status is the difference between a bug report and a shrug.
test: $(TEST_BINS) $(CLI) check-fat
	@fail=""; \
	for t in $(TEST_BINS); do \
		./$$t || fail="$$fail $$t($$?)"; \
	done; \
	if [ -n "$$fail" ]; then \
		echo; \
		echo "FAILED test binaries:$$fail" >&2; \
		exit 1; \
	fi

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

# A real STUN binding exchange against Tailscale's DERP servers.
$(BUILD)/livestun: tests/livestun.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/livestun.c $(LIB_OBJS) $(LDFLAGS) -o $@

live-stun: $(BUILD)/livestun
	./$(BUILD)/livestun

# The aarch64 half's character semantics, on x86_64 hardware.
#
# `char` is signed on cosmo's x86_64 and unsigned on its aarch64, so any
# `c < 0` on a plain char means something different in the two halves of
# every fat binary we ship -- and only the x86_64 half has ever been
# executed. This is the cheapest way to exercise the difference: no
# emulator, no new toolchain, just the other signedness.
#
# It does not test aarch64 code generation, only our arithmetic. qemu is
# still the next step.
test-unsigned-char:
	$(MAKE) BUILD=build/uchar EXTRA_CFLAGS=-funsigned-char test

# And the aarch64 half itself, on real aarch64 instructions under qemu-user.
# Skips with a message saying what to install if qemu is not there.
test-aarch64: $(TEST_BINS)
	BUILD=$(BUILD) sh scripts/test-aarch64.sh

# A whole netcheck against the real relay list: that the servers answer, that
# the region called preferred really is the quickest, and that it is dialable
# and not merely quick to answer a probe.
$(BUILD)/livenetcheck: tests/livenetcheck.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/livenetcheck.c $(LIB_OBJS) $(LDFLAGS) -o $@

live-netcheck: $(BUILD)/livenetcheck
	./$(BUILD)/livenetcheck

# A tailcat-c client and a tailcat-c server finding a direct path between
# them, which is the half of Phase 4.4 a simulated network cannot check.
live-direct: $(CLI)
	CLI=$(CLI) sh scripts/live-direct.sh

# A client reaching a third address through an exit node, and a server that
# was not asked to be one refusing to.
live-exitnode: $(CLI)
	CLI=$(CLI) sh scripts/live-exitnode.sh

# A server refusing a client that is not on its --allow list, and admitting
# one that is, through a real relay.
live-allow: $(CLI)
	CLI=$(CLI) sh scripts/live-allow.sh

# SOCKS5 UDP ASSOCIATE carrying datagrams to two services at once.
live-socksudp: $(CLI)
	CLI=$(CLI) sh scripts/live-socksudp.sh

live-cli: $(CLI)
	CLI=$(CLI) sh scripts/live-cli.sh

# The other direction: a real Go client dialling our server, which is the only
# check that covers the passive open and the listener.
live-serve: $(CLI)
	CLI=$(CLI) sh scripts/live-serve.sh

# Slow on purpose: about six minutes, because it holds one session across
# WireGuard's 120-second rekey and 180-second expiry against the real Go
# server. Nothing faster can prove that rekeying interoperates.
live-rekey: $(CLI)
	CLI=$(CLI) sh scripts/live-rekey.sh

# `serve <ports>` proxying a real local service to the real Go client.
live-serve-ports: $(CLI)
	CLI=$(CLI) sh scripts/live-serve-ports.sh

# Several real Go clients through one server at the same time.
live-multi: $(CLI)
	CLI=$(CLI) sh scripts/live-multi.sh

# The other direction: our forward and socks reaching a real Go server.
live-forward: $(CLI)
	CLI=$(CLI) sh scripts/live-forward.sh

live-browse: $(CLI)
	CLI=$(CLI) sh scripts/live-browse.sh

# The system ssh and scp, driven through our tunnel to a real SSH server.
live-ssh: $(CLI)
	CLI=$(CLI) sh scripts/live-ssh.sh

# Our cp delivering into a real `tailcat recv` drop box.
live-recv: $(CLI)
	CLI=$(CLI) sh scripts/live-recv.sh

# A saved identity, shared between both implementations in both directions.
live-genkey: $(CLI)
	CLI=$(CLI) sh scripts/live-genkey.sh

$(BUILD)/livesshd: tests/livesshd.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests $< $(LIB_OBJS) $(LDFLAGS) -o $@

# One real OpenSSH client against our server. The only check that can tell
# whether the SSH subset speaks SSH rather than speaking to itself.
$(BUILD)/livesshcli: tests/livesshcli.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests $< $(LIB_OBJS) $(LDFLAGS) -o $@

# Our client against our server, over loopback. Needs no network; proves the
# client half exists, not that it interoperates -- see live-ls for that.
live-sshloop: $(BUILD)/livesshd $(BUILD)/livesshcli
	BUILD=$(BUILD) sh scripts/live-sshloop.sh

live-sshd: $(BUILD)/livesshd
	BUILD=$(BUILD) sh scripts/live-sshd.sh

# And the drop box, driven by a real scp and sftp. The refusals are the
# feature, so the checks are on the filesystem afterwards rather than on what
# the client printed.
live-dropbox: $(BUILD)/livesshd
	BUILD=$(BUILD) sh scripts/live-dropbox.sh

# And `recv` over a real tunnel. The only check that reaches the code where
# the SSH server's blocking reads drive the serve event loop.
live-recv-serve: $(CLI)
	BUILD=$(BUILD) sh scripts/live-recv-serve.sh

# Our SSH and SFTP clients against a real Go tailcat file server. The
# interoperability claim for the client half.
live-ls: $(CLI)
	BUILD=$(BUILD) sh scripts/live-ls.sh

live-tailcat: $(BUILD)/livetailcat
	LIVETC=$(BUILD)/livetailcat sh scripts/live-tailcat.sh

# Tiered local checks, numbered like Starfleet diagnostics: 1 is the one where
# you take the panels off, 5 is the quick sweep. scripts/diagnostic.sh has the
# details and times every stage it runs.
#
#   make diag5   seconds   did I just break the build
#   make diag3   minutes   both toolchains, sanitizers, fuzzing, crosscheck
#   make diag1   long      the above from a clean tree, plus every live test
#
# diag3 is what the pre-push hook runs. Install it once with:
#   git config core.hooksPath scripts/githooks
diag1 diag3 diag5:
	@sh scripts/diagnostic.sh $(patsubst diag%,%,$@)

# -include, not include: the files do not exist on a first build, and make
# must not treat that as an error.
-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

clean:
	rm -rf build
