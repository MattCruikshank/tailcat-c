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

CFLAGS ?= -std=c11 -O2 -g
CFLAGS += $(WARNINGS) $(HARDENING) -Iinclude

ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

LIB_SRCS := \
	src/tc.c \
	src/base64url.c \
	src/cbor.c \
	src/addr.c

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o)

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/test_%.c=$(BUILD)/test_%)

.PHONY: all test clean check-fat fuzz interop
all: $(LIB_OBJS)

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
$(BUILD)/fuzz_addr: tests/fuzz_addr.c $(LIB_SRCS)
	@mkdir -p $(dir $@)
	gcc -std=c11 -O1 -g $(WARNINGS) -Iinclude \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-fno-sanitize-recover=all \
		tests/fuzz_addr.c $(LIB_SRCS) -o $@

fuzz: $(BUILD)/fuzz_addr
	./$(BUILD)/fuzz_addr $(FUZZ_ITERS)

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
