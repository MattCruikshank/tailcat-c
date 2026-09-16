#!/bin/sh
# Run a make/shell command inside WSL with the Cosmopolitan APE loader usable.
#
# WSL registers a binfmt_misc handler ("WSLInterop") for any file starting with
# "MZ", which swallows Actually Portable Executables and hands them to Windows.
# cosmocc runs APE tools during its own build, so it fails outright until that
# handler is disabled and Cosmopolitan's loader is registered instead.
#
# binfmt_misc is per-WSL-instance kernel state and WSL tears the instance down
# when its last process exits, so the fix cannot be applied once up front -- it
# has to happen in the same invocation as the build. Hence this wrapper.
#
# Usage: scripts/wslmake.sh <shell command...>
set -eu

DISTRO="${TC_WSL_DISTRO:-Ubuntu}"
WSLUSER="${TC_WSL_USER:-$(wsl.exe -d "$DISTRO" -e sh -c 'echo $USER' | tr -d '\r')}"
PROJ="${TC_WSL_PROJ:-$(wsl.exe -d "$DISTRO" -e wslpath -a "$(pwd -W 2>/dev/null || pwd)" | tr -d '\r')}"

exec wsl.exe -d "$DISTRO" -u root -e sh -c '
  COSMO="/home/'"$WSLUSER"'/cosmocc"
  if [ -f "$COSMO/bin/ape-x86_64.elf" ]; then
    cp -f "$COSMO/bin/ape-x86_64.elf" /usr/bin/ape 2>/dev/null || true
    chmod 0755 /usr/bin/ape 2>/dev/null || true
  fi
  # Disable WSLInterop for this instance only; it comes back on next boot.
  [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && \
    echo -1 > /proc/sys/fs/binfmt_misc/WSLInterop 2>/dev/null || true
  [ -e /proc/sys/fs/binfmt_misc/APE ] || \
    echo ":APE:M::MZqFpD::/usr/bin/ape:" > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
  [ -e /proc/sys/fs/binfmt_misc/APE-jart ] || \
    echo ":APE-jart:M::jartsr::/usr/bin/ape:" > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
  exec runuser -u '"$WSLUSER"' -- bash -lc "cd '"$PROJ"' && $*"
' sh "$@"
