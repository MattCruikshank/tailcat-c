# Running the suite on a BSD, in qemu

A plan, not a record. Nothing here has been done yet.

## Why this, and why now

`README.md` claims six operating systems, and says plainly that four of them
are untested -- this is the plan for making that sentence shorter. Two have
ever run this code:
Linux and Windows. macOS, FreeBSD, OpenBSD and NetBSD are *built* — the fat
APE contains code for them and `check-fat` proves the binary is well-formed —
and that is the whole of the evidence.

Bugs 46 and 48 are why that stopped being an acceptable gap. Both were the
same mistake: asking a question about the machine in a way that only works on
the machine it was written on.

- **Bug 46** chose the config directory with `#ifdef __APPLE__`, which cosmocc
  does not define. On macOS we wrote saved keys to `~/.config/tailcat/keys/`
  while the real tailcat used `~/Library/Application Support/`. The two
  implementations could not read each other's keys on that platform, and
  nothing here could have noticed.
- **Bug 48** was the same failure on Windows, and it was found only because
  Windows is a platform these hands can reach.

One of those was caught by accident of hardware. The other sat there because
nobody could run the thing. That is the risk this plan is about: **not that
the untested platforms are broken, but that we would not know.**

A BSD is the cheapest of the four to reach. macOS is the one that actually
had the bug, and it is the one this plan cannot help with — see the end.


## What is actually being tested

Not, mainly, our code. The interesting subject is **the Actually Portable
Executable mechanism itself**, on an OS where it has never been exercised
here.

On Linux the APE runs through a `binfmt_misc` registration that
`scripts/wslmake.sh` installs; on Windows it is a native PE. On a BSD it is
neither: the file begins with a shell-script polyglot header that the system
shell executes, which then arranges for the real program to run. That path has
never been taken by this project's binary.

So the first question a run answers is "does `./build/cosmo/tailcat-c version`
print anything at all on FreeBSD?" Everything after that is ordinary testing.
If the answer is no, that is a much larger finding than any individual test
result, and it invalidates a claim in the README that has been made for
months.

Secondary, and genuinely likely to find something: anything that asks the
platform a question. `config_dir()` now asks `tc_host_os()` at runtime (bug
46), and a BSD is the branch nothing has ever taken. `self_path()` uses
`GetProgramExecutableName()` (bug 47) whose BSD implementation is
Cosmopolitan's, not ours. The DNS resolver goes through musl's `res_query`,
which was checked on Linux and Windows and never on a BSD.


## What the machine can do

Checked, on this machine, before writing any of this down:

| | |
|---|---|
| `/dev/kvm` | present — WSL2 has nested virtualisation enabled |
| CPU | AMD with `svm`, so hardware acceleration is real |
| Disk | 890 GB free |
| Memory | 15 GB total, 14 available |
| `qemu-user-static` | installed (this is what the aarch64 stage uses) |
| `qemu-system-x86` | **not installed**, but resolves in the Ubuntu archive |
| root in WSL | `wsl.exe -u root` works with no sudo password |

The distinction between the two qemus is the reason this is a plan and not a
one-liner:

- **`qemu-user-static`** runs a foreign-*architecture* binary against the
  *host Linux kernel*, translating instructions and passing syscalls through.
  That is exactly what the aarch64 stage needs: ARM instructions, Linux
  syscalls, this kernel.
- **`qemu-system-x86`** emulates a whole machine and boots a real kernel.

A FreeBSD binary makes FreeBSD syscalls, and `qemu-user` has no FreeBSD kernel
to make them to. (`qemu-bsd-user` exists and does not help: it runs BSD
binaries on a BSD host.) So a BSD means full-system emulation, and with KVM
that costs speed measured in percent rather than multiples.


## Which BSD

**FreeBSD 14.5-RELEASE**, and specifically the cloud-init image:

```
https://download.freebsd.org/releases/VM-IMAGES/14.5-RELEASE/amd64/Latest/
    FreeBSD-14.5-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz
```

(Index confirmed reachable, HTTP 200; 14.4 and 14.5 are the current releases;
both plain and `BASIC-CLOUDINIT` variants exist in `ufs` and `zfs` flavours.)

FreeBSD wins because it is the only BSD that publishes a prebuilt image which
boots unattended, and the cloud-init variant is what makes the whole thing
scriptable: a seed ISO injects an SSH key and enables `sshd` on first boot,
with no console interaction at all. Driving a serial console with `expect` is
the alternative and it is miserable.

- **NetBSD** also publishes images and would be the natural second.
- **OpenBSD** publishes no qcow2 and needs a scripted `autoinstall` from ISO.
  Worth doing eventually; not worth doing first.


## The approach

1. **Install the emulator.** `wsl.exe -u root -e apt-get install -y
   qemu-system-x86`. One package on the developer's machine; it is the only
   change this plan makes outside the repository.

2. **Fetch and decompress the image**, into `build/bsd/` (git-ignored). ~500 MB
   compressed. Verify it against FreeBSD's published checksum rather than
   trusting the transfer.

3. **Build a cloud-init seed ISO** with a generated SSH key and `sshd`
   enabled. The key is generated per run and thrown away; nothing here needs a
   durable identity.

4. **Boot headless** with KVM and user-mode networking:
   ```
   qemu-system-x86_64 -enable-kvm -m 4096 -smp 4 -nographic \
       -drive file=freebsd.qcow2,if=virtio \
       -drive file=seed.iso,media=cdrom \
       -nic user,hostfwd=tcp::12222-:22
   ```

5. **Copy the build in and run it.** `scp` the contents of `build/cosmo/` —
   the fat binary and the ~40 test binaries — and run them. The first command
   is `./tailcat-c version`, because that is the question in section two.

6. **Report like the other tiers**, `ok`/`FAIL` per binary, so the output is
   comparable with `diagnostic.sh`'s.

If it works, it becomes `scripts/bsd-test.sh` and a `make bsd-test` target,
and joins level 1 — not level 5 or 3, because it boots a virtual machine and
takes minutes.


## The alternatives, and why they lose

- **A shared folder instead of SSH.** qemu can expose a host directory as a
  virtual FAT disk (`-drive file=fat:rw:...`), which avoids networking
  entirely. Attractive, and the fallback if cloud-init disappoints — but FAT
  loses the executable bit, which for a test run consisting entirely of
  executables is the wrong thing to lose.
- **Baking the binaries into the image.** Reproducible, and rebuilds the image
  on every source change. Too slow to use while iterating.
- **A cloud BSD box.** Faster to reach the first answer; costs money, needs
  credentials, and leaves the project unable to reproduce its own result. The
  point is a check that anyone cloning this repository can run.
- **Cross-testing with `qemu-bsd-user`.** Does not apply, as above.


## What could go wrong

- **The APE may not start.** The headline risk, and the reason to do this. If
  the polyglot header fails on FreeBSD's `sh`, the fallback is Cosmopolitan's
  `ape` loader binary, the same mechanism `wslmake.sh` registers on Linux.
- **KVM in WSL2 may be less available than `/dev/kvm` suggests.** The device
  node existing is not proof the ioctls work. If acceleration fails, TCG still
  runs, several times slower — tolerable for a suite that takes 15 seconds
  natively, and a reason to time it before assuming.
- **The tests may need tools the image lacks.** The unit tests are
  self-contained binaries, so this mostly affects anything shelling out. The
  live and script-driven stages are out of scope (below).
- **Disk images are large and easy to leave behind.** `build/bsd/` must be
  git-ignored from the start. This session has already committed two stray
  test keys by running `git add -A` after filesystem testing; a 3 GB disk
  image would be a worse version of the same mistake.


## What this will not cover

Stated plainly, because a green run will be tempting to over-read.

- **Not the live tests.** Those dial Tailscale's relays and need working
  outbound networking from inside the VM plus a second endpoint. Possible
  later; out of scope here. What is in scope is the offline suite, which is
  ~42,000 assertions and every codec, crypto and protocol path.
- **Not macOS.** Which is where bug 46 actually lived. FreeBSD exercises *a*
  non-Linux, non-Windows path, and that is worth a great deal, but
  `TC_OS_MACOS` stays untaken. Only a Mac fixes that, and no amount of qemu
  substitutes for one.
- **Not OpenBSD or NetBSD**, at first. See above.

The honest summary: this converts "four platforms built and never run" into
"three platforms built and never run, and one of them tested properly". That
is a real reduction in risk and not a complete one, and the README should say
so in exactly those terms rather than claiming BSD support outright.
