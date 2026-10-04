# copyfail-check

[![CI](https://github.com/ledlight33/copyfail-check-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/ledlight33/copyfail-check-skill/actions/workflows/ci.yml)

A portable Agent Skill and standalone script that let any AI agent, or you, check a Linux host for Copy Fail (CVE-2026-31431) using read-only commands. It tells you whether the kernel is in the affected range, whether the vulnerable `algif_aead` path is reachable or blocked, whether any privileged file looks different in the page cache than on disk, and whether the usual weak traces are present. It never runs, fetches or contains exploit code, and it is designed to be read-only (read the disclaimer below before you run it).

> **New to Copy Fail forensics?** There is a free interactive walkthrough for humans that explains the investigation step by step and includes the same read-only checklist: [ledlight33.github.io/copyfail-dfir](https://ledlight33.github.io/copyfail-dfir/) (Greek version: [?lang=el](https://ledlight33.github.io/copyfail-dfir/?lang=el)). It is a separate project, and this skill links to it only as further reading.

Copy Fail (CVE-2026-31431, CVSS 7.8) is a Linux kernel bug in `algif_aead` / `authencesn` that lets a local unprivileged user write into the page cache of a file they can only read. It affects kernels from 4.14 until patched and has been on the CISA KEV list since 2026-05-01. Early exploitation was limited and mostly PoC testing (Microsoft). CrowdStrike (2026-08-03) reported finding Belarus-nexus activity just over 20 hours after public disclosure. No ransomware or botnet use and no patch bypass have been reported in the sources reviewed for this project (as of 2026-10-03).

## ⚠️Disclaimer: check first, then run⚠️

This project was created and tested in the author's own environment (Ubuntu under WSL2, plus unit tests with mocked reads). Linux systems, kernels, filesystems and AI agents differ, so it may behave differently on yours.

- **Do not take "read-only" on trust.** The script is designed to be read-only, but you should read `copyfail-check/scripts/copyfail_check.sh` and `copyfail-check/SKILL.md` before you run them. Run the script yourself once before you let an agent run it.
- **Test first.** Try it on a test machine, not on a production system.
- **An AI agent can misread instructions or make mistakes.** Keep it supervised, require your approval for every action that changes anything, and do not give it more access than you are comfortable with. The skill tells the agent to behave safely, but no instructions can force an agent to follow them.
- **Read-only operations still have side effects.** They use CPU and disk I/O (the scan can take minutes on a large filesystem), can update file access times, and a direct read first writes already-modified cached pages back to disk, which is normal operating system behavior.
- **The result is a signal, not a verdict.** A clean result is not proof that a machine is safe, and a mismatch is not proof of a compromise. Do not use this as your only security control.

The author is not responsible or liable for any damage, data loss, downtime or other harm caused by running this script, by an AI agent that uses this skill, or by acting on its output. You use it entirely at your own risk. This matches the MIT license, under which the software is provided "as is", without warranty of any kind.

## What it does

- Compares the running kernel with the fixed releases (5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12 and 7.0) and, for Ubuntu generic and lowlatency kernels, with the fixed ABI numbers from Ubuntu's CVE page (6.8.0-117, used by the 24.04 GA kernel and the 22.04 HWE kernel, and 6.17.0-29, used by the 24.04 HWE kernel and 25.10).
- Checks whether the AEAD interface is built in, whether `algif_aead` is loaded, and whether it is blocked by a modprobe rule or by `initcall_blacklist`.
- Compares a normal (cached) read with a direct `O_DIRECT` disk read of every setuid file on the root filesystem plus `/etc/passwd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, the `su`, `sudo` and `runc` binaries and any paths you add with `--extra`. A difference is re-checked once to rule out a file that changed.
- Asks the package manager (`dpkg -V` or `rpm -V`) whether `su` differs from its package.
- Looks for weak traces: kernel log timing of the PF_ALG protocol family, shell history that mentions copy.fail, and auditd socket events (root only).
- Prints a text report or JSON, and returns an exit code an agent or a script can act on.

## What it does NOT do

- It does not contain, download or run any exploit. It never tries to trigger the bug.
- It is read-only by design (see the disclaimer above). The code never writes files, never uses sudo, never loads or unloads modules and never drops caches.
- A clean result is a good sign, not proof. The poisoned page can be evicted from the cache, or lost on reboot, and the file on disk was never changed.
- It cannot confirm a compromise by itself. It detects a cached-versus-disk difference, which can come from Copy Fail or from a related page-cache bug (Dirty Frag, Fragnesia, DirtyClone). Confirming what happened needs memory forensics.
- It does not patch or harden anything. Patch the kernel.

## Tested on

| Environment | Status |
| --- | --- |
| Ubuntu 24.04 under WSL2 (kernel 6.6.87.2) | Full runs (text, JSON and `--no-scan`) and all unit tests |
| Ubuntu on GitHub Actions (`ubuntu-latest`) | Unit tests and a JSON smoke test on every push |
| Other distributions (Kali, Debian, Fedora, the RHEL family, Arch, Alpine and more) | Expected to work, **not yet tested** |
| Non-Linux systems (macOS, Windows without WSL) | Not applicable, the script exits with code 64 |

Things to know on other distributions:

- The script needs real bash (not `sh` or `dash`) and the standard tools it uses: `find`, `dd`, `sha256sum`, `grep`, `sed`, `awk` and `readlink`. `dpkg` or `rpm`, `dmesg` or `journalctl`, and `ausearch` are optional and only add detail.
- Only Ubuntu has a built-in table of fixed kernel builds. On other distributions the kernel result is usually `check_vendor`, because the script cannot know which fixes a vendor has backported. Check your vendor's security tracker for that part. The configuration, module and file comparison checks do not depend on the distribution.

If you run it on another distribution, please open an issue with the distribution, the kernel version and the verdict, whether it worked or not. That helps this table grow.

## Install

This is meant to work with any agent. The skill is one folder, `copyfail-check/`, with plain-markdown instructions (`SKILL.md`) and a bash script. It only needs a Linux shell with bash. Get it first:

```sh
git clone https://github.com/ledlight33/copyfail-check-skill.git
```

Then pick the row that matches your setup:

| Your setup | What to do |
| --- | --- |
| An agent that supports Agent Skills (a skills directory of folders with a `SKILL.md`) | Copy the `copyfail-check` folder into that agent's skills directory. Example for Claude Code: `mkdir -p ~/.claude/skills && cp -r copyfail-check-skill/copyfail-check ~/.claude/skills/` (all projects) or the same into `.claude/skills/` inside a project |
| Any other agent that can read files and run shell commands | Keep the folder anywhere the agent can read and tell it: "Follow copyfail-check/SKILL.md". You can also add that line to your agent's project instructions file. This repository ships an `AGENTS.md` that does it when an agent works inside the repository |
| An agent without shell access | Run the script yourself and give the agent the JSON output. It interprets it with `copyfail-check/references/interpretation.md`. You can also paste `SKILL.md` into the agent's custom instructions |
| No agent at all | Run `bash copyfail-check/scripts/copyfail_check.sh` yourself, or from cron, CI or a SIEM, and act on the exit code |

## Use

Example prompts for an agent:

1. "Check whether this machine is exposed to Copy Fail (CVE-2026-31431) with the copyfail-check skill and explain the verdict."
2. "Run the Copy Fail check with JSON output and give me a short summary I can paste into a ticket."
3. "Run the Copy Fail check and also compare /usr/local/bin/mytool with its on-disk copy. If the verdict is SUSPECT, tell me what to do first."

Direct command:

```sh
bash copyfail-check/scripts/copyfail_check.sh
```

Run it as root if you want full coverage (kernel log, audit log, other users' shell history). The script never calls sudo itself, so you decide how it is started.

Options:

| Option | What it does |
| --- | --- |
| `--json` | Print machine-readable JSON instead of the text report |
| `--extra PATH` | Also compare PATH (cached read versus direct disk read). Repeatable |
| `--no-scan` | Skip the cached-versus-disk comparison (kernel and config checks only) |
| `--max-files N` | Compare at most N setuid files (default 3000). The named files and `--extra` paths are always compared |
| `--version` | Print the script version |
| `-h`, `--help` | Show the help text |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Not exposed, and no weak signals |
| 1 | Exposed, unknown, or weak signals were found |
| 2 | Suspect: a confirmed cached-versus-disk mismatch, or the package manager reports `su` differs |
| 64 | Usage error, or the host is not Linux |

Verdicts: `NOT_EXPOSED`, `EXPOSED_NO_INDICATORS`, `EXPOSED_INCONCLUSIVE` and `SUSPECT`. Exposure is reported as `not_exposed`, `mitigated`, `possibly_exposed` or `exposed`, and the kernel assessment as `not_affected`, `fixed`, `affected` or `check_vendor`. JSON output has the keys `tool`, `version`, `timestamp`, `host`, `exposure`, `integrity`, `traces` and `verdict`.

If the verdict is `SUSPECT`, do not reboot and do not drop caches, because both destroy evidence. Capture memory (LiME or AVML), isolate the host, then investigate. The walkthrough below explains the steps.

## Example output

Real output from an Ubuntu 24.04 host running under WSL2, run as a normal user. This host blocks `algif_aead` with a modprobe rule, so exposure is reported as `mitigated` and the verdict is `NOT_EXPOSED`. That comes from the block, not from a patched kernel, and the report says so.

```text
Copy Fail (CVE-2026-31431) read-only check, v1.0.0
Host: host01 | Ubuntu 24.04.4 LTS | kernel 6.6.87.2-microsoft-standard-WSL2 | x86_64 | root: no | container: no

== Exposure
[INFO] Kernel assessment: check_vendor. Vendor kernel with upstream base 6.6.87, which is below the upstream fix. Distributions backport fixes, so check your vendor's security tracker.
[INFO] AF_ALG AEAD build config: m (from /proc/config.gz)
[INFO] Module loaded now: no | modprobe block: yes (modprobe rule: install algif_aead /bin/false) | initcall_blacklist: no
[OK] Exposure: mitigated. algif_aead is blocked. This does not cover the related page-cache bugs (Dirty Frag, Fragnesia, DirtyClone). Patch the kernel.

== Integrity (cached read vs direct disk read)
[INFO] Checked 17 file(s): 17 matched, 0 unsupported, 0 unreadable.
[OK] Package manager sees no change in su (dpkg -V util-linux). A clean result proves little: the page may already be gone.

== Weak traces
[INFO] Kernel log PF_ALG: absent
[INFO] auditd: unavailable (needs root and the audit tools)

== Verdict: NOT_EXPOSED (exit 0)
Not exposed through this bug on this host. algif_aead is blocked. This does not cover the related page-cache bugs (Dirty Frag, Fragnesia, DirtyClone). Patch the kernel.
```

## Safety

The script only reads. This is everything it touches.

Reads:

- Host facts: `/etc/os-release`, `/proc/uptime`, `/proc/1/cgroup`, `/proc/sys/kernel/hostname` (fallback), `/.dockerenv`, `/run/.containerenv` and the `container` environment variable, plus the output of `uname`, `hostname` and `date` (JSON timestamp only).
- Kernel configuration: `/proc/config.gz` (through `zcat`) or `/boot/config-<release>`, with `modules.builtin` and `modules.dep` under `/lib/modules/<release>` as a fallback, plus `/proc/modules` and `/proc/cmdline`.
- Module rules: the files under `/etc/modprobe.d`, `/usr/lib/modprobe.d`, `/lib/modprobe.d` and `/run/modprobe.d`.
- Integrity scan: `find / -xdev -perm -4000 -type f` to list setuid files, then for each file one normal read through `sha256sum` and one direct read through `dd iflag=direct` piped to `sha256sum`. A file that differs is read again once after `sleep 1`. The named files are `/etc/passwd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, `/usr/bin/su`, `/bin/su`, `/usr/bin/sudo`, three common `runc` paths and whatever you pass with `--extra`.
- Package manager: `command -v su`, `readlink -f`, then `dpkg -S` and `dpkg -V`, or `rpm -qf` and `rpm -V`.
- Weak traces: `dmesg` (or `journalctl -k -b --no-pager` when `dmesg` is not allowed), `~/.bash_history` and `~/.zsh_history` (as root also the root and `/home/*` histories, searched for the text copy.fail), and `ausearch -sc socket` when running as root with the audit tools installed.

Writes and changes: the script creates, modifies and deletes nothing. Results go to standard output only. It never uses sudo, never loads or unloads kernel modules, never changes sysctls or configuration, never drops caches and never downloads anything. Reading files has the usual side effects of any read: pages are brought into the page cache and access times may be updated. A direct read also makes the kernel write back any dirty (not yet saved) cached pages of that file first. That only saves data the system had already written, but it is the one way the check can cause a disk write.

One privacy note: when a history file mentions copy.fail, the report prints the first matching line (cut to 140 characters), so read the output before pasting it somewhere public.

## How the check works

Copy Fail lets an unprivileged local user write a few bytes at a time into the kernel's cached copy of a file it can only read, so the altered data lives in RAM while the file on disk stays unchanged. The script hashes each privileged file twice, once with a normal read, which is served from the page cache, and once with an `O_DIRECT` read, which goes to the disk, and compares the two hashes. A difference that is still there on a re-check one second later means the copy the kernel serves is not the copy on disk.

For the full story, including the memory forensics steps of an investigation, see the human walkthrough: https://ledlight33.github.io/copyfail-dfir/ (Greek version: https://ledlight33.github.io/copyfail-dfir/?lang=el).

## Limitations

- A clean result is not proof of safety. A poisoned page may already have been evicted or lost on reboot, and a mitigation that blocks only `algif_aead` does not protect against the related page-cache bugs.
- A mismatch is not proof of Copy Fail specifically. The comparison checks the result rather than the syscall path, so related page-cache bugs should show up too, but this has not been lab-tested for every one of them. A file that is legitimately changing while it is read can also differ once, which the re-check is meant to filter out.
- The comparison needs direct reads. Some filesystems do not support them. Those files are counted as unsupported, and if nothing can be compared the scan is reported as inconclusive.
- Scope is limited to setuid files on the root filesystem (`find -xdev`, up to `--max-files`), the fixed list of named files above and your `--extra` paths. Other mounted filesystems and non-setuid files are not covered unless you add them.
- Kernel assessment uses the upstream fixed releases and the Ubuntu ABI numbers for 6.8.0 and 6.17.0 generic and lowlatency kernels. Other vendor kernels, including Ubuntu cloud flavours such as aws, are reported as `check_vendor`, because distributions backport fixes. Check your vendor's security tracker. If no build configuration or module index file is readable, the build configuration is reported as unknown.
- Weak traces are weak. Attackers can avoid shell history and kernel log timing, auditd does not log these calls with its default rules, and legitimate crypto tools also open AF_ALG sockets.
- Inside a container the page cache is shared with the host, so the results describe the host kernel.
- Linux only. On any other system the script exits with code 64.
- It does not replace EDR, memory forensics or patching.

## Development

Run the unit tests from the repository root:

```sh
bash tests/run_tests.sh
```

The tests source the script's helper functions and check the kernel assessment, exposure and verdict logic. They touch nothing on the system.

CI runs on every push and pull request to `main`:

1. The unit tests (`bash tests/run_tests.sh`).
2. A smoke test that runs `copyfail_check.sh --no-scan --json` and checks that the output is valid JSON with the expected top-level keys. The script may exit non-zero by design, so the JSON is captured first.
3. ShellCheck on both shell scripts. This step reports problems but does not fail the build.

## Credits

Written by Marino Bekios, MB Labs. LinkedIn: https://linkedin.com/in/marbekios, GitHub: ledlight33.

Copy Fail was publicly disclosed on 2026-04-29 with a proof of concept by Taeyang Lee (Theori). The facts used here come from public sources: the NVD record, the vendor advisories and the research cited in the walkthrough linked above.

## License

MIT. See [LICENSE](LICENSE). See [SECURITY.md](SECURITY.md) for how to report a mistake or a security issue.
