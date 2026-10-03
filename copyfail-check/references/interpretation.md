# Interpreting the output

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Verdict `NOT_EXPOSED` and no weak traces |
| 1 | `EXPOSED_NO_INDICATORS`, `EXPOSED_INCONCLUSIVE`, or `NOT_EXPOSED` with weak traces |
| 2 | `SUSPECT`: confirmed mismatch, or the package manager reports `su` differs |
| 64 | Usage error or not a Linux host |

## JSON fields (`--json`)

Top level: `tool`, `version`, `timestamp` (UTC), `host`, `exposure`, `integrity`, `traces`, `verdict`.

`host`: `name`, `kernel` (uname -r), `arch`, `distro`, `root` (true if run as uid 0), `container` (true if a container is detected, so the page cache is the host's), `uptime_seconds`.

`exposure`:
- `status`: `not_exposed`, `mitigated`, `possibly_exposed`, `exposed`.
- `kernel_status`: `not_affected` (older than 4.14), `fixed` (at or above the fixed release for its branch; for Ubuntu generic and lowlatency 6.8.0 and 6.17.0 kernels the ABI number is compared), `affected`, `check_vendor` (vendor kernel below the upstream fix so a backport may exist, or a release string that could not be parsed).
- `kernel_base`: major.minor.patch parsed from the release. `vendor_kernel`: true if the release string has a vendor suffix.
- `aead_config`: `y`, `m`, `n` or `unknown` for CONFIG_CRYPTO_USER_API_AEAD (read from /proc/config.gz or /boot/config-RELEASE; if neither is readable, the module index files modules.builtin and modules.dep under /lib/modules/RELEASE are used). `n` means not exposed.
- `module_loaded`: `yes` if algif_aead is in /proc/modules now.
- `modprobe_blocked`: `yes` if an `install algif_aead /bin/false` (or `/bin/true`) rule exists in modprobe.d.
- `initcall_blocked`: `yes` if the boot command line has an `initcall_blacklist` naming algif_aead_init, af_alg_init or crypto_authenc_esn_module_init.
- `note`: plain explanation.

`integrity`:
- `scan`: `done`, `skipped` (`--no-scan`) or `inconclusive` (no file could be compared, or tools missing).
- `files_checked`, `matched`, `direct_read_unsupported`, `unreadable`, `capped` (`yes` if the `--max-files` limit was hit).
- `mismatches`: files whose cached and direct reads still differed on a re-check one second later. `transient`: files that differed once and matched on re-check (the file was changing).
- `package_check`: `clean`, `changed` (dpkg -V or rpm -V flags a checksum change for `su`) or `unavailable`.

`traces` (all weak):
- `dmesg`: `unreadable`, `absent`, `normal`, `late` or `unparsed` (a PF_ALG line was found but its time could not be read). `late` means the PF_ALG line appeared more than 300 seconds after boot, which can mean on-demand module loading. `dmesg_seconds_after_boot` holds the number.
- `history_hits`: shell history lines mentioning copy.fail (current user only, all users when root).
- `audit`: `unavailable` (needs root and ausearch), `none`, `hits`. `audit_hits` counts socket(AF_ALG, SOCK_SEQPACKET) calls. Legitimate crypto tools also do this, so identify the process.
- `weak_signals`: the human-readable list of the above.

`verdict`: `status`, `exit_code`, `summary`.

## Verdicts

- `NOT_EXPOSED`: either the kernel is fixed or older than the bug, AEAD is not compiled in, or algif_aead is blocked (`mitigated`). Always read `exposure.status`. `mitigated` still leaves the kernel unpatched and the related bugs open.
- `EXPOSED_NO_INDICATORS`: vulnerable and the comparison ran with no mismatch. Good sign, not proof.
- `EXPOSED_INCONCLUSIVE`: vulnerable and the comparison did not run or compared nothing. Memory forensics is the way to confirm.
- `SUSPECT`: a confirmed mismatch (or `package_check` is `changed`). A mismatch overrides a fixed or mitigated exposure result, because it can come from a related page-cache bug that the Copy Fail fix does not cover.

## False positives

- A file replaced or updated while the scan ran. The one-second re-check reduces this (see `transient`).
- `package_check` `changed` can come from a legitimate local change to `su` or a package database that is out of sync. Confirm with the direct-disk comparison and, if in doubt, with memory.
- Ordinary unsaved writes do not show up as differences, because a direct read first writes back the dirty cached pages of the range.
- The script probes direct reads first and counts files that fail the probe as unsupported, so a mismatch normally means a real difference. If many or all compared files mismatch, suspect a filesystem or storage quirk before a mass compromise. A single odd mismatch on a network or FUSE mount deserves lower confidence than one on a local disk. Verify any mismatch independently before declaring an incident, but do not delay memory capture while doing so.
- An auditd or kernel-log hit alone is weak: legitimate crypto tools open AF_ALG sockets, and on-demand module loading happens in normal use.

## False negatives (a clean result can be wrong)

- Eviction: the poisoned page can be dropped at any time (memory pressure, cache drop, scans). It is lost on reboot.
- Unsupported filesystems: some filesystems lack direct reads, depending on the filesystem and kernel version (for example some network or FUSE mounts). Those files are counted in `direct_read_unsupported` and are not compared.
- Coverage: only setuid files on the root filesystem (other mounts are skipped by `-xdev`), `/etc/passwd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, runc and `--extra` paths. A page-cache write can target any readable file. Add `--extra` for files that matter and separate mounts.
- Non-root runs cannot read some files (`unreadable`) and miss other users' history, the kernel log on restricted systems and audit data.
- Containers share the host page cache. A check inside a container describes the host kernel, and a container image or layer can be the target (shared base layers, the runc binary).
- Vendor kernels and backports: `check_vendor` and `possibly_exposed` mean the version number cannot decide. Use the vendor tracker. The version logic only knows the Ubuntu ABI numbers for 6.8.0 and 6.17.0 generic and lowlatency kernels.
- Weak traces can be avoided by an attacker (history cleared, no audit rules, no kernel log).
- The check says nothing about persistence or other actions after root was gained.

## Why clean is not proof

The evidence is a page in RAM that never touches disk. If it was evicted, or the host rebooted, the cached and disk views match again even though the host was root-compromised. Report "no indicators found right now" and recommend patching plus detection (auditd rules for socket(AF_ALG) and splice, set up before an incident).
