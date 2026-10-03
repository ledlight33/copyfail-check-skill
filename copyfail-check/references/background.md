# Background: Copy Fail (CVE-2026-31431)

## What it is

Copy Fail is a local privilege escalation in the Linux kernel. It affects kernels from 4.14 (2017) until patched. NVD rates it CVSS 3.1 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). It needs a local, unprivileged account: it is not a remote bug by itself.

Mechanism in short:

- The kernel exposes crypto to user space through AF_ALG sockets. The `algif_aead` module handles authenticated encryption (AEAD).
- A 2017 change (commit 72548b093ee3, Linux 4.14) made `algif_aead` work in place. Combined with the scratch-write behaviour of the `authencesn` template, a crypto operation can write 4 bytes into pages that belong to a file passed in with `splice()`.
- Those pages are the file's page cache (the in-memory copy). Repeating the 4-byte write lets an unprivileged user overwrite the start of a setuid program such as `/usr/bin/su` in memory, then run it to get a root shell.
- The upstream fix (commit a664bf3d603d, "crypto: algif_aead - Revert to operating out-of-place") reverts `algif_aead` to out-of-place operation.

## Page cache in plain words

Linux keeps copies of recently used file contents in RAM so that reads are fast. When a program reads or runs a file, it gets the RAM copy. Normally the kernel marks changed RAM pages as dirty and writes them back to disk.

Copy Fail changes the RAM copy without marking it dirty. So:

- The disk copy is never modified. A powered-off disk image, a hash taken from the disk, or file-integrity tooling that reads the disk all look clean.
- Anything that executes or reads the file normally gets the poisoned RAM copy, for as long as the page stays cached.
- The poisoned page can be evicted at any time (memory pressure, a cache drop, heavy scans) and is lost on reboot. That is why a clean check is a good sign and not proof, and why memory capture comes first when an incident is suspected.

The check in this skill exploits the same fact from the other side: it reads each file twice, once through the cache and once directly from disk (O_DIRECT), and flags any difference.

## Timeline (dates as published, YYYY-MM-DD)

- 2026-03-23: reported privately to kernel security.
- 2026-04-01: mainline fix committed.
- 2026-04-11: stable releases 6.18.22 and 6.19.12 carry the fix. Older stable branches followed around 2026-04-30.
- 2026-04-22: CVE record published.
- 2026-04-29: public disclosure with a short Python PoC by Taeyang Lee (Theori), found with Theori's Xint Code tool by their account.
- 2026-05-01: added to the CISA KEV catalog. Microsoft reported limited exploitation, mainly PoC testing.
- 2026-05-04: first RHEL 9 fix (per Red Hat).
- 2026-05-07: Dirty Frag disclosed (related bug class). Cloudflare reported no impact and a clean threat hunt.
- 2026-05-13: Fragnesia disclosed (related).
- 2026-05-19: Xint published a pod-to-host container escape using a shared page cache.
- 2026-06 (JFrog write-up 2026-06-25): DirtyClone (related).
- 2026-08-03: CrowdStrike's 2026 threat hunting report says OverWatch found Belarus-nexus activity (UMBRAL BISON) exploiting it just over 20 hours after public disclosure.
- 2026-09-28: containerd merged a default seccomp change that blocks AF_ALG (release availability not confirmed here).

## Exploitation status (calibrated)

- On the CISA KEV list since 2026-05-01.
- Early exploitation was limited and mostly PoC testing, per Microsoft. CrowdStrike says about 94 percent of OverWatch events in the first 24 hours were PoC testing.
- CrowdStrike (2026-08-03) reported finding Belarus-nexus activity (UMBRAL BISON) in just over 20 hours after public disclosure, in a short passage of its report with no indicators.
- Public exploit code is plentiful: VulnCheck counted 132 exploits by 2026-05-21, and a Metasploit module exists.
- No ransomware or botnet use was found in the sources reviewed. No patch bypass or second algif_aead CVE was found.
- Absence of public reports is not proof of absence on a given host.

## Related bugs (same class, separate fixes)

These write to file-backed page cache through other kernel paths. Blocking `algif_aead` does not cover them. Each has its own patch.

- Dirty Frag: CVE-2026-43284 (xfrm-ESP) and CVE-2026-43500 (RxRPC). Reported exploitable even where the Copy Fail algif_aead mitigation is applied. Microsoft saw limited use after SSH access.
- Fragnesia: CVE-2026-46300, ESP-in-TCP. A separate bug, not a Copy Fail variant.
- DirtyClone: CVE-2026-43503. A JFrog write-up describes a missing flag in `__pskb_copy_fclone()` that lets ESP decrypt in place over file-backed pages.

They are often compared to Dirty Pipe (CVE-2022-0847) and Dirty COW (CVE-2016-5195): the kernel ends up writing to memory that backs a file the user may only read. The cached-versus-disk comparison checks the result rather than the syscall path, so it should also notice them, but this has not been lab-tested for every bug.
