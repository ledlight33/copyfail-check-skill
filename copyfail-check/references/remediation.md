# Remediation and incident response

Every command below is a suggestion. Show it to the user, explain what it does and what it affects, and run it only after a clear yes. Never run any of it after a SUSPECT result before memory is captured.

## 1. Patch the kernel (the real fix)

Fixed upstream kernel releases: 5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12 and 7.0. The fix reverts algif_aead to out-of-place operation. After installing, reboot into the new kernel and confirm with `uname -r`.

Distributions backport fixes, so use the vendor tracker, not only the version number:

- Ubuntu (per Ubuntu's CVE page, last updated 2026-08-27): 24.04 needs 6.8.0-117 or later on the GA kernel or 6.17.0-29 or later on the HWE kernel; 22.04 needs 5.15.0-179 or later on the GA kernel or 6.8.0-117 or later on the HWE kernel; 25.10 needs 6.17.0-29 or later; 26.04 is listed as not affected. Older releases and current details: https://ubuntu.com/security/CVE-2026-31431.
- Debian: https://security-tracker.debian.org/tracker/CVE-2026-31431
- RHEL family: https://access.redhat.com/security/vulnerabilities/RHSB-2026-002
- Amazon Linux: https://explore.alas.aws.amazon.com/CVE-2026-31431.html

Typical suggestion on Debian or Ubuntu: `sudo apt update && sudo apt full-upgrade`, then `sudo reboot`. A reboot interrupts services, so agree on timing with the user. Never reboot a suspected-compromised host before memory capture.

## 2. Interim mitigation (until the patched kernel is running)

Check `exposure.aead_config` in the script output first.

- `m` (module): block algif_aead from loading. Example: `echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf`. If the module is already loaded, `sudo rmmod algif_aead` removes it (can fail if in use; a reboot also clears it). The check reports `mitigated` once the rule exists and the module is not loaded. Anything that uses the kernel crypto API from user space through algif_aead stops working, so confirm nothing depends on it.
- `y` (built in, as on the RHEL family): a modprobe block does nothing. Red Hat documents boot parameters such as `initcall_blacklist=algif_aead_init` (alternatives it names: `af_alg_init` or `crypto_authenc_esn_module_init`), with a performance cost. Add the parameter to the kernel command line with your distribution's normal boot loader tooling, then reboot. Follow the exact wording in RHSB-2026-002 and prefer the patched kernel.
- `n`: not exposed through this bug.

Blocking algif_aead does not cover Dirty Frag, Fragnesia or DirtyClone. Only a patched kernel does.

## 3. Containers

- Docker Engine 29.4.3 or later denies socket(AF_ALG) in its default seccomp profile (it also adds an AppArmor rule and an SELinux module, per Docker). Docker says hosts are protected on 29.4.3 or later or with a patched host kernel. Earlier 29.4.2 advice is superseded. Custom seccomp profiles should deny socket with domain AF_ALG (38).
- Kubernetes RuntimeDefault with containerd did not block AF_ALG in tests in April 2026. Check your runtime version. containerd merged a default seccomp change on 2026-09-28 that blocks AF_ALG (moby profiles merged a similar change on 2026-09-16); which release ships it was not confirmed, so check the release notes.
- Containers share the host page cache. A pod that can poison it (shared image layers, the runc binary) can affect the host (Xint, 2026-05-19). Sandboxed runtimes such as gVisor, Kata and per-pod microVMs (EKS Fargate) keep a pod from poisoning the host page cache. A guest kernel there still needs the patch.
- Patch the node kernel. Seccomp is defence in depth.

## 4. Related bugs (separate CVEs, separate fixes)

CVE-2026-43284 and CVE-2026-43500 (Dirty Frag), CVE-2026-46300 (Fragnesia), CVE-2026-43503 (DirtyClone). Install a kernel your vendor lists as fixed for each. Reported interim workarounds for the Dirty Frag family are blocking the esp4, esp6 and rxrpc modules and restricting unprivileged user namespaces. Both have side effects (esp4 and esp6 carry IPsec ESP traffic; user namespaces are used by rootless containers and some sandboxes), so only suggest them with those costs stated.

## 5. Detect it next time

- auditd rules for socket with domain AF_ALG and for splice, installed before an incident. Default rules do not log these calls. Example lines (verify against the sets published by Splunk and Elastic before deploying; in audit logs the value shows as hex 26):
  `-a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg`
  `-a always,exit -F arch=b64 -S splice -k splice_use`
- Behaviour rules: AF_ALG SEQPACKET sockets opened by programs that are not crypto tools (Sysdig publishes a Falco rule; Cloudflare counted socket(AF_ALG) per binary fleet-wide with an eBPF exporter).
- Integrity: hash privileged files two ways (normal read and O_DIRECT read) and alert on any difference. The page can be evicted at any time, so check often. This skill's script does exactly that.

## 6. Incident response for a SUSPECT result

Assume root-level compromise. Work in this order. Ask the user to approve each step.

1. Do not reboot, do not drop caches (`/proc/sys/vm/drop_caches`), do not reinstall or restore `su`, do not kill or log out suspect processes, and avoid big scans or copies on the host. All of these can destroy the evidence in RAM.
2. Capture memory first.
   - LiME: needs a module built for the exact running kernel (`uname -r`). From external or evidence media: `insmod /mnt/evidence/lime-$(uname -r).ko "path=tcp:4444 format=lime"`, then on the analyst machine `nc HOST 4444 > host.lime`. LiME may not load under Secure Boot or kernel lockdown without a signed module.
   - AVML: an alternative acquisition tool that needs no kernel module. Follow its README.
   - Stream the image to another machine or external media, not the host disk. Hash it (`sha256sum`) for chain of custody.
3. Isolate the host from the network after capture (if capture uses the network, keep only that path). Prefer network-level isolation (security group, VLAN, switch port) over powering off.
4. Preserve logs: copy auth logs, the journal, audit logs, shell histories and login records off the host read-only, with hashes.
5. Analyse the memory image offline with Volatility 3, which needs the symbol table (ISF) for that exact kernel. Useful plugins: `linux.pagecache.Files` and `linux.pagecache.InodePages` (cached view of `su` and other files), `linux.pstree.PsTree`, `linux.pslist.PsList`, `linux.bash.Bash`. The launcher may be called vol, vol.py or vol3.
6. Rotate credentials: SSH keys, passwords, API tokens, certificates and secrets that were on the host or reachable from it. Review hosts it could reach.
7. Look for persistence: new accounts, authorized_keys changes, cron and systemd units, new setuid files, loaded modules. Patching does not remove a foothold.
8. Rebuild from a known-good image on a patched kernel instead of cleaning in place. Restore data only after checking it.
9. Run this check on other hosts in the same environment, and on every node that shares a page cache with affected containers.

Human walkthrough of a full investigation: https://ledlight33.github.io/copyfail-dfir/
