# Changelog

All notable changes to this project are documented in this file.

## v1.0.0 - 2026-10-03

Initial release.

### Added

- `copyfail-check/SKILL.md`: an Agent Skill that guides an AI agent through a read-only Copy Fail (CVE-2026-31431) check and the interpretation of its result.
- `copyfail-check/scripts/copyfail_check.sh`: the read-only check script, with text and `--json` output and the options `--extra`, `--no-scan`, `--max-files`, `--version` and `--help`.
- Kernel assessment against the upstream fixed releases (5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12 and 7.0) and the Ubuntu fixed ABI numbers (6.8.0-117 and 6.17.0-29, generic and lowlatency flavours), with `check_vendor` for other vendor kernels.
- Exposure checks: AEAD build configuration, loaded module, modprobe block and `initcall_blacklist`.
- Integrity check that compares a normal (cached) read with a direct `O_DIRECT` disk read of every setuid file on the root filesystem plus `/etc/passwd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, `runc` and any `--extra` paths, with one re-check to rule out files that changed.
- Package manager check of `su` (`dpkg -V` or `rpm -V`).
- Weak traces: kernel log PF_ALG timing, shell history that mentions copy.fail, and auditd socket events (root only).
- Verdicts `NOT_EXPOSED`, `EXPOSED_NO_INDICATORS`, `EXPOSED_INCONCLUSIVE` and `SUSPECT`, with exit codes 0, 1, 2 and 64.
- Unit tests (`tests/run_tests.sh`, 107 tests) and a GitHub Actions workflow with the unit tests, a JSON smoke test that checks the top-level keys and a non-blocking ShellCheck step.
- README, SECURITY policy and MIT license.
