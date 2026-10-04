# Changelog

All notable changes to this project are documented in this file.

## v1.0.2 - 2026-10-04 (documentation only, the script is unchanged)

### Added

- A "Tested on" section in the README: what has been tested (Ubuntu 24.04 under WSL2, Ubuntu on GitHub Actions), what is expected to work but is not yet tested (other distributions), what the script needs, and a request to report results from other distributions.

## v1.0.1 - 2026-10-04 (documentation only, the script is unchanged)

### Added

- A "Disclaimer: check first, then run" section in the README: tested only in the author's environment, read the script before running it, test on a non-production machine first, supervise AI agents, side effects of read-only operations, no liability.
- The skill and `AGENTS.md` now tell an agent to explain what the script reads and wait for a clear go before the first run on a host.

### Changed

- Wording now says the script is "designed to be read-only" instead of promising it never changes anything.

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
- Agent-neutral install instructions for any agent, a standalone no-agent mode, and an `AGENTS.md` that points agents working in the repository to the skill.
- README, SECURITY policy and MIT license.
