# Security policy

## Scope

This project is a defensive checker. It helps an AI agent or a human find out whether a Linux host is exposed to Copy Fail (CVE-2026-31431) and whether privileged files look different in the page cache than on disk. It uses read-only commands and never changes the system.

## No exploit code

This project must never contain exploit code. That means no proof-of-concept source, no payloads, and nothing that downloads or runs exploit code or triggers the bug. Pull requests that add any of these will be closed. The checker detects results (a cached-versus-disk difference). It never reproduces the attack.

## Reporting a mistake or a security issue

- Wrong or outdated facts, false positives, false negatives, bugs and ordinary security concerns: open a GitHub issue in this repository.
- Anything sensitive, for example a flaw in the script that makes it write to or change a system, or a problem you do not want to disclose publicly yet: contact Marino Bekios privately through LinkedIn (https://linkedin.com/in/marbekios) and do not post the details in a public issue.

If the script ever modifies a system, that is a security bug and will be treated as one.

## Supported versions

Only the latest release is supported.
