# Sources

Facts in this skill come from the sources below, as reviewed for the human guide at https://ledlight33.github.io/copyfail-dfir/ (source: https://github.com/ledlight33/copyfail-dfir). Dates are as published. Check them again for anything you quote to a user, because this topic changes.

## Primary and vendor

- Original disclosure site: https://copy.fail/
- NVD record (CVSS, affected ranges): https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-31431
- Upstream fix commit: https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5
- CISA KEV addition, 2026-05-01: https://www.cisa.gov/news-events/alerts/2026/05/01/cisa-adds-one-known-exploited-vulnerability-catalog
- Ubuntu CVE page: https://ubuntu.com/security/CVE-2026-31431
- Ubuntu blog: https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available
- Red Hat bulletin RHSB-2026-002: https://access.redhat.com/security/vulnerabilities/RHSB-2026-002
- Debian tracker: https://security-tracker.debian.org/tracker/CVE-2026-31431
- Amazon Linux: https://explore.alas.aws.amazon.com/CVE-2026-31431.html
- Docker, mitigating in Docker Engine: https://www.docker.com/blog/mitigating-cve-2026-31431-copy-fail-in-docker-engine/
- containerd default seccomp change: https://github.com/containerd/containerd/pull/14245
- Moby profiles socket-domain allow-list: https://github.com/moby/profiles/pull/39

## Analysis, exploitation and detection

- Xint, distributions: https://xint.io/blog/copy-fail-linux-distributions
- Xint, pod to host: https://xint.io/blog/copy-fail-pod-to-host
- Microsoft, 2026-05-01: https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/
- Microsoft, Dirty Frag, 2026-05-08: https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/
- SecurityWeek, exploitation begins: https://www.securityweek.com/exploitation-of-copy-fail-linux-vulnerability-begins/
- CrowdStrike 2026 threat hunting report: https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/
- Cloudflare response: https://blog.cloudflare.com/copy-fail-linux-vulnerability-mitigation/
- VulnCheck, targeted vulnerabilities, May 2026: https://www.vulncheck.com/blog/routinely-targeted-vulnerabilities-may-2026
- Elastic Security Labs: https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild
- Splunk detection: https://www.splunk.com/en_us/blog/security/detecting-copy-fail-cve-2026-31431-phenomenal-power-itty-bitty-script.html
- Sysdig: https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds
- Kubernetes RuntimeDefault test: https://juliet.sh/blog/we-tested-copy-fail-in-kubernetes-pss-restricted-runtime-default-af-alg
- Andrea Fortuna write-up: https://andreafortuna.org/2026/05/02/copy-fail-cve-2026-31431/

## Related bugs

- Dirty Frag, The Hacker News: https://thehackernews.com/2026/05/linux-kernel-dirty-frag-lpe-exploit.html
- Fragnesia, The Hacker News: https://thehackernews.com/2026/05/new-fragnesia-linux-kernel-lpe-grants.html
- DirtyClone, JFrog: https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/

## Forensics

- Volatility 3 page cache plugins: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.pagecache.html

## Human guide

- Walkthrough and read-only checklist (open `#step-8`): https://ledlight33.github.io/copyfail-dfir/
