#!/usr/bin/env bash
# copyfail_check.sh: read-only check for CVE-2026-31431 (Copy Fail) exposure and signs of tampering.
#
# Safety: this script only READS. It never writes files, never uses sudo, never loads or
# unloads modules, never drops caches and never runs or downloads exploit code.
# License: MIT. Part of copyfail-check-skill.
#
# Exit codes: 0 not exposed, 1 exposed / unknown / weak signals, 2 suspect (confirmed mismatch),
#             64 usage error.

# This script needs real bash (arrays, process substitution). Refuse sh, dash, ash and posix mode.
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix 2>/dev/null; then
  echo "copyfail_check.sh needs bash (not sh). Run it as: bash copyfail_check.sh" >&2
  exit 64
fi

VERSION="1.0.0"
LC_ALL=C
export LC_ALL

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# Parse a kernel release string into KERNEL_BASE (major.minor.patch), KERNEL_VENDOR (0/1), KERNEL_RC (0/1)
parse_release() {
  local rel="$1"
  KERNEL_RC=0
  case "$rel" in *-rc[0-9]*) KERNEL_RC=1 ;; esac
  KERNEL_BASE=$(printf '%s' "$rel" | sed -E 's/^([0-9]+)\.([0-9]+)\.?([0-9]*).*/\1.\2.\3/')
  case "$KERNEL_BASE" in *.) KERNEL_BASE="${KERNEL_BASE}0" ;; esac
  if printf '%s' "$rel" | grep -qE '^[0-9]+\.[0-9]+(\.[0-9]+)?(-rc[0-9]+)?$'; then
    KERNEL_VENDOR=0
  else
    KERNEL_VENDOR=1
  fi
}

# Numeric version compare. Echoes -1, 0 or 1 for a<b, a==b, a>b (major.minor.patch).
vcmp() {
  local a="$1" b="$2" i x y
  for i in 1 2 3; do
    x=$(printf '%s' "$a" | cut -d. -f"$i"); y=$(printf '%s' "$b" | cut -d. -f"$i")
    x=${x:-0}; y=${y:-0}
    if [ "$x" -lt "$y" ]; then echo -1; return; fi
    if [ "$x" -gt "$y" ]; then echo 1; return; fi
  done
  echo 0
}
ver_ge() { [ "$(vcmp "$1" "$2")" -ge 0 ]; }
ver_lt() { [ "$(vcmp "$1" "$2")" -lt 0 ]; }

# Upstream affected ranges from the NVD record: start (inclusive), end (exclusive).
# 4.14 <= v < 5.10.254; 5.11 <= v < 5.15.204; 5.16 <= v < 6.1.170; 6.2 <= v < 6.6.137;
# 6.7 <= v < 6.12.85; 6.13 <= v < 6.18.22; 6.19 <= v < 6.19.12; 7.0-rc* only.
UPSTREAM_RANGES="4.14.0 5.10.254|5.11.0 5.15.204|5.16.0 6.1.170|6.2.0 6.6.137|6.7.0 6.12.85|6.13.0 6.18.22|6.19.0 6.19.12"

in_upstream_affected_range() {
  local base="$1" pair s e
  local IFS='|'
  for pair in $UPSTREAM_RANGES; do
    s=${pair% *}; e=${pair#* }
    if ver_ge "$base" "$s" && ver_lt "$base" "$e"; then return 0; fi
  done
  return 1
}

# Ubuntu fixed ABI numbers per Ubuntu's CVE page: 24.04 GA kernel 6.8.0-117, HWE kernel 6.17.0-29.
# These apply to the generic and lowlatency flavours only. Cloud flavours (aws, azure, gcp, oracle
# and others) have their own ABI numbering (for example 6.17.0-1007-aws) and must not be compared.
ubuntu_fixed_abi() {
  case "$1" in
    6.8.0) echo 117 ;;
    6.17.0) echo 29 ;;
    *) echo "" ;;
  esac
}

# assess_kernel RELEASE OS_ID -> sets KERNEL_STATUS (not_affected|fixed|affected|check_vendor) and KERNEL_NOTE
assess_kernel() {
  local rel="$1" osid="$2" abi fixed_abi flavour
  parse_release "$rel"
  KERNEL_STATUS="check_vendor"
  KERNEL_NOTE=""

  if ! printf '%s' "$KERNEL_BASE" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    KERNEL_NOTE="Could not parse the kernel release string. Check your vendor's security tracker."
    return
  fi
  if ver_lt "$KERNEL_BASE" "4.14.0"; then
    KERNEL_STATUS="not_affected"; KERNEL_NOTE="Kernel base $KERNEL_BASE is older than 4.14, where the bug was introduced."
    if [ "$KERNEL_VENDOR" = 1 ]; then KERNEL_NOTE="$KERNEL_NOTE Vendor kernels can backport changes, so confirm with your vendor if in doubt."; fi
    return
  fi
  if [ "$KERNEL_RC" = 1 ] && [ "$KERNEL_BASE" = "7.0.0" ]; then
    KERNEL_STATUS="affected"; KERNEL_NOTE="Kernel 7.0 release candidates are in the affected range."; return
  fi
  if ver_ge "$KERNEL_BASE" "7.0.0"; then
    KERNEL_STATUS="fixed"; KERNEL_NOTE="Kernel base $KERNEL_BASE includes the upstream fix."; return
  fi

  if in_upstream_affected_range "$KERNEL_BASE"; then
    if [ "$KERNEL_VENDOR" = 0 ]; then
      KERNEL_STATUS="affected"; KERNEL_NOTE="Upstream kernel $KERNEL_BASE is below the fixed release for its branch."
      return
    fi
    if [ "$osid" = "ubuntu" ]; then
      fixed_abi=$(ubuntu_fixed_abi "$KERNEL_BASE")
      abi=$(printf '%s' "$rel" | sed -nE 's/^[0-9]+\.[0-9]+\.[0-9]+-([0-9]+).*/\1/p')
      flavour=$(printf '%s' "$rel" | sed -nE 's/^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-(.*)$/\1/p')
      case "$flavour" in generic|generic-*|lowlatency|lowlatency-*) ;; *) fixed_abi="" ;; esac
      if [ -n "$fixed_abi" ] && [ -n "$abi" ]; then
        if [ "$abi" -ge "$fixed_abi" ]; then
          KERNEL_STATUS="fixed"; KERNEL_NOTE="Ubuntu kernel ABI $abi is at or above the fixed ABI $fixed_abi for $KERNEL_BASE."
        else
          KERNEL_STATUS="affected"; KERNEL_NOTE="Ubuntu kernel ABI $abi is below the fixed ABI $fixed_abi for $KERNEL_BASE."
        fi
        return
      fi
    fi
    KERNEL_STATUS="check_vendor"
    KERNEL_NOTE="Vendor kernel with upstream base $KERNEL_BASE, which is below the upstream fix. Distributions backport fixes, so check your vendor's security tracker."
    return
  fi

  KERNEL_STATUS="fixed"
  KERNEL_NOTE="Kernel base $KERNEL_BASE is at or above the upstream fixed release for its branch."
}

# Strip control characters (including newlines and terminal escapes) from untrusted text before
# it is printed in the text report, so file names and history lines cannot forge report lines.
clean() { printf '%s' "$1" | tr '\001-\037\177' '?'; }

# JSON string escaping. Control characters other than tab and newline are replaced by '?'.
jesc() {
  printf '%s' "$1" | tr '\001-\010\013-\037\177' '?' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | awk 'BEGIN{ORS=""} { if (NR>1) print "\\n"; print $0 }'
}
jarr() {
  local first=1 x
  printf '['
  for x in "$@"; do
    if [ "$first" = 0 ]; then printf ','; fi
    first=0
    printf '"%s"' "$(jesc "$x")"
  done
  printf ']'
}

usage() {
  cat <<'EOF'
copyfail_check.sh [options]

Read-only check for CVE-2026-31431 (Copy Fail) exposure and signs of page-cache tampering.

Options:
  --json            print machine-readable JSON instead of the text report
  --extra PATH      also compare PATH (cached read vs direct disk read); repeatable
  --no-scan         skip the cached-vs-disk comparison (kernel and config checks only)
  --max-files N     compare at most N files (default 3000)
  --version         print the script version
  -h, --help        show this help

Exit codes: 0 not exposed, 1 exposed / unknown / weak signals, 2 suspect (confirmed mismatch),
            64 usage error.
Run as root for full coverage (kernel log, audit log, other users' shell history).
The script is designed to be read-only. Read it before you run it and use it at your own
risk (see the disclaimer in the README).
EOF
}

# Hash helpers and the per-file comparison. Globals used: SCAN_TOTAL SCAN_OK SCAN_UNSUPPORTED
# SCAN_UNREADABLE MISMATCHES TRANSIENT SEEN.
# A hash helper prints nothing when the read failed, so a failed read is never taken for a mismatch.
cached_hash() { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }
direct_hash() {
  local out
  out=$( set -o pipefail; dd if="$1" iflag=direct bs=4096 2>/dev/null | sha256sum 2>/dev/null ) || return 1
  printf '%s\n' "${out%% *}"
}

# Probe whether direct (O_DIRECT) reads work for a file on its filesystem.
direct_supported() { dd if="$1" iflag=direct bs=4096 count=1 of=/dev/null 2>/dev/null; }

# Note: a direct read first writes back any dirty cached pages of the range, so normal unflushed
# writes do not show up as a difference. A page poisoned through the AF_ALG bug is never marked
# dirty, which is why the difference is visible.
compare_file() {
  local f="$1" a b pass
  SCAN_TOTAL=$((SCAN_TOTAL + 1))
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then SCAN_UNREADABLE=$((SCAN_UNREADABLE + 1)); return; fi
  if ! direct_supported "$f"; then
    SCAN_UNSUPPORTED=$((SCAN_UNSUPPORTED + 1)); return
  fi
  for pass in 1 2; do
    a=$(cached_hash "$f"); b=$(direct_hash "$f")
    if [ -z "$a" ]; then SCAN_UNREADABLE=$((SCAN_UNREADABLE + 1)); return; fi
    if [ -z "$b" ]; then SCAN_UNSUPPORTED=$((SCAN_UNSUPPORTED + 1)); return; fi
    if [ "$a" = "$b" ]; then
      if [ "$pass" = 1 ]; then SCAN_OK=$((SCAN_OK + 1)); else TRANSIENT+=("$f"); fi
      return
    fi
    # Re-check once to rule out a file that changed between the two reads.
    if [ "$pass" = 1 ]; then sleep 1; fi
  done
  MISMATCHES+=("$f")
}

# Compare a path once, even when it is reachable under several names (symlinks, merged /usr).
scan_path() {
  local f="$1" real
  real=$(readlink -f -- "$f" 2>/dev/null)
  [ -n "$real" ] || real="$f"
  case "$SEEN" in *"|$real|"*) return ;; esac
  SEEN="$SEEN$real|"
  compare_file "$f"
}

# Decide the exposure status from the gathered facts. In: KERNEL_STATUS KERNEL_NOTE CFG_AEAD
# INITCALL_BLOCK MOD_BLOCKED MOD_LOADED. Out: EXPOSURE EXPOSURE_NOTE.
# A modprobe rule cannot stop code that is built into the kernel (CFG_AEAD=y), only initcall_blacklist can.
compute_exposure() {
  EXPOSURE=exposed; EXPOSURE_NOTE=""
  if [ "$KERNEL_STATUS" = not_affected ] || [ "$KERNEL_STATUS" = fixed ]; then
    EXPOSURE=not_exposed; EXPOSURE_NOTE="$KERNEL_NOTE"
  elif [ "$CFG_AEAD" = n ]; then
    EXPOSURE=not_exposed; EXPOSURE_NOTE="The AEAD interface of AF_ALG is not compiled into this kernel."
  elif [ "$INITCALL_BLOCK" = yes ] || { [ "$MOD_BLOCKED" = yes ] && [ "$MOD_LOADED" = no ] && [ "$CFG_AEAD" != y ]; }; then
    EXPOSURE=mitigated; EXPOSURE_NOTE="algif_aead is blocked. This does not cover the related page-cache bugs (Dirty Frag, Fragnesia, DirtyClone). Patch the kernel."
  elif [ "$KERNEL_STATUS" = check_vendor ]; then
    EXPOSURE=possibly_exposed; EXPOSURE_NOTE="$KERNEL_NOTE"
  else
    EXPOSURE=exposed; EXPOSURE_NOTE="$KERNEL_NOTE"
  fi
  if { [ "$EXPOSURE" = exposed ] || [ "$EXPOSURE" = possibly_exposed ]; } && [ "$MOD_BLOCKED" = yes ] && [ "$CFG_AEAD" = y ]; then
    EXPOSURE_NOTE="$EXPOSURE_NOTE A modprobe block rule exists, but algif_aead is built into this kernel, so the rule has no effect."
  fi
}

# Decide the verdict. In: MISMATCHES TRANSIENT PKG_STATE EXPOSURE EXPOSURE_NOTE SCAN_STATE WEAK.
# Out: VERDICT EXIT VERDICT_TEXT.
compute_verdict() {
  if [ "${#MISMATCHES[@]}" -gt 0 ]; then
    VERDICT=SUSPECT; EXIT=2
    VERDICT_TEXT="Confirmed cached-vs-disk mismatch on ${#MISMATCHES[@]} file(s). This is Copy Fail or a related page-cache bug. Treat the host as compromised: do not reboot, do not drop caches, capture memory first."
  elif [ "$PKG_STATE" = changed ]; then
    VERDICT=SUSPECT; EXIT=2
    VERDICT_TEXT="The package manager reports su differs from the package. If the integrity comparison found no mismatch, the file on disk differs (a local change or tampering that is not page-cache only); if it did, the page cache was modified. Confirm, and capture memory first."
  elif [ "$EXPOSURE" = not_exposed ] || [ "$EXPOSURE" = mitigated ]; then
    VERDICT=NOT_EXPOSED; EXIT=0
    VERDICT_TEXT="Not exposed through this bug on this host. $EXPOSURE_NOTE"
  elif [ "$SCAN_STATE" = done ]; then
    VERDICT=EXPOSED_NO_INDICATORS; EXIT=1
    VERDICT_TEXT="Exposed to Copy Fail, but no cached-vs-disk mismatch was found right now. This is a good sign, not proof: the poisoned page can be evicted or lost on reboot."
    if [ "${#TRANSIENT[@]}" -gt 0 ]; then VERDICT_TEXT="$VERDICT_TEXT Some files differed once but matched on re-check (listed above)."; fi
  else
    VERDICT=EXPOSED_INCONCLUSIVE; EXIT=1
    VERDICT_TEXT="Exposed to Copy Fail and the integrity comparison could not run or was inconclusive (direct reads may be unsupported on this filesystem). Memory forensics is the way to confirm."
  fi
  if [ "$EXIT" -eq 0 ] && [ "${#WEAK[@]}" -gt 0 ]; then EXIT=1; fi
}

# Allow tests to source the helper functions without running the checks.
if [ "${COPYFAIL_CHECK_SOURCE_ONLY:-0}" = "1" ]; then
  return 0 2>/dev/null || exit 0
fi

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
JSON=0; SCAN=1; MAX_FILES=3000; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --no-scan) SCAN=0 ;;
    --max-files) shift; MAX_FILES="${1:-}" ;;
    --extra)
      shift
      if [ -z "${1:-}" ]; then echo "--extra needs a path" >&2; exit 64; fi
      EXTRA+=("$1") ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done
case "$MAX_FILES" in ''|*[!0-9]*) echo "--max-files needs a number" >&2; exit 64 ;; esac
if [ "${#MAX_FILES}" -gt 9 ]; then echo "--max-files is too large" >&2; exit 64; fi

if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
  echo "This check only applies to Linux." >&2
  exit 64
fi

# ---------------------------------------------------------------------------
# 1. Host facts
# ---------------------------------------------------------------------------
HOST_NAME=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)
[ -n "$HOST_NAME" ] || HOST_NAME=unknown
HOST_KERNEL=$(uname -r)
ARCH=$(uname -m)
EUID_V=${EUID:-1}
DISTRO_ID=""; DISTRO_PRETTY="unknown"
if [ -r /etc/os-release ]; then
  DISTRO_ID=$(sed -nE 's/^ID=("?)([^"]*)\1$/\2/p' /etc/os-release | head -1)
  DISTRO_PRETTY=$(sed -nE 's/^PRETTY_NAME=("?)([^"]*)\1$/\2/p' /etc/os-release | head -1)
fi
UPTIME_S=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
CONTAINER=no
if [ -f /.dockerenv ] || [ -f /run/.containerenv ] || [ -n "${container:-}" ] || grep -qE 'docker|kubepods|containerd|lxc|libpod' /proc/1/cgroup 2>/dev/null; then
  CONTAINER=yes
fi

# ---------------------------------------------------------------------------
# 2. Exposure: kernel version, build config, module and mitigations
# ---------------------------------------------------------------------------
assess_kernel "$HOST_KERNEL" "$DISTRO_ID"

CFG_AEAD=unknown; CFG_SRC=""; cfg_line=""
if [ -r /proc/config.gz ] && have zcat; then
  cfg_line=$(zcat /proc/config.gz 2>/dev/null | grep -E '^(# )?CONFIG_CRYPTO_USER_API_AEAD[= ]' | head -1)
  [ -n "$cfg_line" ] && CFG_SRC="/proc/config.gz"
fi
if [ -z "$cfg_line" ] && [ -r "/boot/config-$HOST_KERNEL" ]; then
  cfg_line=$(grep -E '^(# )?CONFIG_CRYPTO_USER_API_AEAD[= ]' "/boot/config-$HOST_KERNEL" 2>/dev/null | head -1)
  [ -n "$cfg_line" ] && CFG_SRC="/boot/config-$HOST_KERNEL"
fi
case "$cfg_line" in
  *"=y"*) CFG_AEAD=y ;;
  *"=m"*) CFG_AEAD=m ;;
  *"is not set"*) CFG_AEAD=n ;;
esac
# No readable build config: fall back to the module index files that ship with the kernel modules.
if [ "$CFG_AEAD" = unknown ]; then
  for mdir in "/lib/modules/$HOST_KERNEL" "/usr/lib/modules/$HOST_KERNEL"; do
    if [ -r "$mdir/modules.builtin" ] && grep -qE '(^|/)algif_aead\.ko' "$mdir/modules.builtin" 2>/dev/null; then
      CFG_AEAD=y; CFG_SRC="$mdir/modules.builtin"; break
    fi
    if [ -r "$mdir/modules.dep" ] && grep -qE '(^|/)algif_aead\.ko' "$mdir/modules.dep" 2>/dev/null; then
      CFG_AEAD=m; CFG_SRC="$mdir/modules.dep"; break
    fi
  done
fi

MOD_LOADED=no
grep -qE '^algif_aead ' /proc/modules 2>/dev/null && MOD_LOADED=yes
MOD_BLOCKED=no; MOD_BLOCK_NOTE=""
blk=$(grep -rhsE '^[[:space:]]*install[[:space:]]+algif[_-]aead[[:space:]]+(/usr)?/bin/(false|true)' /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d /run/modprobe.d 2>/dev/null | head -1)
if [ -n "$blk" ]; then MOD_BLOCKED=yes; MOD_BLOCK_NOTE="modprobe rule: $blk"; fi
INITCALL_BLOCK=no
grep -qE 'initcall_blacklist=[^ ]*(algif_aead_init|af_alg_init|crypto_authenc_esn_module_init)' /proc/cmdline 2>/dev/null && INITCALL_BLOCK=yes

compute_exposure

# ---------------------------------------------------------------------------
# 3. Integrity: cached read vs direct disk read of privileged files
# ---------------------------------------------------------------------------
SCAN_STATE=skipped; SCAN_TOTAL=0; SCAN_OK=0; SCAN_UNSUPPORTED=0; SCAN_UNREADABLE=0; SCAN_CAPPED=no
MISMATCHES=(); TRANSIENT=(); SEEN="|"

if [ "$SCAN" = 1 ]; then
  if have sha256sum && have dd && have find; then
    SCAN_STATE=done
    while IFS= read -r -d '' f; do
      if [ "$SCAN_TOTAL" -ge "$MAX_FILES" ]; then SCAN_CAPPED=yes; break; fi
      scan_path "$f"
    done < <(find / -xdev -perm -4000 -type f -print0 2>/dev/null)
    for f in /etc/passwd /etc/pam.d/su /etc/pam.d/sudo /usr/bin/su /bin/su /usr/bin/sudo /usr/bin/runc /usr/sbin/runc /usr/local/sbin/runc; do
      [ -e "$f" ] && scan_path "$f"
    done
    for f in "${EXTRA[@]}"; do scan_path "$f"; done
    if [ "$SCAN_OK" -eq 0 ] && [ "${#MISMATCHES[@]}" -eq 0 ]; then SCAN_STATE=inconclusive; fi
  else
    SCAN_STATE=inconclusive
  fi
fi

# Package manager view of su (reads through the page cache, so it can also notice tampering).
PKG_STATE=unavailable; PKG_NOTE=""
SU_PATH=$(command -v su 2>/dev/null)
SU_REAL=$(readlink -f "$SU_PATH" 2>/dev/null)
if [ -n "$SU_REAL" ]; then
  if have dpkg; then
    pkg=$(dpkg -S "$SU_REAL" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$pkg" ]; then
      if dpkg -V "$pkg" 2>/dev/null | grep -E "^..5" | grep -qE '[[:space:]](/usr)?/s?bin/su$'; then PKG_STATE=changed; else PKG_STATE=clean; fi
      PKG_NOTE="dpkg -V $pkg"
    fi
  elif have rpm; then
    pkg=$(rpm -qf "$SU_REAL" 2>/dev/null | head -1)
    case "$pkg" in *" "*) pkg="" ;; esac   # "file ... is not owned by any package"
    if [ -n "$pkg" ]; then
      if rpm -V "$pkg" 2>/dev/null | grep -E "^.{2}5" | grep -qE '[[:space:]](/usr)?/s?bin/su$'; then PKG_STATE=changed; else PKG_STATE=clean; fi
      PKG_NOTE="rpm -V $pkg"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4. Weak traces: kernel log timing, shell history, audit log
# ---------------------------------------------------------------------------
WEAK=()

DMESG_STATE=unreadable; DMESG_SECS=""
dm_out=""
if dmesg >/dev/null 2>&1; then
  DMESG_STATE=absent
  dm_out=$(dmesg 2>/dev/null | grep -i 'PF_ALG' | head -1)
elif have journalctl && journalctl -k -b --no-pager >/dev/null 2>&1; then
  DMESG_STATE=absent
  dm_out=$(journalctl -k -b --no-pager -o short-monotonic 2>/dev/null | grep -i 'PF_ALG' | head -1)
fi
if [ -n "$dm_out" ]; then
  DMESG_SECS=$(printf '%s' "$dm_out" | sed -nE 's/^\[ *([0-9]+)\..*/\1/p')
  if [ -z "$DMESG_SECS" ]; then
    DMESG_STATE=unparsed
  elif [ "$DMESG_SECS" -gt 300 ]; then
    DMESG_STATE=late
    WEAK+=("Kernel log shows the PF_ALG protocol family registered ${DMESG_SECS}s after boot (more than 300s can mean on-demand module loading).")
  else
    DMESG_STATE=normal
  fi
fi

HIST_CANDIDATES=("$HOME/.bash_history" "$HOME/.zsh_history")
if [ "$EUID_V" -eq 0 ]; then
  HIST_CANDIDATES+=(/root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history)
fi
HIST_FILES=(); HIST_SEEN="|"
for h in "${HIST_CANDIDATES[@]}"; do
  case "$HIST_SEEN" in *"|$h|"*) continue ;; esac
  HIST_SEEN="$HIST_SEEN$h|"; HIST_FILES+=("$h")
done
HIST_HITS=()
for h in "${HIST_FILES[@]}"; do
  [ -r "$h" ] || continue
  m=$(grep -n -m1 -i 'copy\.fail' "$h" 2>/dev/null | cut -c1-140)
  [ -n "$m" ] && HIST_HITS+=("$h: $m")
done
if [ "${#HIST_HITS[@]}" -gt 0 ]; then WEAK+=("Shell history mentions copy.fail in ${#HIST_HITS[@]} file(s).") ; fi

AUDIT_STATE=unavailable; AUDIT_HITS=0
if have ausearch && [ "$EUID_V" -eq 0 ]; then
  AUDIT_STATE=none
  AUDIT_HITS=$(ausearch -sc socket 2>/dev/null | grep -cE ' a0=26 a1=(5|80005) ')
  if [ "${AUDIT_HITS:-0}" -gt 0 ]; then
    AUDIT_STATE=hits
    WEAK+=("auditd recorded ${AUDIT_HITS} socket(AF_ALG, SOCK_SEQPACKET) call(s). Legitimate crypto tools also do this, so check which process made them.")
  fi
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
compute_verdict

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [ "$JSON" = 1 ]; then
  printf '{\n'
  printf '  "tool": "copyfail_check.sh", "version": "%s", "timestamp": "%s",\n' "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "host": {"name": "%s", "kernel": "%s", "arch": "%s", "distro": "%s", "root": %s, "container": %s, "uptime_seconds": %s},\n' \
    "$(jesc "$HOST_NAME")" "$(jesc "$HOST_KERNEL")" "$(jesc "$ARCH")" "$(jesc "$DISTRO_PRETTY")" \
    "$([ "$EUID_V" -eq 0 ] && echo true || echo false)" "$([ "$CONTAINER" = yes ] && echo true || echo false)" "${UPTIME_S:-0}"
  printf '  "exposure": {"status": "%s", "kernel_status": "%s", "kernel_base": "%s", "vendor_kernel": %s, "aead_config": "%s", "module_loaded": "%s", "modprobe_blocked": "%s", "initcall_blocked": "%s", "note": "%s"},\n' \
    "$EXPOSURE" "$KERNEL_STATUS" "$(jesc "$KERNEL_BASE")" "$([ "$KERNEL_VENDOR" = 1 ] && echo true || echo false)" "$CFG_AEAD" "$MOD_LOADED" "$MOD_BLOCKED" "$INITCALL_BLOCK" "$(jesc "$EXPOSURE_NOTE")"
  printf '  "integrity": {"scan": "%s", "files_checked": %s, "matched": %s, "direct_read_unsupported": %s, "unreadable": %s, "capped": "%s", "mismatches": %s, "transient": %s, "package_check": "%s"},\n' \
    "$SCAN_STATE" "$SCAN_TOTAL" "$SCAN_OK" "$SCAN_UNSUPPORTED" "$SCAN_UNREADABLE" "$SCAN_CAPPED" "$(jarr "${MISMATCHES[@]}")" "$(jarr "${TRANSIENT[@]}")" "$PKG_STATE"
  printf '  "traces": {"dmesg": "%s", "dmesg_seconds_after_boot": "%s", "history_hits": %s, "audit": "%s", "audit_hits": %s, "weak_signals": %s},\n' \
    "$DMESG_STATE" "$DMESG_SECS" "$(jarr "${HIST_HITS[@]}")" "$AUDIT_STATE" "${AUDIT_HITS:-0}" "$(jarr "${WEAK[@]}")"
  printf '  "verdict": {"status": "%s", "exit_code": %s, "summary": "%s"}\n' "$VERDICT" "$EXIT" "$(jesc "$VERDICT_TEXT")"
  printf '}\n'
else
  echo "Copy Fail (CVE-2026-31431) read-only check, v$VERSION"
  echo "Host: $(clean "$HOST_NAME") | $(clean "$DISTRO_PRETTY") | kernel $(clean "$HOST_KERNEL") | $ARCH | root: $([ "$EUID_V" -eq 0 ] && echo yes || echo no) | container: $CONTAINER"
  echo
  echo "== Exposure"
  echo "[INFO] Kernel assessment: $KERNEL_STATUS. $KERNEL_NOTE"
  echo "[INFO] AF_ALG AEAD build config: $CFG_AEAD ${CFG_SRC:+(from $CFG_SRC)}"
  echo "[INFO] Module loaded now: $MOD_LOADED | modprobe block: $MOD_BLOCKED ${MOD_BLOCK_NOTE:+($(clean "$MOD_BLOCK_NOTE"))} | initcall_blacklist: $INITCALL_BLOCK"
  case "$EXPOSURE" in
    not_exposed|mitigated) echo "[OK] Exposure: $EXPOSURE. $EXPOSURE_NOTE" ;;
    *) echo "[WARN] Exposure: $EXPOSURE. $EXPOSURE_NOTE" ;;
  esac
  if [ "$CONTAINER" = yes ]; then echo "[WARN] Running inside a container: the page cache is shared with the host, so results describe the host kernel."; fi
  echo
  echo "== Integrity (cached read vs direct disk read)"
  case "$SCAN_STATE" in
    skipped) echo "[INFO] Skipped (--no-scan)." ;;
    inconclusive) echo "[WARN] Inconclusive: checked $SCAN_TOTAL file(s), direct reads unsupported on $SCAN_UNSUPPORTED, unreadable $SCAN_UNREADABLE. This filesystem may not support direct reads." ;;
    done) echo "[INFO] Checked $SCAN_TOTAL file(s): $SCAN_OK matched, $SCAN_UNSUPPORTED unsupported, $SCAN_UNREADABLE unreadable$([ "$SCAN_CAPPED" = yes ] && echo " (stopped at the --max-files limit)")." ;;
  esac
  for f in "${MISMATCHES[@]}"; do echo "[ALERT] MISMATCH (confirmed on re-check): $(clean "$f")"; done
  for f in "${TRANSIENT[@]}"; do echo "[INFO] Differed once but matched on re-check (file changing?): $(clean "$f")"; done
  case "$PKG_STATE" in
    changed) echo "[ALERT] Package manager says su differs from the package ($PKG_NOTE)." ;;
    clean) echo "[OK] Package manager sees no change in su ($PKG_NOTE). A clean result proves little: the page may already be gone." ;;
    *) echo "[INFO] Package manager check unavailable." ;;
  esac
  echo
  echo "== Weak traces"
  echo "[INFO] Kernel log PF_ALG: $DMESG_STATE ${DMESG_SECS:+(${DMESG_SECS}s after boot)}"
  if [ "$AUDIT_STATE" = unavailable ]; then echo "[INFO] auditd: unavailable (needs root and the audit tools)"; else echo "[INFO] auditd: $AUDIT_STATE ($AUDIT_HITS matching socket calls)"; fi
  for h in "${HIST_HITS[@]}"; do echo "[WARN] History: $(clean "$h")"; done
  for w in "${WEAK[@]}"; do echo "[WARN] $w"; done
  echo
  echo "== Verdict: $VERDICT (exit $EXIT)"
  echo "$VERDICT_TEXT"
  if [ "$VERDICT" = SUSPECT ]; then
    echo "Next: do not reboot or drop caches. Capture memory (LiME or AVML), isolate the host, then investigate."
  fi
fi
exit "$EXIT"
