#!/usr/bin/env bash
# Unit tests for copyfail_check.sh. They call pure functions with mocked reads, plus a few
# read-only runs of the script itself (usage errors, JSON validity). Nothing here changes the system.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../copyfail-check/scripts/copyfail_check.sh"

COPYFAIL_CHECK_SOURCE_ONLY=1
export COPYFAIL_CHECK_SOURCE_ONLY
# shellcheck source=/dev/null
. "$SCRIPT"

PASS=0; FAIL=0
check() { # release os_id expected_status
  assess_kernel "$1" "$2"
  if [ "$KERNEL_STATUS" = "$3" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL: release='$1' os='$2' expected=$3 got=$KERNEL_STATUS ($KERNEL_NOTE)"
  fi
}

# Upstream kernels around each fixed boundary
check "5.10.253" "" affected
check "5.10.254" "" fixed
check "5.15.203" "" affected
check "5.15.204" "" fixed
check "6.1.169" "" affected
check "6.1.170" "" fixed
check "6.6.136" "" affected
check "6.6.137" "" fixed
check "6.12.84" "" affected
check "6.12.85" "" fixed
check "6.18.21" "" affected
check "6.18.22" "" fixed
check "6.19.11" "" affected
check "6.19.12" "" fixed
check "7.0.0" "" fixed
check "7.0.0-rc3" "" affected
check "7.1.5" "" fixed
check "7.1.0-rc1" "" fixed

# Non-LTS and end-of-life branches fall inside the NVD ranges
check "5.11.5" "" affected
check "6.3.2" "" affected
check "6.13.5" "" affected
check "6.17.4" "" affected

# Before the bug was introduced
check "4.13.16" "" not_affected
check "3.10.0-1160.el7.x86_64" "centos" not_affected
check "4.14.0" "" affected

# Ubuntu uses ABI numbers from Ubuntu's CVE page, for the generic and lowlatency flavours only
check "6.8.0-101-generic" ubuntu affected
check "6.8.0-116-generic" ubuntu affected
check "6.8.0-117-generic" ubuntu fixed
check "6.8.0-120-generic" ubuntu fixed
check "6.17.0-28-generic" ubuntu affected
check "6.17.0-29-generic" ubuntu fixed
check "6.8.0-100-lowlatency" ubuntu affected
check "6.8.0-117-lowlatency" ubuntu fixed
# Cloud flavours have their own ABI numbers (1007 here is not "newer than 29")
check "6.17.0-1007-aws" ubuntu check_vendor
check "6.8.0-1030-aws" ubuntu check_vendor
check "6.8.0-1012-azure" ubuntu check_vendor

# Vendor kernels without a known mapping must be verified with the vendor
check "5.15.0-179-generic" ubuntu check_vendor
check "5.14.0-503.el9.x86_64" rhel check_vendor
check "6.1.0-25-amd64" debian check_vendor
check "6.6.87.2-microsoft-standard-WSL2" "" check_vendor
check "6.8.0-101-generic" debian check_vendor

# Vendor kernel whose base already includes the upstream fix
check "6.12.90-1-lts" arch fixed
check "7.2.8-custom" "" fixed

# Release strings that cannot be parsed are never reported as fixed or safe
check "garbage" "" check_vendor
check "" "" check_vendor

# Parser details
parse_release "6.6.87.2-microsoft-standard-WSL2"
[ "$KERNEL_BASE" = "6.6.87" ] && [ "$KERNEL_VENDOR" = 1 ] && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: parse WSL release base=$KERNEL_BASE vendor=$KERNEL_VENDOR"; }
parse_release "7.0"
[ "$KERNEL_BASE" = "7.0.0" ] && [ "$KERNEL_VENDOR" = 0 ] && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: parse 7.0 base=$KERNEL_BASE vendor=$KERNEL_VENDOR"; }

expect() { # name actual expected
  if [ "$2" = "$3" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1)); echo "FAIL: $1: expected [$3] got [$2]"
  fi
}

# JSON escaping helper
out=$(jesc 'a"b\c'"$(printf '\t')"'d')
expect "jesc quote, backslash, tab" "$out" 'a\"b\\c\td'
out=$(jarr "one" 'two "2"')
expect "jarr two items" "$out" '["one","two \"2\""]'
out=$(jarr)
expect "jarr empty" "$out" '[]'
out=$(jesc "$(printf 'x\001y\rz')")
expect "jesc replaces control characters" "$out" 'x?y?z'
out=$(jesc 'line one
line two')
expect "jesc keeps a newline as \\n" "$out" 'line one\nline two'
out=$(clean "$(printf 'a\nb\033[31mc')")
expect "clean strips newlines and escapes for the text report" "$out" 'a?b?[31mc'

# JSON validity with awkward strings (needs python3, skipped when it is missing)
if command -v python3 >/dev/null 2>&1; then
  tabc=$(printf '\t')
  awk_json=$(jarr 'quote " back \ tab'"$tabc"'end
second line' "$(printf 'cr\rctl\001end')" "unicode: $(printf '\316\265\316\273\316\273')" 'trailing backslash \' '')
  printf '%s' "$awk_json" | python3 -c 'import json,sys; a=json.load(sys.stdin); assert len(a)==5 and a[0].count("\n")==1 and a[2].startswith("unicode")' 2>/dev/null
  expect "jarr output with awkward strings is valid JSON" "$?" "0"
fi

# --- hash helpers with the real tools (skipped when direct reads are unsupported here) -------
realf=$(mktemp); head -c 10000 /dev/urandom > "$realf"
if direct_supported "$realf"; then
  expect "real cached and direct hashes agree" "$(direct_hash "$realf")" "$(cached_hash "$realf")"
fi
out=$(direct_hash "/nonexistent/file"); rc=$?
expect "direct_hash prints nothing and fails for a missing file" "$rc/$out" "1/"
rm -f "$realf"

# --- compare_file with mocked reads (no real exploit or page cache needed) ---------------
reset_scan() { SCAN_TOTAL=0; SCAN_OK=0; SCAN_UNSUPPORTED=0; SCAN_UNREADABLE=0; MISMATCHES=(); TRANSIENT=(); SEEN="|"; }
sleep() { :; }
tmpf=$(mktemp); echo data > "$tmpf"
flag=$(mktemp -u)

reset_scan; direct_supported() { return 0; }; cached_hash() { echo aaa; }; direct_hash() { echo aaa; }
compare_file "$tmpf"
expect "matching reads" "$SCAN_OK/${#MISMATCHES[@]}/${#TRANSIENT[@]}" "1/0/0"

reset_scan; direct_hash() { echo bbb; }
compare_file "$tmpf"
expect "persistent mismatch is confirmed" "$SCAN_OK/${#MISMATCHES[@]}/${#TRANSIENT[@]}" "0/1/0"

reset_scan; direct_hash() { if [ -e "$flag" ]; then echo aaa; else : > "$flag"; echo bbb; fi; }
compare_file "$tmpf"
expect "mismatch that vanishes on re-check is transient" "$SCAN_OK/${#MISMATCHES[@]}/${#TRANSIENT[@]}" "0/0/1"

reset_scan; direct_hash() { return 1; }
compare_file "$tmpf"
expect "failed direct read is not a mismatch" "$SCAN_UNSUPPORTED/${#MISMATCHES[@]}" "1/0"

reset_scan; cached_hash() { return 0; }; direct_hash() { echo aaa; }
compare_file "$tmpf"
expect "failed cached read (file vanished or unreadable) is not a mismatch" "$SCAN_UNREADABLE/${#MISMATCHES[@]}" "1/0"

reset_scan; direct_supported() { return 1; }
compare_file "$tmpf"
expect "unsupported direct reads are not a mismatch" "$SCAN_UNSUPPORTED/${#MISMATCHES[@]}" "1/0"

reset_scan; compare_file "/nonexistent/file"
expect "missing file is unreadable" "$SCAN_UNREADABLE/${#MISMATCHES[@]}" "1/0"

# The same file reachable under several names is compared once
reset_scan; direct_supported() { return 0; }; cached_hash() { echo aaa; }; direct_hash() { echo aaa; }
link=$(mktemp -u); ln -s "$tmpf" "$link"
scan_path "$tmpf"; scan_path "$link"; scan_path "$tmpf"
expect "same file under several names is compared once" "$SCAN_TOTAL/$SCAN_OK" "1/1"
rm -f "$link" "$tmpf" "$flag"

# --- compute_exposure ------------------------------------------------------------------
t_exposure() { # kernel_status cfg initcall modblocked modloaded expected
  KERNEL_STATUS="$1"; KERNEL_NOTE="note"; CFG_AEAD="$2"; INITCALL_BLOCK="$3"; MOD_BLOCKED="$4"; MOD_LOADED="$5"
  compute_exposure; expect "exposure $*" "$EXPOSURE" "$6"
}
t_exposure fixed unknown no no no not_exposed
t_exposure not_affected y no no no not_exposed
t_exposure affected n no no no not_exposed
t_exposure affected m no yes no mitigated
t_exposure affected m no yes yes exposed
t_exposure affected y yes no no mitigated
t_exposure check_vendor m no no no possibly_exposed
t_exposure affected m no no no exposed
t_exposure affected unknown no yes no mitigated
# A modprobe rule does nothing when the code is built into the kernel
t_exposure affected y no yes no exposed
case "$EXPOSURE_NOTE" in *"has no effect"*) PASS=$((PASS + 1)) ;; *) FAIL=$((FAIL + 1)); echo "FAIL: built-in note missing: $EXPOSURE_NOTE" ;; esac
t_exposure check_vendor y no yes no possibly_exposed
# initcall_blacklist does work for built-in code
t_exposure affected y yes yes no mitigated

# --- compute_verdict: every branch -----------------------------------------------------
t_verdict() { # name expected_verdict expected_exit
  EXPOSURE_NOTE=""; compute_verdict
  expect "$1 verdict" "$VERDICT" "$2"; expect "$1 exit" "$EXIT" "$3"
}
MISMATCHES=("/usr/bin/su"); TRANSIENT=(); PKG_STATE=clean; EXPOSURE=exposed; SCAN_STATE=done; WEAK=()
t_verdict "confirmed mismatch" SUSPECT 2
MISMATCHES=(); PKG_STATE=changed; t_verdict "package manager reports a change" SUSPECT 2
PKG_STATE=clean; EXPOSURE=not_exposed; t_verdict "not exposed" NOT_EXPOSED 0
WEAK=("weak signal"); t_verdict "not exposed but weak signal" NOT_EXPOSED 1
WEAK=(); EXPOSURE=exposed; SCAN_STATE=done; t_verdict "exposed, clean scan" EXPOSED_NO_INDICATORS 1
TRANSIENT=("/etc/passwd"); t_verdict "exposed, clean scan with a transient file" EXPOSED_NO_INDICATORS 1
TRANSIENT=()
SCAN_STATE=inconclusive; t_verdict "exposed, inconclusive scan" EXPOSED_INCONCLUSIVE 1
SCAN_STATE=skipped; t_verdict "exposed, scan skipped" EXPOSED_INCONCLUSIVE 1
EXPOSURE=mitigated; MISMATCHES=("/usr/bin/sudo"); t_verdict "mismatch beats a mitigation" SUSPECT 2

# --- the script itself: usage errors and output shape (read-only runs) ----------------------
unset COPYFAIL_CHECK_SOURCE_ONLY
bash "$SCRIPT" --bogus >/dev/null 2>&1;                expect "unknown option exits 64" "$?" "64"
bash "$SCRIPT" --max-files abc >/dev/null 2>&1;        expect "non-numeric --max-files exits 64" "$?" "64"
bash "$SCRIPT" --max-files >/dev/null 2>&1;            expect "--max-files without a value exits 64" "$?" "64"
bash "$SCRIPT" --max-files 99999999999 >/dev/null 2>&1; expect "huge --max-files exits 64" "$?" "64"
bash "$SCRIPT" --extra >/dev/null 2>&1;                expect "--extra without a path exits 64" "$?" "64"
bash "$SCRIPT" --version >/dev/null 2>&1;              expect "--version exits 0" "$?" "0"
bash "$SCRIPT" --help >/dev/null 2>&1;                 expect "--help exits 0" "$?" "0"
sh "$SCRIPT" --version >/dev/null 2>&1;                expect "running under sh is refused with 64" "$?" "64"
bash "$SCRIPT" --no-scan >/dev/null 2>&1;              rc=$?
case "$rc" in 0|1|2) PASS=$((PASS + 1)) ;; *) FAIL=$((FAIL + 1)); echo "FAIL: --no-scan exit code $rc" ;; esac
if command -v python3 >/dev/null 2>&1; then
  for opts in "--json --no-scan" "--json --max-files 3"; do
    # shellcheck disable=SC2086
    bash "$SCRIPT" $opts 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin)
assert set(d)=={"tool","version","timestamp","host","exposure","integrity","traces","verdict"}
assert d["verdict"]["status"] in ("NOT_EXPOSED","EXPOSED_NO_INDICATORS","EXPOSED_INCONCLUSIVE","SUSPECT")
assert d["exposure"]["status"] in ("not_exposed","mitigated","possibly_exposed","exposed")
assert d["exposure"]["kernel_status"] in ("not_affected","fixed","affected","check_vendor")' 2>/dev/null
    expect "script --$opts prints valid JSON with the documented keys" "$?" "0"
  done
  # A missing --extra path counts as unreadable and is never reported as a mismatch
  bash "$SCRIPT" --json --max-files 0 --extra /nonexistent/path 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin)["integrity"]
assert d["unreadable"]>=1 and d["mismatches"]==[] and d["capped"]=="yes"' 2>/dev/null
  expect "missing --extra path is unreadable, not a mismatch" "$?" "0"
fi

echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
