#!/bin/bash
# tests/run-all.sh — exhaustive offline test suite for Basidium.
# Exits 0 if every assertion passes, non-zero on first failure.
# Run from repo root: tests/run-all.sh
#
# Hits everything testable without sudo / a NIC / NCCL / a switch.
# What it cannot exercise: live pcap_inject, sniffer fail-open detection,
# NCCL subprocess launch, --stop-on-* halt paths under real load, TUI.

set -u

PASS=0
FAIL=0
LOG_FAIL=0
TMP=$(mktemp -d -t basidium-test.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

BIN=./basidium
[[ -x $BIN ]] || { echo "build first: make"; exit 2; }

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yel()   { printf '\033[33m%s\033[0m' "$*"; }

assert_eq() {
    local label=$1 want=$2 got=$3
    if [[ $want == "$got" ]]; then
        PASS=$((PASS+1))
        printf '  %s %s\n' "$(green PASS)" "$label"
    else
        FAIL=$((FAIL+1))
        printf '  %s %s\n    want: %q\n    got : %q\n' "$(red FAIL)" "$label" "$want" "$got"
    fi
}

assert_exit() {
    local label=$1 want=$2 ; shift 2
    local out
    out=$("$@" 2>&1)
    local rc=$?
    if [[ $rc == "$want" ]]; then
        PASS=$((PASS+1))
        printf '  %s %s (exit %d)\n' "$(green PASS)" "$label" "$rc"
    else
        FAIL=$((FAIL+1))
        printf '  %s %s\n    want exit: %s  got: %s\n    output: %s\n' \
            "$(red FAIL)" "$label" "$want" "$rc" "$out"
    fi
}

assert_stderr_contains() {
    local label=$1 needle=$2 ; shift 2
    local out
    out=$("$@" 2>&1)
    if [[ $out == *"$needle"* ]]; then
        PASS=$((PASS+1))
        printf '  %s %s\n' "$(green PASS)" "$label"
    else
        FAIL=$((FAIL+1))
        printf '  %s %s\n    expected substring: %q\n    got: %q\n' \
            "$(red FAIL)" "$label" "$needle" "$out"
    fi
}

assert_file_nonempty() {
    local label=$1 path=$2
    if [[ -s $path ]]; then
        PASS=$((PASS+1))
        printf '  %s %s\n' "$(green PASS)" "$label"
    else
        FAIL=$((FAIL+1))
        printf '  %s %s (file empty or missing: %s)\n' "$(red FAIL)" "$label" "$path"
    fi
}

section() { echo; echo "=== $* ==="; }

# ------------------------------------------------------------------
section "1. Builds + selftest"
# ------------------------------------------------------------------
assert_exit "selftest" 0 $BIN --selftest

# ------------------------------------------------------------------
section "2. Help / version / list flags"
# ------------------------------------------------------------------
assert_exit "--version exit 0"        0 $BIN --version
out=$($BIN --version --json)
assert_eq "--version --json content"  '{"version": "2.5"}' "$out"
assert_exit "--help exit 0"           0 $BIN --help
assert_exit "-h exit 0"               0 $BIN -h
out=$($BIN --list-modes | tr '\n' ' ')
assert_eq "--list-modes content"      'mac arp dhcp pfc nd lldp stp igmp ' "$out"

# ------------------------------------------------------------------
section "3. Input validation — should reject"
# ------------------------------------------------------------------
assert_exit "-V 5000 (vlan>4094)"               1 $BIN -V 5000
assert_exit "-V abc (non-numeric)"              1 $BIN -V abc
assert_exit "-V -1 (negative)"                  1 $BIN -V -1
assert_exit "-t 0 (threads<1)"                  1 $BIN -t 0
assert_exit "-t 17 (threads>16)"                1 $BIN -t 17
assert_exit "-r -5 (negative pps)"              1 $BIN -r -5
assert_exit "-J 59 (frame too small)"           1 $BIN -J 59
assert_exit "-J 99999 (frame too large)"        1 $BIN -J 99999
assert_exit "-S 00:11 (incomplete OUI)"         1 $BIN -S 00:11
assert_exit "-S zzz (non-hex OUI)"              1 $BIN -S zzz
assert_exit "-S 100:200:300 (>0xFF byte)"       1 $BIN -S 100:200:300
assert_exit "-T 10.0.0.0/40 (mask>32)"          1 $BIN -T 10.0.0.0/40
assert_exit "-T 10.0.0.0/-1 (mask<0)"           1 $BIN -T 10.0.0.0/-1
assert_exit "-T 10.0.0.0 (no slash)"            1 $BIN -T 10.0.0.0
assert_exit "-T 999.999.999.999/24 (bad ip)"    1 $BIN -T 999.999.999.999/24
assert_exit "--vlan-pcp 8 (>7)"                 1 $BIN --vlan-pcp 8
assert_exit "--pfc-priority 8 (>7)"             1 $BIN --pfc-priority 8
assert_exit "--pfc-quanta 70000 (>0xFFFF)"      1 $BIN --pfc-quanta 70000
assert_exit "--qinq 0 (<1)"                     1 $BIN --qinq 0
assert_exit "--qinq 5000 (>4094)"               1 $BIN --qinq 5000
assert_exit "--vlan-range 0 (<1)"               1 $BIN --vlan-range 0
assert_exit "--duration 5x (bad suffix)"        1 $BIN --duration 5x
assert_exit "--duration -5 (negative)"          1 $BIN --duration -5
assert_exit "--duration abc (non-numeric)"      1 $BIN --duration abc
assert_exit "--payload neon (unknown pattern)"  1 $BIN --payload neon
assert_exit "--seed abc (non-numeric)"          1 $BIN --seed abc
assert_exit "--sweep 1:2 (too few colons)"      1 $BIN --sweep 1:2
assert_exit "--sweep 1:1:1 (b<=a)"              1 $BIN --sweep 1:1:1
assert_exit "--sweep 1:100:0 (step=0)"          1 $BIN --sweep 1:100:0
assert_exit "--burst 0:50 (count<=0)"           1 $BIN --burst 0:50
assert_exit "--burst 64 (no colon)"             1 $BIN --burst 64
assert_exit "-M nope (unknown mode)"            1 $BIN -M nope
assert_exit "no -i no --dry-run"                2 $BIN

# ------------------------------------------------------------------
section "4. Input validation — should accept"
# ------------------------------------------------------------------
assert_exit "-V 0 (untagged)"        0 $BIN -V 0     --print-config
assert_exit "-V 4094 (max)"          0 $BIN -V 4094  --print-config
assert_exit "-t 1 (min)"             0 $BIN -t 1     --print-config
assert_exit "-t 16 (max)"            0 $BIN -t 16    --print-config
assert_exit "-J 60 (min)"            0 $BIN -J 60    --print-config
assert_exit "-J 9216 (jumbo max)"    0 $BIN -J 9216  --print-config
assert_exit "--pfc-priority 0"       0 $BIN --pfc-priority 0 --print-config
assert_exit "--pfc-priority 7"       0 $BIN --pfc-priority 7 --print-config
assert_exit "--pfc-quanta 0"         0 $BIN --pfc-quanta 0 --print-config
assert_exit "--pfc-quanta 65535"     0 $BIN --pfc-quanta 65535 --print-config
assert_exit "-T 10.0.0.0/0 (zero mask)"  0 $BIN -T 10.0.0.0/0  --print-config
assert_exit "-T 10.0.0.0/32 (host)"      0 $BIN -T 10.0.0.0/32 --print-config
assert_exit "--duration 30 (bare int)"   0 $BIN --duration 30 --print-config
assert_exit "--duration 5m"              0 $BIN --duration 5m --print-config
assert_exit "--duration 2h"              0 $BIN --duration 2h --print-config
assert_exit "--duration 1d"              0 $BIN --duration 1d --print-config
assert_exit "--payload zeros"        0 $BIN --payload zeros --print-config
assert_exit "--payload ff"           0 $BIN --payload ff --print-config
assert_exit "--payload dead"         0 $BIN --payload dead --print-config
assert_exit "--payload incr"         0 $BIN --payload incr --print-config

# ------------------------------------------------------------------
section "5. Effective config / day suffix arithmetic"
# ------------------------------------------------------------------
out=$($BIN --duration 1d --print-config | grep '^session_duration=' | cut -d= -f2)
assert_eq "1d == 86400 seconds" 86400 "$out"
out=$($BIN --duration 2h --print-config | grep '^session_duration=' | cut -d= -f2)
assert_eq "2h == 7200 seconds" 7200 "$out"
out=$($BIN --duration 5m --print-config | grep '^session_duration=' | cut -d= -f2)
assert_eq "5m == 300 seconds" 300 "$out"
out=$($BIN --stop-on-degradation 30 --print-config | grep '^stop_on_deg' | cut -d= -f2)
assert_eq "stop-on-degradation 30 → -30" "-30.00" "$out"
out=$($BIN --stop-on-degradation -25 --print-config | grep '^stop_on_deg' | cut -d= -f2)
assert_eq "stop-on-degradation -25 → -25" "-25.00" "$out"

# ------------------------------------------------------------------
section "6. Scenario parser — positive"
# ------------------------------------------------------------------
for f in examples/*.tco; do
    label="validate $(basename "$f")"
    assert_exit "$label" 0 $BIN --validate "$f"
done

# ------------------------------------------------------------------
section "7. Scenario parser — negative"
# ------------------------------------------------------------------
mkdir -p "$TMP/tco"
printf 'bogus 1000 30\n' > "$TMP/tco/bad-mode.tco"
assert_exit "reject unknown mode"            1 $BIN --validate "$TMP/tco/bad-mode.tco"
printf 'mac 1000\n' > "$TMP/tco/missing-dur.tco"
assert_exit "reject missing duration"        1 $BIN --validate "$TMP/tco/missing-dur.tco"
printf 'mac -10 30\n' > "$TMP/tco/negative-pps.tco"
assert_exit "reject negative pps"            1 $BIN --validate "$TMP/tco/negative-pps.tco"
printf 'mac 1000 0\n' > "$TMP/tco/zero-dur.tco"
assert_exit "reject zero duration"           1 $BIN --validate "$TMP/tco/zero-dur.tco"
: > "$TMP/tco/empty.tco"
assert_exit "reject empty file"              1 $BIN --validate "$TMP/tco/empty.tco"
printf '# only comments\n# nothing else\n' > "$TMP/tco/only-comments.tco"
assert_exit "reject comments-only file"      1 $BIN --validate "$TMP/tco/only-comments.tco"
assert_exit "reject missing file"            1 $BIN --validate "$TMP/tco/no-such-file"
# CRLF should be tolerated (positive)
printf 'mac 1000 30\r\npfc 5000 60\r\n' > "$TMP/tco/crlf.tco"
assert_exit "tolerate CRLF lines"            0 $BIN --validate "$TMP/tco/crlf.tco"
# Comments and blank lines mid-file
printf '# header\n\nmac 1000 30\n\n# midcomment\npfc 5000 60\n' > "$TMP/tco/mixed.tco"
assert_exit "tolerate blanks + comments"     0 $BIN --validate "$TMP/tco/mixed.tco"

# ------------------------------------------------------------------
section "8. Profile loader"
# ------------------------------------------------------------------
PDIR="$TMP/profiles"
mkdir -p "$PDIR"
export BASIDIUM_PROFILE_DIR="$PDIR"
# valid profile
printf 'mode=pfc\nthreads=4\nvlan_id=100\npfc_priority=5\npfc_quanta=32768\n' > "$PDIR/valid.conf"
out=$($BIN --profile valid --print-config | grep -E '^(mode|threads|vlan_id|pfc_priority|pfc_quanta)=' | sort | tr '\n' ' ')
assert_eq "load valid profile" "mode=pfc pfc_priority=5 pfc_quanta=32768 threads=4 vlan_id=100 " "$out"
# CRLF profile
printf 'mode=arp\r\nthreads=2\r\n' > "$PDIR/crlf.conf"
out=$($BIN --profile crlf --print-config | grep -E '^(mode|threads)=' | sort | tr '\n' ' ')
assert_eq "load CRLF profile" "mode=arp threads=2 " "$out"
# Unknown mode → reject
printf 'mode=bogus\n' > "$PDIR/bad-mode.conf"
assert_exit "reject bogus mode in profile"   1 $BIN --profile bad-mode -i lo
assert_stderr_contains "bogus mode error"    "is not a known mode" $BIN --profile bad-mode -i lo
# Out of range
printf 'mode=mac\nthreads=99\n' > "$PDIR/oor.conf"
assert_exit "reject threads=99 in profile"   1 $BIN --profile oor -i lo
assert_stderr_contains "oor message"         "out of range" $BIN --profile oor -i lo
# Bad name (path traversal)
assert_exit "reject ../traversal name"       1 $BIN --profile "../etc/passwd"
# Profiles list
out=$($BIN --list-profiles | sort | tr '\n' ' ')
assert_eq "list-profiles enumerates" "bad-mode crlf oor valid " "$out"
unset BASIDIUM_PROFILE_DIR

# XDG fallback (no legacy ~/.basidium, no override)
mkdir -p "$TMP/xdg/basidium"
printf 'mode=arp\nthreads=3\n' > "$TMP/xdg/basidium/x.conf"
out=$(HOME="$TMP/xdg-fakehome" XDG_CONFIG_HOME="$TMP/xdg" $BIN --profile x --print-config | grep -E '^(mode|threads)=' | sort | tr '\n' ' ')
assert_eq "XDG_CONFIG_HOME path resolves" "mode=arp threads=3 " "$out"

# ------------------------------------------------------------------
section "9. RNG seed determinism"
# ------------------------------------------------------------------
$BIN --pcap-out="$TMP/seed-a.pcap" -n 200 -M arp --seed 42  > /dev/null
$BIN --pcap-out="$TMP/seed-b.pcap" -n 200 -M arp --seed 42  > /dev/null
$BIN --pcap-out="$TMP/seed-c.pcap" -n 200 -M arp --seed 999 > /dev/null
md5_a=$(python3 -c "
import sys, hashlib
with open('$TMP/seed-a.pcap','rb') as f: d=f.read()
i=24; out=b''
while i+16 <= len(d):
    cl = int.from_bytes(d[i+8:i+12],'little'); i+=16; out+=d[i:i+cl]; i+=cl
print(hashlib.md5(out).hexdigest())")
md5_b=$(python3 -c "
import sys, hashlib
with open('$TMP/seed-b.pcap','rb') as f: d=f.read()
i=24; out=b''
while i+16 <= len(d):
    cl = int.from_bytes(d[i+8:i+12],'little'); i+=16; out+=d[i:i+cl]; i+=cl
print(hashlib.md5(out).hexdigest())")
md5_c=$(python3 -c "
import sys, hashlib
with open('$TMP/seed-c.pcap','rb') as f: d=f.read()
i=24; out=b''
while i+16 <= len(d):
    cl = int.from_bytes(d[i+8:i+12],'little'); i+=16; out+=d[i:i+cl]; i+=cl
print(hashlib.md5(out).hexdigest())")
assert_eq "seed=42 deterministic (run1==run2)" "$md5_a" "$md5_b"
if [[ "$md5_a" != "$md5_c" ]]; then
    PASS=$((PASS+1)); echo "  $(green PASS) seed=42 != seed=999 (different streams)"
else
    FAIL=$((FAIL+1)); echo "  $(red FAIL) seed=42 == seed=999 (RNG not seeding properly)"
fi

# Without --seed: two runs differ
$BIN --pcap-out="$TMP/noseed-1.pcap" -n 200 -M arp > /dev/null
$BIN --pcap-out="$TMP/noseed-2.pcap" -n 200 -M arp > /dev/null
md5_n1=$(python3 -c "
import hashlib
with open('$TMP/noseed-1.pcap','rb') as f: d=f.read()
i=24; out=b''
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16; out+=d[i:i+cl]; i+=cl
print(hashlib.md5(out).hexdigest())")
md5_n2=$(python3 -c "
import hashlib
with open('$TMP/noseed-2.pcap','rb') as f: d=f.read()
i=24; out=b''
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16; out+=d[i:i+cl]; i+=cl
print(hashlib.md5(out).hexdigest())")
if [[ "$md5_n1" != "$md5_n2" ]]; then
    PASS=$((PASS+1)); echo "  $(green PASS) no --seed: two runs differ (entropy seeding works)"
else
    FAIL=$((FAIL+1)); echo "  $(red FAIL) no --seed: two runs identical (entropy may be broken)"
fi

# ------------------------------------------------------------------
section "10. Packet builder content via pcap-out"
# ------------------------------------------------------------------
# Build one frame per mode and validate the EtherType byte.
# (Parallel arrays — bash 3.2 on macOS lacks associative arrays.)
modes=(mac  arp  pfc  nd   lldp igmp)
etypes=(0800 0806 8808 86dd 88cc 0800)
for idx in "${!modes[@]}"; do
    m=${modes[$idx]}
    want=${etypes[$idx]}
    $BIN --pcap-out="$TMP/m.pcap" -n 1 -M "$m" --seed 7 > /dev/null
    et=$(python3 -c "
with open('$TMP/m.pcap','rb') as f: d=f.read()
print(d[24+16+12:24+16+14].hex())")
    assert_eq "build_packet_$m EtherType" "$want" "$et"
done
# STP uses LLC framing — type field is length=7, not an EtherType
$BIN --pcap-out="$TMP/stp.pcap" -n 1 -M stp --seed 7 > /dev/null
et=$(python3 -c "
with open('$TMP/stp.pcap','rb') as f: d=f.read()
print(d[24+16+12:24+16+14].hex())")
assert_eq "build_packet_stp length field == 0007" "0007" "$et"

# ------------------------------------------------------------------
section "11. Buffer-hygiene check across mode boundaries"
# ------------------------------------------------------------------
# Build IGMP then MAC in same worker; the MAC frame should NOT carry IGMP's
# ip_p=2 / ip_tos=0xC0.  We mimic this by running a 2-step .tco scenario
# (igmp→mac) and inspecting the MAC frame in the pcap.
cat > "$TMP/tco/hygiene.tco" <<'EOF'
igmp 1000 1
mac  1000 1
EOF
$BIN --pcap-out="$TMP/hygiene.pcap" --scenario "$TMP/tco/hygiene.tco" --seed 1 > /dev/null
# Find first mac frame in pcap (EtherType 0x0800 with ip_p=17 NOT 2 ; we
# just inspect the *last* frame which should be MAC mode).
last_proto=$(python3 -c "
with open('$TMP/hygiene.pcap','rb') as f: d=f.read()
i=24
last_eth_type=None; last_proto=None
while i+16 <= len(d):
    ts_sec=int.from_bytes(d[i:i+4],'little')
    cl=int.from_bytes(d[i+8:i+12],'little')
    i += 16
    eth_type = d[i+12:i+14].hex()
    if eth_type == '0800':
        last_eth_type = eth_type
        last_proto = d[i+14+9]   # ip_p byte at offset 9 of struct ip
    i += cl
print(last_proto)")
# build_packet_mac doesn't set ip_p (it's left at 0 after our memset).
# If buffer hygiene is broken, ip_p would be 2 from the prior IGMP frame.
assert_eq "MAC frame after IGMP: ip_p == 0 (clean)" "0" "$last_proto"

# Also check ip_tos isn't 0xC0 from the IGMP frame
last_tos=$(python3 -c "
with open('$TMP/hygiene.pcap','rb') as f: d=f.read()
i=24
last_tos=None
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16
    if d[i+12:i+14].hex() == '0800':
        last_tos = d[i+14+1]
    i += cl
print(last_tos)")
assert_eq "MAC frame after IGMP: ip_tos == 0 (clean)" "0" "$last_tos"

# ------------------------------------------------------------------
section "12. Reports — JSON + CSV + compact"
# ------------------------------------------------------------------
$BIN --dry-run -M arp -n 2048 --scenario examples/ci-smoke.tco \
     --report="$TMP/r.json" --csv "$TMP/r.csv" --seed 1 > /dev/null
assert_file_nonempty "report JSON exists"     "$TMP/r.json"
assert_file_nonempty "CSV exists"             "$TMP/r.csv"
assert_eq "CSV header"  \
    "step,mode,pps_target,pps_achieved,nccl_busbw,nccl_degradation_pct,nic_tx_packets,nic_tx_dropped,nic_tx_errors" \
    "$(head -1 "$TMP/r.csv")"
csv_rows=$(($(wc -l < "$TMP/r.csv") - 1))
assert_eq "CSV row count == 2 (ci-smoke steps)"  2 "$csv_rows"
# Compact mode: single line
$BIN --dry-run -M arp -n 2048 --scenario examples/ci-smoke.tco \
     --report="$TMP/c.json" --report-compact --seed 1 > /dev/null
lines=$(wc -l < "$TMP/c.json" | tr -d ' ')
assert_eq "compact report is one line (no \\n)"  0 "$lines"
# Compact JSON parses (round-trip via python)
python3 -c "import json; json.load(open('$TMP/c.json'))" \
    && { PASS=$((PASS+1)); echo "  $(green PASS) compact JSON parses"; } \
    || { FAIL=$((FAIL+1)); echo "  $(red FAIL) compact JSON failed to parse"; }
# Pretty JSON parses
python3 -c "import json; json.load(open('$TMP/r.json'))" \
    && { PASS=$((PASS+1)); echo "  $(green PASS) pretty JSON parses"; } \
    || { FAIL=$((FAIL+1)); echo "  $(red FAIL) pretty JSON failed to parse"; }

# ------------------------------------------------------------------
section "13. NDJSON output"
# ------------------------------------------------------------------
$BIN --dry-run -M arp -n 1024 --ndjson 2>/dev/null > "$TMP/nd.out"
# Each line should be standalone JSON
all_ok=1
while IFS= read -r line; do
    [[ -z $line ]] && continue
    python3 -c "import json,sys; json.loads(sys.argv[1])" "$line" 2>/dev/null || { all_ok=0; break; }
done < "$TMP/nd.out"
if [[ $all_ok == 1 ]] && [[ -s $TMP/nd.out ]]; then
    PASS=$((PASS+1)); echo "  $(green PASS) every NDJSON line parses"
else
    FAIL=$((FAIL+1)); echo "  $(red FAIL) NDJSON parse failure or empty"
fi

# ------------------------------------------------------------------
section "14. --diff regression detection"
# ------------------------------------------------------------------
cat > "$TMP/d-old.json" <<'EOF'
{"sweep": {"steps": [
  {"pps_target": 1000, "pps_achieved": 1000, "nccl_busbw": 100.0},
  {"pps_target": 5000, "pps_achieved": 5000, "nccl_busbw": 95.0}
]}}
EOF
cat > "$TMP/d-new-good.json" <<'EOF'
{"sweep": {"steps": [
  {"pps_target": 1000, "pps_achieved": 1000, "nccl_busbw": 100.0},
  {"pps_target": 5000, "pps_achieved": 4995, "nccl_busbw": 94.5}
]}}
EOF
cat > "$TMP/d-new-bad.json" <<'EOF'
{"sweep": {"steps": [
  {"pps_target": 1000, "pps_achieved": 1000, "nccl_busbw": 100.0},
  {"pps_target": 5000, "pps_achieved": 5000, "nccl_busbw": 50.0}
]}}
EOF
cat > "$TMP/d-pps-bad.json" <<'EOF'
{"sweep": {"steps": [
  {"pps_target": 1000, "pps_achieved": 600},
  {"pps_target": 5000, "pps_achieved": 5000}
]}}
EOF
cat > "$TMP/d-scenario.json" <<'EOF'
{"scenario": {"steps": [
  {"mode": "mac", "pps_target": 1000, "pps_achieved": 1000, "nccl_busbw": 100.0},
  {"mode": "pfc", "pps_target": 5000, "pps_achieved": 4500, "nccl_busbw": 70.0}
]}}
EOF
assert_exit "diff: identical → exit 0"             0 $BIN --diff "$TMP/d-old.json" "$TMP/d-old.json"
assert_exit "diff: minor change within thresh"     0 $BIN --diff "$TMP/d-old.json" "$TMP/d-new-good.json"
assert_exit "diff: -47% busbw → exit 2"            2 $BIN --diff "$TMP/d-old.json" "$TMP/d-new-bad.json"
assert_exit "diff: stricter -60% threshold OK"     0 $BIN --diff "$TMP/d-old.json" "$TMP/d-new-bad.json" --diff-threshold-busbw -60
assert_exit "diff: -40% pps drop → exit 2"         2 $BIN --diff "$TMP/d-old.json" "$TMP/d-pps-bad.json"
assert_exit "diff: scenario regression → exit 2"   2 $BIN --diff "$TMP/d-old.json" "$TMP/d-scenario.json"
assert_exit "diff: missing file → exit 1"          1 $BIN --diff "$TMP/no-such" "$TMP/d-old.json"
assert_exit "diff: missing args → errx"            1 $BIN --diff
assert_exit "diff: malformed unknown opt"          1 $BIN --diff a b --bogus

# ------------------------------------------------------------------
section "15. Signal handling"
# ------------------------------------------------------------------
$BIN --dry-run -M arp -r 1000 -n 1000000 &
PID=$!
sleep 0.5
kill -INT $PID
wait $PID
rc=$?
assert_eq "SIGINT exit 0"  0 "$rc"
$BIN --dry-run -M arp -r 1000 -n 1000000 &
PID=$!
sleep 0.5
kill -TERM $PID
wait $PID
rc=$?
assert_eq "SIGTERM exit 0" 0 "$rc"

# ------------------------------------------------------------------
section "16. Bounded -n termination (regression test)"
# ------------------------------------------------------------------
# Prior to v2.5 the worker batched total_sent updates every 1024 packets,
# so `-n 3` overshot to ~1024 because the break condition never fired
# until a batch flushed.  These assertions pin the fix.
$BIN --pcap-out="$TMP/n3.pcap" -M arp -n 3 --seed 1 > /dev/null
n=$(python3 -c "
with open('$TMP/n3.pcap','rb') as f: d=f.read()
i=24; n=0
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16+cl; n+=1
print(n)")
assert_eq "-n 3 produces exactly 3 packets" 3 "$n"

$BIN --pcap-out="$TMP/n100.pcap" -M arp -n 100 -t 4 --seed 1 > /dev/null
n=$(python3 -c "
with open('$TMP/n100.pcap','rb') as f: d=f.read()
i=24; n=0
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16+cl; n+=1
print(n)")
assert_eq "-n 100 -t 4 produces exactly 100 packets (no over-shoot)" 100 "$n"

$BIN --pcap-out="$TMP/n1.pcap" -M pfc -n 1 --seed 1 > /dev/null
n=$(python3 -c "
with open('$TMP/n1.pcap','rb') as f: d=f.read()
i=24; n=0
while i+16 <= len(d):
    cl=int.from_bytes(d[i+8:i+12],'little'); i+=16+cl; n+=1
print(n)")
assert_eq "-n 1 produces exactly 1 packet" 1 "$n"

# ------------------------------------------------------------------
section "17. Bash completion script"
# ------------------------------------------------------------------
bash -n contrib/basidium.bash && \
    { PASS=$((PASS+1)); echo "  $(green PASS) bash -n contrib/basidium.bash"; } || \
    { FAIL=$((FAIL+1)); echo "  $(red FAIL) bash completion has syntax errors"; }

# ------------------------------------------------------------------
section "18. Sanitizer build"
# ------------------------------------------------------------------
make clean > /dev/null 2>&1
if make asan > "$TMP/asan-build.log" 2>&1; then
    PASS=$((PASS+1)); echo "  $(green PASS) make asan compiles"
    if ./basidium --selftest > /dev/null 2>&1; then
        PASS=$((PASS+1)); echo "  $(green PASS) selftest under ASan+UBSan"
    else
        FAIL=$((FAIL+1)); echo "  $(red FAIL) selftest under ASan failed"
    fi
    if ./basidium --dry-run --scenario examples/ci-smoke.tco > /dev/null 2>&1; then
        PASS=$((PASS+1)); echo "  $(green PASS) scenario dry-run under ASan"
    else
        FAIL=$((FAIL+1)); echo "  $(red FAIL) scenario under ASan failed"
    fi
else
    FAIL=$((FAIL+1)); echo "  $(red FAIL) make asan failed (see $TMP/asan-build.log)"
fi
make clean > /dev/null 2>&1
make > /dev/null 2>&1

# ------------------------------------------------------------------
echo
echo "============================================================"
printf '  Total: %s passed, %s failed\n' "$(green $PASS)" "$([[ $FAIL -gt 0 ]] && red $FAIL || green 0)"
echo "============================================================"
[[ $FAIL -eq 0 ]] || exit 1
exit 0
