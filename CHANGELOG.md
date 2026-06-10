# Changelog

All notable changes to Basidium are documented here.

## [2.6.1] — 2026-06-10

Follow-up bug-hunt patch after the 2.6 review. Correctness and
fail-fast-contract fixes; no new features. 163 regression assertions in
`tests/run-all.sh` (up from 136); selftest, three sanitizer suites
(ASan, UBSan, TSan), and `make check` clean.

### Fixed
- **`--stop-on-degradation` now exits 2 as documented.** The sweep
  (`sweep_thread_func`) and TCO (`tco_thread_func`) gates halted the run
  on an NCCL busbw regression by clearing `is_running`, but nothing set
  an exit-code flag, so `main()` returned 0 — silently defeating the
  documented fail-fast contract that scripted gates check with
  `$? -eq 2`. A dedicated `_Atomic degradation_detected` flag now drives
  the exit code. Regression-tested end-to-end with a stub nccl-tests
  binary (sweep and scenario variants plus a no-degradation control),
  which also gives the `fork`+`execvp` NCCL subprocess path its first
  automated coverage. TSan-clean.
- **`--diff` thresholds are sign-tolerant and validated.** A positive or
  zero `--diff-threshold-pps` / `--diff-threshold-busbw` silently
  disabled that regression axis — a CI false-pass — because the gate only
  fires on a negative threshold. The values are now normalized like
  `--stop-on-degradation` (`30` and `-30` both mean "flag a 30% drop"),
  and a non-numeric threshold errors out instead of `strtod`-ing to 0.0.
- **IGMP membership reports carry a valid RFC 2236 checksum.** Unlike
  IPv4 UDP there is no "checksum disabled" encoding; a compliant IGMP
  snooper drops reports that fail the checksum, so the zero-checksum
  frames made `-M igmp` a no-op against exactly the hardware being
  qualified. `build_packet_igmp` now computes it via `ip_checksum`;
  selftest asserts the message checksum verifies to zero.
- **A profile that enables a sweep without a valid step is rejected.**
  `sweep_enabled=1` with a zero/absent `sweep_step` passed
  `profile_validate` (which never checked sweep consistency), bypassed
  the CLI's `--sweep` validation, and reached `sweep_thread_func` where
  the step-count division is a divide-by-zero (SIGFPE). The loader now
  enforces `0 < sweep_start < sweep_end` and `sweep_step > 0`.
- **Non-finite NCCL busbw no longer corrupts the report.** `nccl-tests`
  can print `inf`/`nan` in the busbw column on a degenerate run;
  `sscanf`/`strtod` parse those happily and the value reached the JSON
  and CSV as a bare `inf`/`nan` token — invalid JSON that breaks `--diff`
  and every downstream consumer. `nccl_parse_line` now rejects rows with
  a non-finite `time`/`algbw`/`busbw` at the source.
- **`-l` JSON event log is properly escaped.** v2.5 claimed the event
  log escapes control bytes; `log_event` actually emitted raw `%s`, so a
  control byte or quote in any field would break the NDJSON. Both the
  `type` and `message` fields now run through the same escaper
  `write_report` uses. Tested: every emitted line parses as JSON.
- **Minor:** `--duration 30sX` (trailing junk after the `s` suffix) is
  now rejected like the other suffixes; the JSON report's default
  `packet_size` reads 60 (the real minimum frame size) instead of 64.
- **`--diff` no longer invents phantom steps.** The step-array parser
  walked to end-of-document instead of stopping at the array's closing
  `]`, so the trailing `"nccl": {…}` and `"nic_stats": {…}` objects each
  got parsed as an extra all-zero "step" — emitting bogus rows and
  inflating the step count the CI regression gate reports. The walk is
  now bounded to the matching `]`.
- **`--report FILE` (space-separated form) lands in the named file.**
  getopt only binds an optional argument via `--report=FILE`, so the
  documented `--report sweep.json` form silently dropped the path and
  auto-named a timestamped file. The next argv is now consumed when it
  isn't another option. Stray positional arguments are rejected with a
  clear error instead of being silently ignored.
- **Achieved-PPS and live PPS no longer quantize to multiples of 1024.**
  Unbounded runs only pushed `total_sent` in 1024-packet batches, so
  sweep/TCO `pps_achieved` (and the live counter) snapped to 1024
  multiples — and read 0 for any step that sent fewer than 1024 packets
  in its window. The rate-limited path now flushes the sub-batch residual
  once per wall-clock second; the unlimited path keeps the pure batched
  counter (the 1024 grain is noise at Mpps).
- **Default MAC fast path keeps the destination unicast.** It emitted a
  multicast/broadcast destination MAC on ~half its frames, diverging from
  `build_packet_mac`, the slow path, and what the selftest validates. It
  now clears the multicast bit unless `-U` is set.
- **ARP frames pad to the 60-byte Ethernet minimum** like every other
  builder, instead of emitting a 42-byte runt and relying on the driver
  to pad it.
- **Minor:** `get_target_ip` top octet now spans the full unicast range
  1..223 (was 1..222); the pcap-replay `usleep()` clamps below 1e6 (was
  exactly 1e6 at `-r 1`, the POSIX `EINVAL` boundary); `-i` frees any
  profile-loaded interface string before replacing it.

## [2.6] — 2026-05-08

Bug-hunt patch release. No new user-facing features; eleven correctness
and safety fixes across the builders, runtime, profile loader, NCCL
subprocess, and TUI. Three sanitizer suites (ASan, UBSan, TSan) clean
on selftest + scenario dry-run. 136 regression assertions in
`tests/run-all.sh` (up from 127).

### Fixed
- **TCO orchestrator now honors `--stop-on-degradation`** — pre-2.6
  measured NCCL busbw and recorded the baseline but never compared
  against the threshold, so scenario-based fail-fast CI gates were
  silent. Mirrors the existing sweep-thread gate.
- **Sweep + scenario reports stop emitting zeroed phantom rows for
  steps that never ran.** New `sweep_steps_completed` /
  `tco_steps_completed` atomic counters drive the JSON+CSV iteration; a
  truncated run now emits `"halted_early": true, "steps_planned": N` so
  downstream tools can distinguish "halted at step K" from "ran all N".
- **IPv6 ND solicited-node multicast destination was malformed off-by-
  one** — the `0x01` marker landed at byte 12 instead of 11 and only 16
  bits of the target address were copied. Now matches RFC 4291 §2.7.1.
  Selftest extended to assert the full layout against the ICMPv6 NS
  target field.
- **`--sweep` parse rejects step counts that overflow
  `MAX_SWEEP_STEPS`** using long-long arithmetic so the int multiply
  cannot wrap and silently pass a too-large sweep that `flood.c` would
  then truncate.
- **BPF filter that was silently defeating `--detect`** — the filter
  excluded the very probe-signature frames the C-level fail-open check
  was looking for, making the feature non-functional on every platform.
  Filter removed; the C-level check is reachable. README documents the
  Linux-reliable / macOS-noisy split (macOS BPF echoes TX locally; a
  receiver-mode design in v2.7 will close the gap).
- **`nccl.status` is `_Atomic`** with a documented release/acquire
  invariant. Pre-2.6, consumers in flood/tco/tui/report read
  `status==DONE` and then the result array without holding
  `nccl_mutex`. On weak-memory archs (Apple Silicon, Graviton, Ampere)
  the consumer could observe `DONE` before the array writes were
  visible.
- **Stack buffer overflow in `build_packet_mac` with `-J 9216 -V N
  --qinq M`** (ASan-confirmed). `vlan_tag_frame` and `qinq_tag_frame`
  each grew the frame by 4 bytes past the worker's `MAX_PACKET_SIZE`
  stack buffer. Both taggers now refuse to grow past the buffer;
  `build_packet_mac` reserves room for tags so requested frame size is
  honored minus the tag overhead.
- **`profiles_list` OOB write** of `'\0'` past `names[count]` for
  filenames whose basename exceeded `PROFILE_NAME_MAX`. Now skipped
  with a length precheck.
- **Rate limiter floor**: `-r N -t T` with `N < T` floored
  `per_thread_pps` to 1 and emitted `T pps` instead of `N`. Period now
  computed directly as `1e9 ns × threads / total_pps`, split across
  `tv_sec`/`tv_nsec` to be safe on 32-bit platforms.
- **`pcap_replay_func` swallowed `pcap_inject` failures** and inflated
  `total_sent`. Now checks the return value and emits a one-shot
  warning on first injection failure.
- **Misaligned `struct ip` access**: the worker buffer and selftest
  buffer were `uint8_t buf[N]` (alignment 1), so
  `(struct ip *)(buf + 14)` landed at a 2-byte-aligned address — UB
  per the C standard, UBSan-flagged on aarch64. Both buffers now use a
  4-byte-aligned backing array offset by 2 so the IP header lands on a
  4-byte boundary. Sniffer reads `ip_id` via `memcpy` since the
  libpcap-managed buffer's alignment is not under our control.
- **`profiles_dir` refuses to fall back to `/tmp`** when `HOME` is
  unset and `getpwuid()` fails. Pre-2.6 was a symlink-following hazard
  when the binary ran as root. The TUI's disclaimer/intro markers
  (`.disclaimer_accepted`, `.tui_intro_seen`) honor the same guard.
- **NCCL subprocess runs through `pipe`+`fork`+`execvp`+`waitpid`**
  instead of `popen()`+`/bin/sh -c`. Pre-2.6 the user-supplied
  `--nccl-binary` path and args were shell-evaluated, so any `;`,
  `|`, `$`, backtick, etc. in those strings would be interpreted by
  the shell. The shell is now eliminated entirely. Args tokenized via
  `strtok_r`; child uses only async-signal-safe calls between fork and
  exec.
- **TUI `+`/`-` rate adjust bounded** against `INT_MAX` overflow.
- **Worker initial `cur_mode = MODE_INVALID`** so the first loop
  iteration always rebuilds against the live mode. Eliminates wasted
  RNG draws in `--scenario` runs where TCO has already moved
  `conf.mode` before the worker reaches its first iteration.

### Tests
- Nine new regression assertions in `tests/run-all.sh`:
  - ND IPv6 dst is correct sol-node multicast (wire-format, via pcap)
  - Normal completion does not carry `halted_early`
  - Scenario step entries equal planned for a clean run
  - `-J 9216 + VLAN + QinQ` stays within `MAX_PACKET_SIZE` (ASan tripwire)
  - QinQ outer TPID survives the `-J` cap
  - `list-profiles` skips filenames too long for the buffer
  - `profiles_dir` does not write `/tmp/.basidium` with `HOME` unset
  - Selftest is UBSan-clean (no misaligned `struct ip` access)
  - Scenario dry-run is UBSan-clean

## [2.5] — 2026-04-26

### Added
- **`--diff <a.json> <b.json>`** companion subcommand — compares two reports
  step-by-step, flags PPS / NCCL busbw regressions, and exits 2 if any axis
  exceeds the threshold (defaults: -10% on both, configurable via
  `--diff-threshold-pps` and `--diff-threshold-busbw`). Closes the loop on
  the `--report` design: regression detection now ships in-binary.
- **`--validate <file.tco>`** parses and reports a scenario without running
  it. Exits 0 on a valid file, 1 with a line-numbered diagnostic otherwise.
  Wired into `make check` so malformed scenarios are caught before merge.
- **`--seed N`** seeds the worker xorshift128+ stream deterministically (and
  derives `probe_signature`) so repeated runs are bit-reproducible — useful
  for diff-based regression hunts.
- **`--print-config`** dumps the merged effective config (defaults +
  `--profile` + flag overrides) as `key=value` and exits. Eliminates the
  silent-merge debugging that profile loading caused.
- **`--list-modes` / `--list-profiles`** machine-readable enumerators for
  shell scripting around mode names and saved profile names.
- **`--ndjson`** replaces the in-place `\r[Total: ...]` spinner with
  one JSON object per second on stdout — pipeable to `jq`, `tee`, Loki.
- **`--csv <file>`** emits sweep / scenario steps as CSV alongside the
  JSON report, fixed schema for spreadsheet tooling.
- **`--report-compact`** writes the JSON report in single-line form.
- **`--stop-on-degradation N`** halts a sweep or scenario the first time
  NCCL busbw drops past the threshold (sign-tolerant — `-30`, `30` both
  mean "stop at 30% drop"); pairs with `--stop-on-failopen` for fail-fast
  scripted gates that exit 2 on regression.
- **`--stop-on-failopen`** halts on first fail-open detection rather than
  running to end-of-session.
- **`--duration` accepts `d` suffix** (e.g. `--duration 1d`) and now
  rejects unknown suffixes instead of silently dropping them.
- **`--version --json`** emits machine-parsable version output.
- **`-h` / `--help`** are now recognized; `usage()` exits 0 when explicitly
  requested, 2 on parse errors.
- **`make asan` / `make tsan`** sanitizer build targets — rebuild the
  binary with AddressSanitizer + UndefinedBehaviorSanitizer or
  ThreadSanitizer respectively, then run `--selftest` and a scenario
  dry-run to verify cleanliness.
- **`make test` / `tests/run-all.sh`** — exhaustive offline test suite
  (~127 assertions: every flag's accept/reject behavior, every error
  message, packet builder content via pcap-out, buffer-hygiene across
  mode boundaries via `.tco` scenarios, RNG seed determinism with byte-
  level pcap diff, profile loader (XDG fallback, CRLF, MODE_INVALID,
  range checks, traversal blocking), `--diff` regression detection,
  NDJSON/CSV/compact reports, signal handling, bounded-`-n` termination,
  bash completion syntax, sanitizer build).
- **`make check`** — also runs `--validate` over every `examples/*.tco`
  so malformed scenarios fail the local pre-merge check.
- New example scenarios: `pfc-recovery.tco`, `multi-mode-soak.tco`.
- **Bash completion** (`contrib/basidium.bash`) covers modes, flags,
  scenario file paths, and saved profile names.

### Fixed
- **TCO mode-switch buffer hygiene** — `worker_func` now detects runtime
  `conf.mode` changes (TCO writes them mid-run), wipes the packet buffer,
  and rebuilds the template. Previous behavior could leak bytes from the
  prior mode's frame into the next mode's payload tail.
- **Atomic `conf.mode` and `conf.pps`** — both are now `_Atomic`-qualified,
  giving the workers/sweep/TCO seq_cst semantics under bare assignment.
  TSan no longer flags the read/write race.
- **Packet builder IP-header hygiene** — `build_packet_mac`,
  `build_packet_dhcp`, and `build_packet_igmp` now zero the IP header
  before populating, so `ip_tos`, `ip_off`, and `ip_p` from a previous
  iteration's IGMP/DHCP frame don't leak forward.
- **Wire-format struct packing** — every on-the-wire struct
  (`ether_header_custom`, `arp_header`, `udp_header`, `dhcp_packet`,
  `ipv6_header`, `icmpv6_ns_pkt`, `igmp_header`) is now
  `__attribute__((packed))` with `_Static_assert` size guards. A future
  ABI shift fails the build instead of silently shipping malformed frames.
- **Validated input parsing** — every `atoi()` and unchecked `sscanf` in
  CLI flags and profile loader is now `strtol` with field-named diagnostics.
  `-V 5000`, `-T 10.0.0.0/40`, `-S 00:11`, `--duration 5x`, `--payload neon`
  now all error out with a useful message instead of silently corrupting
  config.
- **`-T` CIDR validation** — mask bits outside 0..32 are rejected; the
  previous code did an undefined left-shift for `mask_bits > 32`.
- **`-S` OUI validation** — malformed input no longer leaves uninitialized
  stack bytes in the OUI; the parse must produce three bytes, each ≤ 0xFF.
- **Signal handling** — replaced `signal()` with `sigaction()`; the handler
  writes only a `volatile sig_atomic_t` flag (async-signal-safe), and the
  main loop polls and propagates to `is_running`. `SIGPIPE` is now
  explicitly ignored so a closed NCCL popen pipe can no longer kill the
  whole process.
- **RNG seeding** — workers seed from `getrandom()` / `/dev/urandom` mixed
  through SplitMix64 instead of `time(NULL) + thread_id`. Adjacent threads
  no longer produce correlated MAC/IP streams.
- **Rate limiter** — replaced the `usleep((1024 * 1000000ULL / pps) * threads)`
  math (which rounded to 0 above ~1Mpps and over-shot below ~10kpps) with
  a per-packet absolute-time pacer using `clock_gettime` + `nanosleep`.
- **Sniffer BPF compile failure is now fatal** — previously the sniffer
  silently continued without the filter, causing `--detect` to fire on
  every injected frame. Now the sniffer exits and emits a warning.
- **`pcap_next` → `pcap_next_ex`** — sniffer thread switched to the
  modern API that distinguishes errors from no-packet timeouts.
- **`pcap_inject` short-write detection** — workers now check `>= len`
  instead of `> 0`, so a partial transmit is correctly counted as failure
  toward `MAX_INJECT_FAILURES`.
- **`get_target_ip` unicast filter** — when no `-T` is set, generated IPs
  are clamped to 1..222 in the top octet, avoiding spurious 0.0.0.0,
  255.255.255.255, and 224.0.0.0/4 multicast addresses that trap to
  switch CPU and pollute test signals.
- **`learned_macs` lazy alloc** — the 24KB ring is now allocated only when
  `-L` is passed. Previously every run leaked it on `errx()` paths.
- **Profile loader CR strip + range checks** — Windows-edited
  `~/.basidium/<name>.conf` files no longer silently load the wrong mode
  because of trailing `\r`. Every numeric field is `strtol`-validated;
  unknown modes are rejected on load instead of falling back to MAC.
- **JSON event log escaping** — `\r`, `\t`, and control chars below 0x20
  are now escaped, so a log message containing a control byte produces
  valid JSON instead of breaking downstream consumers.
- **`-Wshadow -Wnull-dereference -Wstrict-prototypes -Wmissing-prototypes
  -Wformat=2 -fno-strict-aliasing`** added to default CFLAGS; the entire
  tree builds clean with these enabled.

### Distribution
- **`CITATION.cff`** — standard academic-citation metadata for users who
  need to reference Basidium in qualification reports or papers.
- **`make clean`** now also removes `*.dSYM/` (macOS debug symbol bundles)
  and stray `basidium-*.json` / `*.pcap` test artifacts dropped by ad-hoc
  dry-runs.

### Configuration
- **XDG_CONFIG_HOME respected** for profile directory lookup, with the
  legacy `~/.basidium/` retained as a fallback when it already exists
  (no migration required).
- **`BASIDIUM_PROFILE_DIR`** env var explicit override.
- **`NO_COLOR`** environment variable honored; `TERM=dumb` likewise
  disables color paths.

## [2.4] — 2026-04-18

### Added
- **NCCL-correlated rate sweep** — when `--sweep` and `--nccl` are both active, Basidium automatically launches an NCCL test at each sweep step and records per-step bus bandwidth alongside achieved PPS. The JSON report now includes `nccl_busbw` and `nccl_degradation_pct` fields per step, with the first step's result used as the baseline if none was set manually. The sweep thread holds the current PPS level until the NCCL test completes, ensuring measurements reflect actual congestion conditions.
- **TCO (Targeted Congestion Orchestration)** — new `--scenario <file>` flag to run multi-step, multi-mode congestion patterns. Scenario files (`.tco`) define sequences of mode/PPS/duration steps with optional per-step NCCL correlation. Workers dynamically switch modes at runtime. New module: `tco.c`/`tco.h`. Example scenario in `examples/pfc-stress-ramp.tco`.
- **Selftest coverage for TCO and NCCL modules** — `run_selftest()` now exercises `tco_load()` on a generated scenario (positive + invalid-mode negative) and `nccl_parse_line()` on a representative nccl-tests output line plus header/blank/truncated rejections. Total selftest count: 14.

### Fixed
- **`-n <count>` bounded-run termination** — the worker batched
  `total_sent` updates every 1024 packets, so `-n 3` would over-shoot
  to ~1024 (and `-n 100 -t 4` would emit ~400) because the break check
  never saw the count reached. Bounded runs now flush the global counter
  per packet so the loop exits within one packet of the target.
  Unbounded runs still batch (the cache-line-ping-pong cost only matters
  at multi-Mpps with many workers, where `-n` is unbounded by definition).
  Three test assertions added.
- **Worker fast-path stale mode check** — the MAC fast-path optimization was computed once at worker startup, meaning runtime mode changes (from TCO orchestration) would not take effect. Now the fast path also checks `conf.mode == MODE_MAC` each iteration.
- **Unchecked `pthread_create` returns** — the sniffer, sweep, TCO, PCAP-replay, and worker thread launches in `basidium.c` now error out with `strerror(rc)` on failure instead of silently proceeding as if the thread were running.
- **Unchecked `profiles_load` return** — `--profile <name>` now errors out if the profile file is missing or malformed rather than silently falling back to defaults. `profiles_load()` now emits `strerror(errno)` diagnostics on open failure and rejects profiles with out-of-range values (threads, pps, packet_size, vlan_id, vlan_pcp, vlan_range_end, qinq_outer_vid, pfc_priority, pfc_quanta, payload_pattern, session_duration) with a field-specific message instead of silently loading.
- **Unchecked `mkdir` in `profiles_save`** — `ensure_dir()` now reports `strerror(errno)` on failure (except `EEXIST`) and aborts the save, so profile saves don't silently drop on permission or disk errors.
- **Silent partial report writes** — `write_report()` now returns `int`, checks `ferror()` and `fclose()`, and on any stream/flush error prints a diagnostic and unlinks the partial file so downstream tooling doesn't consume half-written JSON. `fopen` failures now include `strerror(errno)`.

## [2.3] — 2026-04-06

### Added
- **macOS / BSD NIC statistics** — TUI stats panel now shows live TX/RX counters on macOS and FreeBSD via `getifaddrs()` + `AF_LINK` `if_data`. Previously showed `n/a` on non-Linux.
- **macOS CI** — GitHub Actions build matrix now includes `macos-latest` alongside `ubuntu-latest`. Both CLI and TUI builds are tested on each platform.
- **`--version` flag** — prints version and exits. Version string defined once in `Makefile` and propagated via `-DBASIDIUM_VERSION`.
- **Mode enum (`flood_mode_t`)** — replaces raw integer mode identifiers with a proper C enum (`MODE_MAC`, `MODE_ARP`, `MODE_DHCP`, `MODE_PFC`, `MODE_ND`, `MODE_LLDP`, `MODE_STP`, `MODE_IGMP`). Eliminates 5 copies of the mode-to-string mapping.
- **`mode_to_string()` / `mode_from_string()`** — shared mode name helpers used across all modules.
- **IPv4 header checksum** — MAC flood and IGMP frames now carry a valid IP checksum. Added `ip_checksum()` utility function. Selftest validates checksum correctness (test 12).
- **Profile name sanitization** — `profiles_save()` and `profiles_load()` now reject names containing path traversal characters (`/`, `..`, `\`) or starting with `.`. Only alphanumeric, dash, and underscore are allowed.
- **CHANGELOG.md** — this file.

### Fixed
- **Thread-safe RNG** — all slow-path packet builders (`build_packet_arp`, `build_packet_dhcp`, `build_packet_pfc`, `build_packet_nd`, `build_packet_lldp`, `build_packet_stp`, `build_packet_igmp`) now accept a per-thread `struct rng_state *` instead of calling `rand()`, which is not thread-safe. The existing `xorshift128plus` RNG is now used everywhere.
- **Session duration in TUI mode** — `--duration` was drawn as a countdown timer in the TUI but never actually stopped the session. Now enforced in the TUI main loop.
- **Per-thread counter undercount** — `thread_sent[thread_id]` was missing the residual `local_sent % 1024` flush. Now both `total_sent` and `thread_sent` receive the residual on worker exit.
- **`SIGTERM` handling** — process now handles `SIGTERM` in addition to `SIGINT`, preventing unclean ncurses terminal state when killed by a process supervisor.
- **Sniffer BPF filter** — the sniffer thread now installs a BPF filter to exclude self-injected frames (by IP ID probe signature), reducing false-positive fail-open detections and broadcast RX inflation.
- **Worker error path** — workers now exit after `MAX_INJECT_FAILURES` (256) consecutive injection failures instead of spinning indefinitely with no-op sends.
- **`_GNU_SOURCE` placement** — moved from `flood.h` (header) to individual `.c` files where it belongs. Prevents fragile include-order dependency.

## [2.2] — 2026-03-15

### Added
- IGMP snooping exhaustion mode (`-M igmp`)
- STP TCN BPDU flood mode (`-M stp`)
- LLDP CPU-path stress mode (`-M lldp`)
- IPv6 Neighbor Discovery flood (`-M nd`)
- QinQ 802.1ad double-tagging (`--qinq`)
- Payload pattern fill (`--payload zeros|ff|dead|incr`)
- Per-thread PPS display in TUI
- NIC TX/RX statistics panel (Linux)
- ASCII sparkline PPS history
- Named profile save/load (`~/.basidium/`)
- First-launch disclaimer and intro walkthrough
- Scrollable help overlay with full CLI reference
- JSON session report (`--report`)
- NCCL busbw correlation panel (`--nccl`)
- Rate sweep with JSON reporting (`--sweep`)

## [2.1] — 2026-02-01

### Added
- Burst mode (`--burst count:gap_ms`)
- Fail-open detection (`--detect`)
- Adaptive throttle (`-A`)
- Learning mode (`-L`)
- PCAP output and replay (`--pcap-out`, `--pcap-replay`)
- Session duration timer (`--duration`)
- VLAN range cycling (`--vlan-range`)
- 802.1Q VLAN tagging (`-V`, `--vlan-pcp`)
- PFC PAUSE flood mode (`-M pfc`)

## [2.0] — 2026-01-15

### Added
- Multi-threaded injection with Xorshift128+ fast path
- ARP broadcast storm mode (`-M arp`)
- DHCP starvation mode (`-M dhcp`)
- Stealth OUI prefix (`-S`)
- Target subnet embedding (`-T`)
- ncurses TUI (`--tui`)
- JSON event logging (`-l`)

## [1.0] — 2025-12-01

### Added
- Initial release: single-threaded MAC CAM flood via libpcap
