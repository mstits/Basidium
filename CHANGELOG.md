# Changelog

All notable changes to Basidium are documented here.

## [2.5] — 2026-04-26

### Added
- **`--diff <a.json> <b.json>`** companion subcommand — compares two reports
  step-by-step, flags PPS / NCCL busbw regressions, and exits 2 if any axis
  exceeds the threshold (defaults: -10% on both, configurable via
  `--diff-threshold-pps` and `--diff-threshold-busbw`). Closes the loop on
  the `--report` design: regression detection now ships in-binary.
- **`--validate <file.tco>`** parses and reports a scenario without running
  it. Exits 0 on a valid file, 1 with a line-numbered diagnostic otherwise.
  Wired into `make check` so CI catches malformed scenarios.
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
  CI runs that exit 2 on regression.
- **`--stop-on-failopen`** halts on first fail-open detection rather than
  running to end-of-session.
- **`--duration` accepts `d` suffix** (e.g. `--duration 1d`) and now
  rejects unknown suffixes instead of silently dropping them.
- **`--version --json`** emits machine-parsable version output.
- **`-h` / `--help`** are now recognized; `usage()` exits 0 when explicitly
  requested, 2 on parse errors.
- **`make asan` / `make tsan`** sanitizer build targets; both are wired
  into separate CI matrix entries that run `--selftest` plus a full scenario
  dry-run.
- **`make test` / `tests/run-all.sh`** — exhaustive offline test suite
  (~125 assertions: every flag's accept/reject behavior, every error
  message, packet builder content via pcap-out, buffer-hygiene across
  mode boundaries via `.tco` scenarios, RNG seed determinism with byte-
  level pcap diff, profile loader (XDG fallback, CRLF, MODE_INVALID,
  range checks, traversal blocking), `--diff` regression detection,
  NDJSON/CSV/compact reports, signal handling). Wired into CI.
- **CI**: `--validate` runs over every `examples/*.tco`; `mandoc -Tlint`
  exercises the man page; ASan+UBSan and TSan matrix entries catch
  leak/UB/race regressions mechanically; full offline test suite gates merges.
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
