# Changelog

All notable changes to Basidium are documented here.

## [Unreleased]

## [2.4] — 2026-04-18

### Added
- **NCCL-correlated rate sweep** — when `--sweep` and `--nccl` are both active, Basidium automatically launches an NCCL test at each sweep step and records per-step bus bandwidth alongside achieved PPS. The JSON report now includes `nccl_busbw` and `nccl_degradation_pct` fields per step, with the first step's result used as the baseline if none was set manually. The sweep thread holds the current PPS level until the NCCL test completes, ensuring measurements reflect actual congestion conditions.
- **TCO (Targeted Congestion Orchestration)** — new `--scenario <file>` flag to run multi-step, multi-mode congestion patterns. Scenario files (`.tco`) define sequences of mode/PPS/duration steps with optional per-step NCCL correlation. Workers dynamically switch modes at runtime. New module: `tco.c`/`tco.h`. Example scenario in `examples/pfc-stress-ramp.tco`.
- **Selftest coverage for TCO and NCCL modules** — `run_selftest()` now exercises `tco_load()` on a generated scenario (positive + invalid-mode negative) and `nccl_parse_line()` on a representative nccl-tests output line plus header/blank/truncated rejections. Total selftest count: 14.

### Fixed
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
