# Contributing to Basidium

## Before You Start

All contributions must be for authorized, defensive, or diagnostic use cases. Pull requests that add capabilities intended for unauthorized use against third-party systems will not be accepted.

## How to Contribute

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Ensure both builds pass cleanly with zero warnings:
   ```sh
   make clean && make
   make clean && make TUI=1
   ```
4. Run the test suites (no root required):
   ```sh
   make check          # 14 builders + scenario validation across examples/
   make test           # ~125 offline assertions covering every flag, every
                       # error path, packet-builder content, RNG determinism,
                       # profile loader, --diff regression detection
   make asan           # rebuild under ASan + UBSan
   ./basidium --selftest
   make tsan           # rebuild under TSan
   ./basidium --selftest
   ```
   For live injection testing, use `sudo make selftest`.
5. New CLI flags must extend `tests/run-all.sh` with both accept and
   reject cases.
6. Open a pull request with a clear description of what changed and why.

## Code Style

- C99, K&R brace style
- `snprintf` / `strdup` — never `sprintf` / `strcpy`
- All allocations checked; all file handles closed
- New packet builders must include a corresponding selftest case in `run_selftest()`
- New numeric CLI flags use `parse_int_range()` / `parse_long_range()` rather than `atoi()` so out-of-range and non-numeric input is rejected with a field-named diagnostic
- New on-the-wire structs are `__attribute__((packed))` with `_Static_assert(sizeof(...))` so a future ABI shift fails the build instead of silently shipping malformed frames
- Mode/PPS reads in workers go through the `_Atomic` qualifier — bare assignment is fine, but do not introduce non-atomic shadow copies that drift

## Reporting Bugs

Open a GitHub issue with:
- What you ran (full command)
- What you expected vs. what happened
- OS, compiler version, libpcap version

For security issues, see [SECURITY.md](SECURITY.md).
