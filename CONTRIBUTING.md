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
4. Run the test suite (no root required):
   ```sh
   make check
   ```
   This runs all 14 selftests (packet builders + TCO/NCCL parsers) plus
   dry-run smoke tests across multiple modes. For live injection testing,
   use `sudo make selftest`.
5. Open a pull request with a clear description of what changed and why

## Code Style

- C99, K&R brace style
- `snprintf` / `strdup` — never `sprintf` / `strcpy`
- All allocations checked; all file handles closed
- New packet builders must include a corresponding selftest case in `run_selftest()`

## Reporting Bugs

Open a GitHub issue with:
- What you ran (full command)
- What you expected vs. what happened
- OS, compiler version, libpcap version

For security issues, see [SECURITY.md](SECURITY.md).
