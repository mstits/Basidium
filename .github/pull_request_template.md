## What does this change?

## Why is this change needed?

## Checklist
- [ ] `make clean && make` builds with zero warnings
- [ ] `make clean && make TUI=1` builds with zero warnings
- [ ] `make check` passes (selftest + scenario validation)
- [ ] `make test` passes (~125 offline assertions in `tests/run-all.sh`)
- [ ] `make asan` rebuild + `--selftest` clean (no leaks / UB)
- [ ] `make tsan` rebuild + `--selftest` clean (no races) — required if you touched any worker / sweep / TCO / sniffer thread state
- [ ] New CLI flags extended `tests/run-all.sh` with both accept and reject cases
- [ ] New packet builders include a selftest case
- [ ] No `sprintf`, `strcpy`, `atoi`, or unchecked allocations introduced
- [ ] On-the-wire structs are `__attribute__((packed))` with `_Static_assert(sizeof(...))`
