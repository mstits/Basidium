CC      = gcc
# -Wcast-align deliberately omitted: packet builders cast uint8_t buffers to
# libc's `struct ip` (a non-packed struct with bitfields), which on strict-
# alignment ARMs requires 4-byte alignment.  This codebase targets x86_64 and
# aarch64 hosts where unaligned access is permitted, and -fno-strict-aliasing
# disables the related UB worry.
CFLAGS  = -Wall -Wextra -Wformat=2 -Wshadow -Wnull-dereference \
          -Wstrict-prototypes -Wmissing-prototypes \
          -fno-strict-aliasing -O2 -D_FORTIFY_SOURCE=2
LDFLAGS = -lpcap -pthread

VERSION = 2.5
CFLAGS += -DBASIDIUM_VERSION=\"$(VERSION)\"

TARGET  = basidium
SRC     = basidium.c flood.c nccl.c tco.c profiles.c nic_stats.c report.c diff.c

# Build with ncurses TUI: make TUI=1
TUI ?= 0
ifeq ($(TUI), 1)
CFLAGS  += -DHAVE_TUI
LDFLAGS += -lncurses
SRC     += tui.c
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

selftest: $(TARGET)
	sudo ./$(TARGET) --selftest

check: $(TARGET)
	./$(TARGET) --selftest
	./$(TARGET) --dry-run -M arp -n 100
	./$(TARGET) --dry-run -M pfc -n 100
	./$(TARGET) --dry-run -M igmp -n 100
	./$(TARGET) --dry-run --scenario examples/ci-smoke.tco
	@for f in examples/*.tco; do ./$(TARGET) --validate "$$f" || exit 1; done
	@echo "All checks passed."

# Exhaustive offline test suite (~120 assertions covering every flag, every
# error path, packet builders via pcap-out, RNG determinism, profile loader,
# diff regression detection, signal handling, sanitizer build).  Requires
# python3 for pcap parsing.  Does not need sudo or a NIC.
test: $(TARGET)
	bash tests/run-all.sh

debug: CFLAGS := -Wall -Wextra -g -DDEBUG -O0 -fno-strict-aliasing \
                 -DBASIDIUM_VERSION=\"$(VERSION)\"
debug: $(TARGET)

asan: CFLAGS := -Wall -Wextra -g -O1 -fno-strict-aliasing \
                -fsanitize=address,undefined -fno-omit-frame-pointer \
                -DBASIDIUM_VERSION=\"$(VERSION)\"
asan: LDFLAGS += -fsanitize=address,undefined
asan: $(TARGET)

tsan: CFLAGS := -Wall -Wextra -g -O1 -fno-strict-aliasing \
                -fsanitize=thread -fno-omit-frame-pointer \
                -DBASIDIUM_VERSION=\"$(VERSION)\"
tsan: LDFLAGS += -fsanitize=thread
tsan: $(TARGET)

PREFIX  ?= /usr/local

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	install -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 644 basidium.8 $(DESTDIR)$(PREFIX)/share/man/man8/basidium.8
	install -d $(DESTDIR)$(PREFIX)/share/basidium/examples
	install -m 644 examples/*.tco $(DESTDIR)$(PREFIX)/share/basidium/examples/
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -m 644 contrib/basidium.bash \
		$(DESTDIR)$(PREFIX)/share/bash-completion/completions/basidium

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/basidium.8
	rm -rf $(DESTDIR)$(PREFIX)/share/basidium
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/basidium

clean:
	rm -f $(TARGET)
	rm -rf $(TARGET).dSYM
	rm -f basidium-*.json *.pcap

.PHONY: all selftest check test debug asan tsan clean install uninstall
