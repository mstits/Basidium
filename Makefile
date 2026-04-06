CC      = gcc
CFLAGS  = -Wall -Wextra -Wformat=2 -O2 -D_FORTIFY_SOURCE=2
LDFLAGS = -lpcap -pthread

VERSION = 2.3
CFLAGS += -DBASIDIUM_VERSION=\"$(VERSION)\"

TARGET  = basidium
SRC     = basidium.c flood.c nccl.c profiles.c nic_stats.c report.c

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
	@echo "All checks passed."

debug: CFLAGS := -Wall -Wextra -g -DDEBUG -O0 -DBASIDIUM_VERSION=\"$(VERSION)\"
debug: $(TARGET)

PREFIX  ?= /usr/local

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	install -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 644 basidium.8 $(DESTDIR)$(PREFIX)/share/man/man8/basidium.8

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/basidium.8

clean:
	rm -f $(TARGET)

.PHONY: all selftest check debug clean install uninstall
