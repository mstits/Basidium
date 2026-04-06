/*
 * tui.h — ncurses TUI interface
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * iptraf-ng inspired layout:
 *   ┌─ header ──────────────────────────────────────────┐
 *   │ Basidium  iface  mode  status                     │
 *   ├─ stats ──────────────┬─ config ───────────────────┤
 *   │ PPS / total / uptime │ threads / rate / oui / ... │
 *   ├─ nccl ───────────────┴────────────────────────────┤
 *   │ busbw correlation line                             │
 *   ├─ log ──────────────────────────────────────────────┤
 *   │ scrolling event log                                │
 *   ├─ keys ─────────────────────────────────────────────┤
 *   │ keybinding hints                                   │
 *   └────────────────────────────────────────────────────┘
 */
#ifndef TUI_H
#define TUI_H

/* Initialise ncurses and create all panel windows */
void tui_init(void);

/* Tear down ncurses — must be called before exit */
void tui_cleanup(void);

/* Redraw all panels from current shared state — call from main loop */
void tui_draw(void);

/* Handle a single keystroke. Returns 1 if the user requested quit. */
int  tui_input(int ch);

/* Append a line to the TUI event log ring buffer (thread-safe) */
void tui_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Prompt the user for a string value inside the TUI (blocking).
 * Stores at most `maxlen-1` chars into `out`. Returns 0 on confirm, -1 on cancel. */
int  tui_prompt(const char *label, char *out, int maxlen);

#endif /* TUI_H */
