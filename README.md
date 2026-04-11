# Basidium (V2.3)

**Multi-threaded Layer-2 Stress & Hardware Evaluation Tool for GPU Cluster Fabrics**

<img width="709" height="497" alt="Basidium Screenshot" src="https://github.com/user-attachments/assets/1fe90db9-669f-4a5e-9c48-4ea22cd53733" />

[![Build](https://github.com/mstits/Basidium/actions/workflows/build.yml/badge.svg)](https://github.com/mstits/Basidium/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why This Exists

Modern AI training and inference infrastructure depends on large GPU clusters interconnected by high-speed fabrics — typically RoCE or InfiniBand over 100/400/800 GbE. Collective communication libraries such as NCCL make heavy, continuous use of these fabrics: `allreduce`, `allgather`, `broadcast`, and related operations generate substantial traffic across multiple switch hops.

In this environment, a single misbehaving switch, a misconfigured NIC, or a fabric policy error does not necessarily cause an obvious outage. Instead, it can manifest as **silent performance degradation** — NCCL throughput drops, step times increase, and GPU utilization falls. These symptoms are often subtle and slow to develop, making root cause identification genuinely difficult.

This problem is not limited to initial bring-up. GPU cluster fabrics are complex systems whose behavior can drift over time: firmware updates, configuration changes, physical layer degradation, and incremental topology changes can all introduce regressions that were not present at initial qualification. Periodic re-validation is a practical necessity, not a one-time exercise.

Standard network qualification (like RFC 2544) does not exercise the fabric at the intensity needed for dense GPU clusters. Basidium provides the high-fidelity stress required to surface the failure modes that cause multi-million dollar idle-time in AI training.

### The Pedestal

A *basidium* (from the Latin, meaning "little pedestal") is the structural foundation that supports and launches spores into the environment. While the mushroom's cap gets the attention, the basidium is the microscopic machinery that ensures the next generation actually takes flight.

In a GPU cluster, **the network fabric is the basidium**. The models get the headlines, but they cannot exist without a stable pedestal. If the fabric is cracked, jittery, or misconfigured, the entire computational process fails. Basidium ensures the pedestal doesn't buckle under the weight of line-rate traffic before you risk your training budget.

### Core Capabilities

```mermaid
graph LR
    subgraph "Layer-2 Stress"
        PFC["PFC PAUSE Flood<br/>RoCE/RDMA deadlock testing"]
        CAM["CAM Table Exhaustion<br/>fail-open detection"]
        ARP["ARP / ND / IGMP<br/>table resource limits"]
        STP["STP TCN Flood<br/>forced MAC flush"]
    end

    subgraph "Measurement"
        SWEEP["Rate Sweep<br/>PPS ramp + JSON report"]
        NCCL["NCCL Correlation<br/>per-step busbw + degradation%"]
    end

    subgraph "Orchestration"
        TCO["TCO Scenarios<br/>multi-mode congestion patterns<br/>.tco scenario files"]
    end

    PFC & CAM & ARP & STP --> SWEEP
    SWEEP --> NCCL
    TCO --> |"mode + PPS<br/>per step"| PFC & CAM & ARP & STP
    TCO --> NCCL
```

- **PFC / RDMA Stress:** Flood PFC PAUSE frames to confirm RoCE/RDMA priority flow control is correctly configured and does not deadlock under congestion — a known failure mode in lossless Ethernet fabrics.
- **L2 Table Exhaustion:** Saturate CAM tables to verify switch fail-open behavior and VLAN isolation under load. Exhaust IGMP snooping and ARP tables to find resource limits before they surface in production.
- **Rate Sweeps:** Generate precise rate sweeps with JSON reporting to establish forwarding capacity baselines and detect regressions over time.
- **NCCL Co-Validation:** Run injection patterns simultaneously with NCCL collective tests to observe how Layer-2 stress conditions measurably affect application-layer throughput. This side-by-side view helps isolate whether a performance problem originates in the fabric or the software stack.
- **Targeted Congestion Orchestration (TCO):** Define multi-step, multi-mode congestion scenarios (`.tco` files) that switch between flood modes at runtime while measuring NCCL degradation at each step.
- **Regression Detection:** Identify performance drift caused by firmware updates, configuration changes, physical layer degradation, or incremental topology changes.

> **Authorization required.** Use only on airgapped hardware you own or have explicit written permission to test. Never run against production infrastructure or equipment belonging to others.
>
> **Total Cluster Outage (TCO) Warning:** Many modules in this tool — specifically PFC flooding and TCO orchestration — are designed to halt traffic flow. Using these on a live environment will likely trigger a **Total Cluster Outage**. Periodic re-validation is a practical necessity, but it must be conducted in a controlled, isolated environment.

**Author:** Matthew Stits \<stits@stits.org\>  
**Repository:** https://github.com/mstits/Basidium

---

## Architecture

```mermaid
graph TD
    CLI["basidium.c<br/>CLI / main loop"] --> FLOOD["flood.c<br/>packet builders<br/>worker threads"]
    CLI --> TUI["tui.c<br/>ncurses TUI"]
    CLI --> SWEEP["sweep_thread<br/>rate ramp"]
    CLI --> TCO["tco.c<br/>scenario orchestrator"]
    CLI --> SNIFF["sniffer_thread<br/>learning / adaptive<br/>fail-open detection"]
    FLOOD --> PCAP["libpcap<br/>pcap_inject"]
    TCO --> |"mutates conf.mode<br/>+ conf.pps"| FLOOD
    SWEEP --> |"mutates conf.pps<br/>+ launches NCCL"| NCCL
    TCO --> |"launches NCCL<br/>per step"| NCCL["nccl.c<br/>NCCL subprocess"]
    TUI --> NCCL
    TUI --> NIC["nic_stats.c<br/>Linux: /sys/class/net<br/>macOS: getifaddrs"]
    CLI --> REPORT["report.c<br/>JSON report"]
    CLI --> PROFILES["profiles.c<br/>~/.basidium/"]
```

### Flood Modes & Packet Path

```mermaid
graph LR
    subgraph "Flood Modes"
        M0[mac<br/>CAM flood]
        M1[arp<br/>ARP storm]
        M2[dhcp<br/>starvation]
        M3[pfc<br/>RoCE/RDMA]
        M4[nd<br/>IPv6 ND]
        M5[lldp<br/>CPU path]
        M6[stp<br/>TCN flush]
        M7[igmp<br/>multicast snoop]
    end

    subgraph "Worker Thread"
        FP[Fast path<br/>Xorshift128+<br/>direct MAC write]
        SP[Slow path<br/>per-thread RNG<br/>full packet rebuild]
    end

    M0 -->|no stealth/VLAN-range| FP
    M0 -->|stealth/learning/VLAN| SP
    M1 & M2 & M3 & M4 & M5 & M6 & M7 --> SP
```

### Thread-Safe RNG Architecture

```mermaid
graph TD
    MAIN[main thread<br/>seeds probe_signature] --> W0[Worker 0<br/>rng_init seed=0]
    MAIN --> W1[Worker 1<br/>rng_init seed=1]
    MAIN --> WN[Worker N<br/>rng_init seed=N]

    W0 --> RNG0[xorshift128+<br/>thread-local state]
    W1 --> RNG1[xorshift128+<br/>thread-local state]
    WN --> RNGN[xorshift128+<br/>thread-local state]

    RNG0 --> B0[build_packet_*<br/>rng_rand for MACs,IPs]
    RNG1 --> B1[build_packet_*<br/>rng_rand for MACs,IPs]
    RNGN --> BN[build_packet_*<br/>rng_rand for MACs,IPs]
```

### TUI Launch Sequence

```mermaid
sequenceDiagram
    participant User
    participant TUI
    participant Workers
    participant Sniffer
    participant Switch

    User->>TUI: launch --tui
    TUI->>Workers: spawn (standby)
    TUI->>Sniffer: spawn (if learning/detect)
    Sniffer->>Sniffer: install BPF filter
    User->>TUI: press s (start)
    TUI->>Workers: set is_started=1
    loop inject
        Workers->>Switch: inject frames
        Switch-->>Sniffer: echo (if fail-open)
        Sniffer-->>TUI: fail_open_detected alert
    end
    User->>TUI: press q
    TUI->>Workers: set is_running=0
```

### Where Basidium Fits in a GPU Cluster

```mermaid
graph TB
    subgraph "GPU Training Cluster"
        GPU1["GPU Server 1<br/>ConnectX-7 100GbE"]
        GPU2["GPU Server 2<br/>ConnectX-7 100GbE"]
        GPU3["GPU Server 3<br/>ConnectX-7 100GbE"]
        GPU4["GPU Server 4<br/>ConnectX-7 100GbE"]
    end

    subgraph "Fabric"
        TOR1["ToR Switch 1<br/>Lossless Ethernet<br/>PFC + ECN"]
        TOR2["ToR Switch 2<br/>Lossless Ethernet<br/>PFC + ECN"]
        SPINE["Spine Switch"]
    end

    GPU1 & GPU2 --> TOR1
    GPU3 & GPU4 --> TOR2
    TOR1 & TOR2 --> SPINE

    subgraph "Basidium Host"
        B["Basidium"]
        TCO_F[".tco scenario"]
        NCCL_T["NCCL test"]
        REPORT_F["JSON report"]
    end

    TCO_F --> |"defines steps"| B
    B --> |"inject PFC/MAC/ARP/STP"| TOR1
    B --> |"launches per step"| NCCL_T
    NCCL_T --> |"allreduce via fabric"| TOR1
    B --> REPORT_F

    style B fill:#2d6,stroke:#000,color:#fff
    style TOR1 fill:#f96,stroke:#000
    style TCO_F fill:#369,stroke:#000,color:#fff
```

---

## Building

**Dependencies:** `libpcap-dev`, `libncurses-dev` (TUI only), `gcc`, `make`

```sh
# CLI only
make

# With ncurses TUI
make TUI=1

# Debug build
make debug

# Install to /usr/local
sudo make install

# Custom prefix
sudo make install PREFIX=/opt/local

# Self-test (12 packet builder tests)
sudo make selftest
```

**Platform notes:**
- Linux: fully supported; NIC TX/RX statistics read from `/sys/class/net/`
- macOS: fully supported; NIC statistics read via `getifaddrs()` + `AF_LINK` `if_data`
- FreeBSD / OpenBSD / NetBSD: NIC statistics supported via same BSD `getifaddrs()` path
- Raw packet injection requires root (`sudo`) on all platforms

---

## Quick Start

```sh
# ---- Build ----
make TUI=1                    # compile with ncurses TUI

# ---- Basic Stress ----
sudo ./basidium -i eth0 -t 4                         # MAC CAM flood, 4 threads
sudo ./basidium -i eth0 -M arp -r 5000 --tui         # ARP storm at 5000 pps with TUI
sudo ./basidium -i eth0 -M pfc                       # PFC PAUSE flood on RDMA priority 3
sudo ./basidium -i eth0 -M igmp -t 4                 # IGMP snooping exhaustion

# ---- Rate Sweep + NCCL Correlation ----
sudo ./basidium -i eth0 --sweep 1000:50000:5000:30 --nccl --report

# ---- TCO Scenario ----
sudo ./basidium -i eth0 --scenario pfc-ramp.tco --nccl --report

# ---- Fail-Open Detection ----
sudo ./basidium -i eth0 --detect -A --tui

# ---- Dry Run (no sudo, no NIC) ----
./basidium --dry-run -M pfc -n 1000
```

*Build your models on a solid pedestal. Build on Basidium.*

---

## Flood Modes (`-M`)

| Mode   | dst MAC              | EtherType | Effect |
|--------|----------------------|-----------|--------|
| `mac`  | random               | 0x0800    | Exhausts CAM table; switch degrades to hub |
| `arp`  | ff:ff:ff:ff:ff:ff    | 0x0806    | Floods ARP table |
| `dhcp` | ff:ff:ff:ff:ff:ff    | 0x0800    | Starves DHCP address pool |
| `pfc`  | 01:80:C2:00:00:01    | 0x8808    | Freezes RoCE/RDMA priority queues |
| `nd`   | 33:33:ff:xx:xx:xx    | 0x86DD    | Exhausts IPv6 ND/NDP table |
| `lldp` | 01:80:C2:00:00:0E    | 0x88CC    | Stresses switch CPU / LLDP daemon |
| `stp`  | 01:80:C2:00:00:00    | LLC       | Triggers repeated MAC table flushes |
| `igmp` | 01:00:5E:xx:xx:xx    | 0x0800    | Exhausts IGMP snooping table |

---

## All Options

### Interface & Performance
| Flag | Default | Description |
|------|---------|-------------|
| `-i <iface>` | required | Network interface |
| `-t <n>` | 1 | Worker threads (max 16) |
| `-r <pps>` | 0 (unlimited) | Rate limit packets/sec |
| `-J <bytes>` | 60 | Frame size (60-9216) |
| `-n <count>` | 0 (unlimited) | Stop after N frames |

### VLAN & PFC
| Flag | Default | Description |
|------|---------|-------------|
| `-V <id>` | 0 (untagged) | 802.1Q VLAN ID (1-4094) |
| `--vlan-pcp <0-7>` | 0 | 802.1p priority bits |
| `--vlan-range <end>` | — | Random VID per frame from `-V` to `end` |
| `--qinq <outer-vid>` | — | 802.1ad outer tag (combine with `-V` for double-tag) |
| `--pfc-priority <0-7>` | 3 | PFC priority class (3 = RDMA on Mellanox/NVIDIA) |
| `--pfc-quanta <val>` | 65535 | PFC pause duration (0-65535) |

### Stealth & Targeting
| Flag | Description |
|------|-------------|
| `-S <OUI>` | Restrict source MAC OUI (e.g. `00:11:22`) |
| `-T <CIDR>` | Embed IPs from subnet; repeatable up to 64 |
| `-L` | Learning mode — skip observed MACs |
| `-A` | Adaptive mode — throttle on broadcast storm |
| `-U` | Allow multicast source MACs |
| `-R` | Randomize DHCP client MAC independently |

### Burst & Advanced
| Flag | Description |
|------|-------------|
| `--burst <count:gap_ms>` | Send `count` frames at wire speed, pause `gap_ms` ms |
| `--detect` | Fail-open detection via embedded probe signature |
| `--payload <pattern>` | MAC flood payload: `zeros` `ff` `dead` `incr` |

### Rate Sweep
```
--sweep start:end:step[:hold_s]
```
Ramps injection rate from `start` to `end` PPS in `step` increments, holding each for `hold_s` seconds (default 10). Exits on completion and writes a JSON report.

### Output & Logging
| Flag | Description |
|------|-------------|
| `-v` | Verbose per-thread and live PPS |
| `-l <file>` | JSON event log |
| `--tui` | ncurses TUI (requires `make TUI=1`) |
| `--report [file]` | JSON session report on exit |
| `--pcap-out <file>` | Write frames to `.pcap` |
| `--pcap-replay <file>` | Replay `.pcap` onto interface |

### NCCL Correlation
| Flag | Description |
|------|-------------|
| `--nccl` | NCCL busbw correlation panel in TUI; per-step measurement during `--sweep` and `--scenario` |
| `--nccl-binary <path>` | Path to nccl-tests binary (implies `--nccl`) |

### TCO (Targeted Congestion Orchestration)
| Flag | Description |
|------|-------------|
| `--scenario <file>` | Run a multi-step congestion scenario from a `.tco` file (mutually exclusive with `--sweep`) |

### Profiles & Sessions
| Flag | Description |
|------|-------------|
| `--profile <name>` | Load `~/.basidium/<name>.conf` |
| `--duration <time>` | Auto-stop: `30`, `5m`, `2h` |

### Diagnostics
| Flag | Description |
|------|-------------|
| `--selftest` | Run 12 built-in validation tests |
| `--version` | Print version and exit |
| `--dry-run` | Build & count packets without injecting (no sudo needed) |

---

## TUI

Launch with `--tui` (requires `make TUI=1`). Starts in **STANDBY** — no injection until you press `s` or Enter.

### Key Bindings
| Key | Action |
|-----|--------|
| `s` / Enter | Start injecting |
| Space | Pause / Resume |
| `q` | Quit |
| `?` | Help overlay |
| `p` | Profile menu |
| `+` / `=` | Rate +1000 pps |
| `-` | Rate -1000 pps |
| `o` | Set OUI prefix |
| `v` | Set VLAN ID |
| `n` | Toggle NCCL panel |
| `b` | Record NCCL baseline |
| `l` | Load `.pcap` for replay |

### Panels
- **Header** — mode, interface, `[STANDBY]`/`[RUNNING]`/`[PAUSED]`, blinking `[!FAIL-OPEN DETECTED!]` when triggered
- **Live Stats** — PPS, total frames, uptime, session countdown, sparkline, per-thread PPS, NIC tx/rx/drop/error
- **Config** — mode, rate or sweep progress, threads, OUI, VLAN/PFC settings
- **NCCL** — busbw, baseline, degradation% (with `--nccl`)
- **Log** — scrolling event log

---

## Switch-Side Qualification Playbook

Each flood mode targets a specific failure mode. The table below maps each mode to the switch counters and behavior you should observe during testing.

### What to Watch Per Mode

| Mode | Target Failure | Expected Switch Behavior | Key Counters / Logs |
|------|---------------|-------------------------|---------------------|
| `mac` | CAM table overflow, fail-open | `dot1dTpLearnedEntryDiscards` climbs; port may flood all frames. Use `--detect` to confirm. | `dot1dTpLearnedEntryDiscards` (1.3.6.1.2.1.17.4.3.1.3), `ifInDiscards` |
| `pfc` | PFC deadlock, watchdog trigger | Target priority queue pauses; watch for PFC watchdog syslog events. Lossless traffic on that priority should halt. | Memory buffer utilization, PFC watchdog syslog, `cbQosPoliceCfgRate` |
| `arp` | ARP table exhaustion | ARP table fills; new entries fail to resolve. Watch for ARP timeouts in switch logs. | `ipNetToMediaTable` (1.3.6.1.2.1.4.22), ARP cache size |
| `dhcp` | DHCP pool starvation | DHCP server exhausts address pool. Useful for testing relay agent behavior. | DHCP server pool utilization, relay counters |
| `stp` | Spanning-tree instability | TCN triggers MAC table flush followed by brief flood mode per flush. `dot1dStpTopChanges` should increment rapidly. | `dot1dStpTopChanges` (1.3.6.1.2.1.17.2.4), `dot1dStpRootPort` |
| `igmp` | IGMP snooping table exhaustion | Snooping table fills; switch falls back to flooding multicast. | `igmpCacheTable` (1.3.6.1.2.1.85.1.2), multicast group count |
| `lldp` | Control-plane CPU stress | LLDP neighbor count climbs; switch CPU may spike. Watch for LLDP flap warnings. | `lldpRemTable`, CPU utilization MIB |
| `nd` | IPv6 ND table exhaustion | ND cache fills; neighbor resolution fails for legitimate hosts. | IPv6 neighbor cache size, ICMPv6 error counters |

Basidium's JSON event log and session reports pair directly with SNMP polling to correlate injection activity with live switch MIB counters.

### Useful MIB OIDs (Reference)

| Metric | MIB Object | OID |
|--------|-----------|-----|
| CAM discard events | `dot1dTpLearnedEntryDiscards` | 1.3.6.1.2.1.17.4.3.1.3 |
| CAM aging time | `dot1dTpAgingTime` | 1.3.6.1.2.1.17.4.2 |
| STP topology changes | `dot1dStpTopChanges` | 1.3.6.1.2.1.17.2.4 |
| Interface errors | `ifInErrors` | IF-MIB::ifInErrors |
| Interface discards | `ifInDiscards` | IF-MIB::ifInDiscards |
| IGMP group table | `igmpCacheTable` | 1.3.6.1.2.1.85.1.2 |

### Poll switch counters alongside a flood run

```bash
#!/bin/bash
# poll-snmp.sh — record CAM, STP, and interface counters during injection
SWITCH=192.168.1.1
COMMUNITY=public

while true; do
  TS=$(date +%s)
  CAM=$(snmpget -v2c -c $COMMUNITY $SWITCH \
    1.3.6.1.2.1.17.4.3.1.3.0 2>/dev/null | awk '{print $NF}')
  ERR=$(snmpget -v2c -c $COMMUNITY $SWITCH \
    IF-MIB::ifInErrors.1 2>/dev/null | awk '{print $NF}')
  STP=$(snmpget -v2c -c $COMMUNITY $SWITCH \
    1.3.6.1.2.1.17.2.4.0 2>/dev/null | awk '{print $NF}')
  echo "$TS cam_discards=$CAM if_errors=$ERR stp_topo_changes=$STP"
  sleep 1
done
```

```bash
# Terminal 1: start SNMP polling
./poll-snmp.sh | tee snmp-log.txt &

# Terminal 2: run Basidium sweep
sudo ./basidium -i eth0 --sweep 1000:100000:10000:5 --report sweep.json
```

### Python: correlate sweep report with SNMP

```python
#!/usr/bin/env python3
"""
Correlate basidium sweep JSON with live SNMP counters.
Requires: pip install pysnmp
"""
import json
from pysnmp.hlapi import *

SWITCH    = "192.168.1.1"
COMMUNITY = "public"
REPORT    = "sweep.json"

def snmp_get(oid):
    it = getCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        UdpTransportTarget((SWITCH, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, _, varBinds = next(it)
    if errorIndication or errorStatus:
        return None
    return int(varBinds[0][1])

with open(REPORT) as f:
    report = json.load(f)

print(f"Interface:  {report['interface']}")
print(f"Duration:   {report['duration_s']}s")
print(f"Total sent: {report['total_packets']:,}")
print(f"Peak PPS:   {report['peak_pps']:,}")
print()

cam  = snmp_get("1.3.6.1.2.1.17.4.3.1.3.0")
stp  = snmp_get("1.3.6.1.2.1.17.2.4.0")
errs = snmp_get("1.3.6.1.2.1.2.2.1.14.1")

print(f"CAM discards:        {cam}")
print(f"STP topo changes:    {stp}")
print(f"Interface errors:    {errs}")
print()

if report.get("sweep"):
    print("Sweep results:")
    for s in report["sweep"]:
        eff = s['achieved_pps'] / s['target_pps'] * 100
        print(f"  step {s['step']:>2}: {s['target_pps']:>8} pps target  "
              f"→  {s['achieved_pps']:>8} achieved  ({eff:.1f}%)")
```

### Watch STP TCN events during STP flood

```bash
# Capture SNMP traps from the switch
snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf &

# Run STP TCN flood
sudo ./basidium -i eth0 -M stp -r 100 -l events.json

# Count topology change traps received
grep -c "topologyChange" /var/log/snmptrapd.log
```

---

## Switch Fail-Open Detection (`--detect`)

Basidium embeds a random 16-bit probe signature in the IP ID field of every MAC-flood frame. The sniffer thread watches the interface; if a frame with that signature is received back, the switch has entered hub mode.

```mermaid
sequenceDiagram
    participant B as Basidium
    participant SW as Switch (healthy)
    participant SW2 as Switch (fail-open)

    B->>SW: inject frame [ip_id=probe]
    SW->>SW: CAM lookup → unicast forward
    note over SW: not echoed back

    B->>SW2: inject frame [ip_id=probe]
    SW2->>SW2: CAM full → flood all ports
    SW2-->>B: echo [ip_id=probe]
    B->>B: fail_open_detected = 1
    B-->>B: TUI alert + FAIL_OPEN log event
```

```sh
sudo ./basidium -i eth0 --detect -A --tui
```

---

## Rate Sweep & Reporting

```mermaid
flowchart LR
    A[sweep_start PPS] -->|+sweep_step| B[inject for sweep_hold s]
    B --> N{--nccl?}
    N -->|yes| F[launch NCCL test]
    F --> G[wait for NCCL completion]
    G --> H[record PPS + busbw]
    N -->|no| E[record achieved PPS]
    E --> C{reached sweep_end?}
    H --> C
    C -->|no| A
    C -->|yes| D["write JSON report<br/>exit"]
```

```sh
# Standard sweep (no NCCL)
sudo ./basidium -i eth0 --sweep 1000:100000:10000:5 --report /tmp/report.json

# NCCL-correlated sweep — measures busbw at each congestion level
sudo ./basidium -i eth0 -M pfc --sweep 1000:50000:5000:30 --nccl --report
```

When `--sweep` and `--nccl` are both active, Basidium launches an NCCL test at each sweep step and waits for it to complete before advancing to the next PPS level. The first step's busbw becomes the baseline; subsequent steps report degradation relative to that baseline. This produces per-step correlation showing exactly how congestion affects application-layer throughput.

> **Note:** The NCCL test runs concurrently with injection, so it measures busbw under active congestion. The sweep hold time should be at least as long as the NCCL test duration (typically 30-120s depending on `--nccl-binary` args). If the NCCL test takes longer than the hold period, the sweep waits for completion before moving on.

Example report (with NCCL correlation):

```json
{
  "generated": "2026-04-10T22:00:00Z",
  "interface": "eth0",
  "mode": "pfc",
  "threads": 1,
  "duration_s": 180,
  "total_packets": 4823000,
  "peak_pps": 48200,
  "sweep": {
    "start": 1000,
    "end": 50000,
    "step": 5000,
    "hold_s": 30,
    "nccl_baseline_busbw": 76.50,
    "steps": [
      {"pps_target": 1000,  "pps_achieved": 999,   "nccl_busbw": 76.50, "nccl_degradation_pct": 0.0},
      {"pps_target": 6000,  "pps_achieved": 5998,  "nccl_busbw": 74.20, "nccl_degradation_pct": -3.0},
      {"pps_target": 11000, "pps_achieved": 10995, "nccl_busbw": 68.10, "nccl_degradation_pct": -11.0},
      {"pps_target": 16000, "pps_achieved": 15990, "nccl_busbw": 52.30, "nccl_degradation_pct": -31.6}
    ]
  }
}
```

---

## TCO — Targeted Congestion Orchestration

Scenario files (`.tco`) define multi-step, multi-mode congestion patterns for automated fabric qualification. The orchestrator thread steps through each configuration, dynamically switching worker threads between flood modes at runtime. With `--nccl`, each step measures application-layer throughput under the current congestion conditions.

```mermaid
flowchart TD
    LOAD["Load .tco scenario"] --> STEP["Apply step: set mode + PPS"]
    STEP --> INJECT["Workers inject at target rate"]
    INJECT --> NCCL_Q{"--nccl?"}
    NCCL_Q --> |yes| NCCL_RUN["Launch NCCL test<br/>measure busbw under congestion"]
    NCCL_Q --> |no| HOLD["Hold for duration_s"]
    NCCL_RUN --> HOLD
    HOLD --> RECORD["Record achieved PPS + busbw"]
    RECORD --> MORE{"More steps?"}
    MORE --> |yes| STEP
    MORE --> |no| REPORT["Write JSON report + exit"]
```

### Scenario File Format

```
# Each line: mode  pps  duration_s  [nccl]
# Comments start with #. Blank lines ignored.

mac   1000  30  nccl     # baseline: light MAC flood + NCCL measurement
pfc   5000  60  nccl     # light PFC stress
pfc  20000  60  nccl     # moderate PFC stress
pfc  50000  60  nccl     # heavy PFC stress
arp  10000  30           # ARP storm (no NCCL measurement this step)
mac   1000  30  nccl     # recovery baseline
```

### Usage

```sh
# Run scenario with NCCL correlation
sudo ./basidium -i eth0 --scenario /path/to/scenario.tco --nccl --report

# Run scenario without NCCL
sudo ./basidium -i eth0 --scenario examples/pfc-stress-ramp.tco --report
```

### Example Report (with NCCL)

```json
{
  "scenario": {
    "name": "pfc-stress-ramp",
    "file": "examples/pfc-stress-ramp.tco",
    "nccl_baseline_busbw": 76.50,
    "steps": [
      {"mode": "mac", "pps_target": 1000,  "duration_s": 30, "pps_achieved": 999,   "nccl_busbw": 76.50, "nccl_degradation_pct": 0.0},
      {"mode": "pfc", "pps_target": 5000,  "duration_s": 60, "pps_achieved": 4998,  "nccl_busbw": 74.20, "nccl_degradation_pct": -3.0},
      {"mode": "pfc", "pps_target": 20000, "duration_s": 60, "pps_achieved": 19995, "nccl_busbw": 68.10, "nccl_degradation_pct": -11.0},
      {"mode": "pfc", "pps_target": 50000, "duration_s": 60, "pps_achieved": 49800, "nccl_busbw": 52.30, "nccl_degradation_pct": -31.6},
      {"mode": "arp", "pps_target": 10000, "duration_s": 30, "pps_achieved": 9998},
      {"mode": "mac", "pps_target": 1000,  "duration_s": 30, "pps_achieved": 999,   "nccl_busbw": 75.80, "nccl_degradation_pct": -0.9}
    ]
  }
}
```

---

## PFC PAUSE for RoCE/RDMA Testing

IEEE 802.3 MAC Control frame layout for PFC mode:

```
[dst: 01:80:C2:00:00:01 (6B)][src: random (6B)]
[EtherType: 0x8808 (2B)][Opcode: 0x0101 (2B)]
[Priority Enable Vector (2B)][quanta[0..7]: 16B]
[pad to 60B]
```

Default priority 3 is the standard lossless class on Mellanox/NVIDIA ConnectX and BlueField. Only the target priority bit is set in the PEV; all other quanta are zero.

```sh
sudo ./basidium -i eth0 -M pfc -V 100 --pfc-priority 3 --pfc-quanta 65535
```

### Note on Apple RDMA over Thunderbolt 5

macOS 26.2 introduced native RDMA over Thunderbolt 5 with an `ibverbs`-compatible API (`infiniband/verbs.h`, `librdma.tbd`). This is a fundamentally different transport from the RoCE/InfiniBand-over-Ethernet fabrics that Basidium targets:

| | GPU Cluster Fabric (Basidium) | Apple TB5 RDMA |
|---|---|---|
| **Transport** | Ethernet (RoCEv2) | Thunderbolt 5 protocol |
| **Flow control** | PFC PAUSE (IEEE 802.1Qbb) | Credit-based (TB controller HW) |
| **Topology** | Multi-hop switched fabric | Point-to-point, no switch |

Basidium's `-M pfc` mode generates IEEE 802.1Qbb MAC Control frames (`EtherType 0x8808`) that stress-test Ethernet switch priority queues. A Thunderbolt 5 controller does not process these frames — it uses credit-based flow control at the hardware level. The failure modes that matter for TB5 RDMA (QP exhaustion, PD leaks, credit stalls) are verbs-level application concerns, not Layer-2 fabric issues.

---

## QinQ Double-Tagging

With `-V 100 --qinq 200` the wire format is:

```
[dst][src][0x88A8][outer TCI VID=200][0x8100][inner TCI VID=100][EtherType][payload]
```

Useful for provider bridges (802.1ad), metro Ethernet, and L2VPN stitching.

```sh
sudo ./basidium -i eth0 -V 100 --qinq 200 -t 4
```

---

## Named Profiles

Profiles are stored in `~/.basidium/` as key=value files. All fields — VLAN, PFC, sweep, burst, detect, QinQ, payload, threads, rate — are persisted. Profile names are restricted to alphanumeric characters, dashes, and underscores to prevent path traversal.

```sh
# Save from TUI: press p → s → type name → Enter

# Load from CLI
sudo ./basidium --profile rdma-stress
sudo ./basidium --profile stp-flood
```

---

## Source Layout

```
basidium.c      main(), CLI parsing, thread orchestration, SIGINT/SIGTERM
flood.c         packet builders, worker threads, sniffer, RNG, selftest
flood.h         shared types, flood_mode_t enum, config struct, prototypes
tco.c/.h        TCO scenario parser + orchestrator thread
tui.c           ncurses TUI (make TUI=1)
nccl.c/.h       NCCL subprocess orchestration
profiles.c/.h   named profile save/load (~/.basidium/) with name sanitization
nic_stats.c/.h  NIC statistics (Linux: sysfs, macOS/BSD: getifaddrs)
report.c/.h     JSON session report writer
```

### Fast Path

In MAC flood mode without stealth, learning, or VLAN-range active, workers use Xorshift128+ to overwrite only the 12 MAC bytes of a pre-built frame template — no packet-builder overhead, near wire-rate throughput.

### Thread Safety

All packet builders accept a per-thread `struct rng_state *` parameter. No global `rand()` calls occur in worker threads. Each thread initializes its own xorshift128+ state from a unique seed, ensuring deterministic, lock-free random number generation.

---

## Dependencies

| Library | Debian/Ubuntu | RHEL/Fedora | macOS (Homebrew) |
|---------|--------------|-------------|-----------------|
| libpcap | `libpcap-dev` | `libpcap-devel` | `brew install libpcap` (usually preinstalled) |
| libpthread | standard | standard | standard |
| libncurses | `libncurses-dev` | `ncurses-devel` (TUI only) | preinstalled |

---

## License

For authorized laboratory use.  
© Matthew Stits — https://github.com/mstits/Basidium

*Build your models on a solid pedestal.*
