# SENTINEL IDS

A real-time network intrusion detection system (IDS) that runs on Windows, listens to live network traffic, detects 5 types of cyber attacks, and presents everything through a dual tactical interface — a terminal UI and a web dashboard.

---

## What It Does

SENTINEL captures every packet that travels through the network and analyzes it in real time. When it detects suspicious behavior, it raises an alert with the attacker's IP, the attack type, and a severity score. The user can then choose to block the attacker with a single keystroke.

**The 5 attacks SENTINEL detects:**

| # | Attack Type | Network Layer | What It Looks For |
|---|-------------|---------------|-------------------|
| 1 | Port Scan | L4 – Transport | Unusual SYN bursts across many ports |
| 2 | ARP Spoofing | L2 – Data Link | MAC/IP mapping conflicts |
| 3 | Brute Force | L7 – Application | Repeated SSH/HTTP login attempts |
| 4 | DNS Anomaly | L7 – Application | DNS tunneling, high-frequency queries |
| 5 | SYN Flood | L4 – Transport | Flood of half-open TCP connections |

---

## Architecture Overview

```
[Network Interface / PCAP File]
            ↓
    [Packet Capture Engine]        core/capture/engine.py
            ↓
       [Packet Parser]             core/capture/parser.py
            ↓
    [Thread-Safe Fan-Out Queue]    core/capture/queue.py
     ↓     ↓     ↓     ↓     ↓
  [Port] [ARP] [BF] [DNS] [SYN]   core/detectors/
     ↓     ↓     ↓     ↓     ↓
        [Alert Manager]            core/alerts/
         ↓           ↓
   [Terminal UI]  [Web Dashboard]  ui/tui/  ui/web/
         ↓
  [Response Engine]                core/response/
         ↓
   [SQLite Database]               db/
```

Each component has one responsibility and does not know about the others. The capture engine does not know detectors exist. The detectors do not know about the UI. This design is called **Separation of Concerns** and makes each part independently testable and replaceable.

---

## Folder Structure

```
sentinel/
├── core/                   # All network and security logic
│   ├── capture/            # Packet ingestion pipeline
│   │   ├── engine.py       # Listens to network interface or reads PCAP file
│   │   ├── parser.py       # Breaks raw Scapy packet into clean fields
│   │   └── queue.py        # Fan-out queue – sends each packet to all detectors
│   ├── detectors/          # One file per attack type
│   │   ├── port_scan.py
│   │   ├── arp_spoof.py
│   │   ├── brute_force.py
│   │   ├── dns_anomaly.py
│   │   └── syn_flood.py
│   ├── alerts/             # Alert lifecycle management
│   │   ├── manager.py      # Receives alerts, deduplicates, scores severity
│   │   └── scoring.py      # Threat scoring engine (0–100)
│   └── response/           # Automated and manual response actions
│       ├── engine.py       # Waits for user confirmation before acting
│       └── firewall.py     # Adds/removes Windows Firewall rules via netsh
│
├── db/                     # Data persistence layer
│   ├── models.py           # SQLAlchemy table definitions
│   └── queries.py          # Reusable queries (top IPs, alerts per hour, etc.)
│
├── ui/
│   ├── tui/                # Terminal UI (Textual framework)
│   │   ├── app.py          # Main Textual application
│   │   └── widgets/        # Custom panels: packet log, alert feed, stats bar
│   └── web/                # Web dashboard (FastAPI + WebSocket)
│       ├── app.py          # FastAPI routes and WebSocket endpoint
│       └── static/         # HTML, CSS, Chart.js frontend
│
├── config/
│   └── config.yaml         # All tunable thresholds – no hardcoded values in code
│
├── tests/                  # Automated tests
│   ├── test_queue.py
│   ├── test_parser.py
│   └── test_detectors/
│
├── docs/
│   ├── adr/                # Architecture Decision Records – why each tool was chosen
│   ├── THREAT_MODEL.md     # What SENTINEL protects against and what it doesn't
│   └── BENCHMARKS.md       # Packets/sec performance on target hardware
│
├── scripts/                # Attack simulation scripts (run from Kali VM or localhost)
│   ├── attack_port_scan.sh
│   ├── attack_arp_spoof.sh
│   ├── attack_brute_force.sh
│   ├── attack_dns_tunnel.sh
│   └── attack_syn_flood.sh
│
├── pcap_samples/           # Pre-recorded attack traffic for offline testing
│
├── main.py                 # Entry point – starts the full system
├── requirements.txt        # Python dependencies
└── DEMO.md                 # Step-by-step demo scenarios for interviews
```

---

## Tech Stack

| Component | Technology | Why |
|-----------|------------|-----|
| Language | Python 3.11+ | Balance of control and productivity; best ecosystem for network tools |
| Packet capture | Scapy + Npcap | Full byte-level control; not a wrapper – we parse every field ourselves |
| Terminal UI | Textual | The most advanced Python TUI framework; looks like a real application |
| Web API | FastAPI | Fast, modern, async-native Python web framework |
| Real-time push | WebSockets | Server pushes alerts to browser – no polling delay |
| Frontend | Vanilla JS + Chart.js | No framework overhead; enough for the use case |
| Database | SQLite + SQLAlchemy | Zero configuration; sufficient for lab scale |
| Packet driver | Npcap | Kernel-mode Windows driver that enables Promiscuous Mode on the NIC |

---

## Key Design Decisions

**Why Scapy and not PyShark or a simpler library?**
Scapy gives direct access to every byte of every packet. We parse IP headers, TCP flags, and DNS payloads ourselves. This means we fully understand what we're detecting, and can explain every field to an interviewer.

**Why a fan-out queue?**
The capture engine runs in one thread. Each of the 5 detectors runs in its own thread. A fan-out queue lets every detector see every packet in parallel without blocking each other. If a detector is slow, it drops packets from its own queue — the other detectors are unaffected.

**Why configuration in YAML and not hardcoded?**
Every detection threshold (e.g., "more than 15 ports in 5 seconds = port scan") lives in `config/config.yaml`. Changing sensitivity requires editing one file, not hunting through code. This is a production pattern from The Twelve-Factor App methodology.

**Why SQLite and not PostgreSQL?**
This system runs in a lab environment on a single machine. SQLite requires zero setup, zero server process, and handles the packet/alert volume comfortably. Switching to PostgreSQL later would only require changing the connection string in `config.yaml`.

**Why PCAP files for development instead of live VMs?**
Running three virtual machines (Kali, Ubuntu, Windows) simultaneously is too resource-intensive on a laptop. Scapy reads `.pcap` files exactly like live traffic, so all five detectors can be developed and tested against real recorded attack traffic — with zero VM overhead.

---

## Testing Strategy

| Stage | Method |
|-------|--------|
| Development | Replay pre-recorded PCAP files with real attack traffic |
| Integration | Single lightweight Docker container as a target |
| Demo | Full live detection against simulated attacks |

---

## Getting Started

```bash
# Install dependencies
pip install -r requirements.txt

# Run the system
python main.py
```

> Npcap must be installed for live capture. Download from https://npcap.com

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Environment setup, project scaffold | ✅ Done – v0.0.1 |
| 1 | Packet capture engine | ✅ Done – v0.1.0 |
| 2 | Port scan detector | ✅ Done – v0.2.0 |
| 3 | Terminal UI | ⬜ Pending |
| 4 | ARP spoof detector | ✅ Done – v0.4.0 |
| 5 | Database & logging | ⬜ Pending |
| 6 | Brute force detector | ✅ Done – v0.6.0 |
| 7 | DNS anomaly detector | ✅ Done – v0.7.0 |
| 8 | SYN flood detector | ⬜ Pending |
| 9 | Web dashboard | ⬜ Pending |
| 10 | Response engine | ⬜ Pending |
| 11 | Advanced features | ⬜ Pending |
| 12 | Demo scenarios | ⬜ Pending |
| 13 | Portfolio polish | ⬜ Pending |
