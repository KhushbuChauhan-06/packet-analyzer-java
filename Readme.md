# 🚀 DPI Engine — High Performance Deep Packet Inspection System

<div align="center">

![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=openjdk)
![Multithreading](https://img.shields.io/badge/Multithreading-Concurrent-green?style=for-the-badge)
![Networking](https://img.shields.io/badge/Networking-TCP%2FIP-blue?style=for-the-badge)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-DPI-red?style=for-the-badge)
![PCAP](https://img.shields.io/badge/PCAP-Packet%20Analysis-purple?style=for-the-badge)
![Thread Safe](https://img.shields.io/badge/Thread--Safe-Queues-success?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

<h3>⚡ Multi-threaded Deep Packet Inspection Engine for Real-Time Network Traffic Analysis</h3>

</div>

---

# 📌 Overview

This project is a **high-performance Deep Packet Inspection (DPI) Engine** built completely in **Java**, designed to analyze and classify network traffic from `.pcap` files using a scalable **multi-threaded packet processing architecture**.

The system simulates how modern:
- Enterprise Firewalls
- Intrusion Detection Systems (IDS)
- Traffic Monitoring Systems
- Network Security Appliances

inspect encrypted and unencrypted traffic efficiently.

---

# ✨ Features

## 🔍 Deep Packet Inspection (DPI)
- Parses raw network packets
- Inspects packet payloads
- Detects application-level traffic

---

## 🔐 TLS SNI Extraction
Extracts domain names from encrypted HTTPS traffic using:
- TLS Handshake Parsing
- Server Name Indication (SNI)

Example:
```text
www.youtube.com → YouTube
github.com      → GitHub
facebook.com    → Facebook
```

---

## 🌐 HTTP Host Detection
Detects websites from HTTP Host headers.

---

## ⚡ Multi-threaded Packet Processing
Implements:
- Producer-Consumer Architecture
- Thread-safe Queues
- Load Balancers
- Fast Path Workers
- Concurrent Packet Pipelines

---

## 🚫 Rule-Based Blocking Engine
Supports:
- IP Blocking
- Domain Blocking
- Application Blocking

Example:
```bash
--block-app YouTube
--block-domain facebook
--block-ip 192.168.1.50
```

---

## 📊 Real-time Statistics
Tracks:
- Packet Counts
- Traffic Distribution
- Application Classification
- Thread Statistics
- Forwarded vs Dropped Packets

---

# 🏗️ System Architecture

```text
                 ┌──────────────────┐
                 │   PCAP Reader    │
                 └────────┬─────────┘
                          │
              ┌───────────▼───────────┐
              │    Load Balancers     │
              └───────┬───────┬───────┘
                      │       │
              ┌───────▼─┐ ┌──▼────────┐
              │ FastPath│ │ FastPath  │
              │ Worker  │ │ Worker    │
              └───────┬─┘ └──┬────────┘
                      │       │
               ┌──────▼───────▼─────┐
               │ Packet Classification│
               └─────────┬──────────┘
                         │
                 ┌───────▼────────┐
                 │  PCAP Writer   │
                 └────────────────┘
```

---

# 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| Language | Java 17 |
| Networking | TCP/IP, UDP, Ethernet |
| Security | Deep Packet Inspection |
| Concurrency | Multithreading, Thread Pools |
| Packet Analysis | PCAP Processing |
| Architecture | Producer-Consumer Pipeline |
| Concepts | Flow Tracking, SNI Parsing |
| Tools | Git, VS Code |

---

# 📂 Project Structure

```text
PACKET_ANALYZER/
│
├── out/
│
├── src/com/dpi/pcap/
│   ├── AppType.java
│   ├── DNSExtractor.java
│   ├── DPIEngine.java
│   ├── FastPath.java
│   ├── FiveTuple.java
│   ├── FlowEntry.java
│   ├── HTTPHostExtractor.java
│   ├── LoadBalancer.java
│   ├── Main.java
│   ├── PacketJob.java
│   ├── PacketParser.java
│   ├── ParsedPacket.java
│   ├── PcapGlobalHeader.java
│   ├── PcapPacketHeader.java
│   ├── PcapReader.java
│   ├── PcapWriter.java
│   ├── RawPacket.java
│   ├── RuleManager.java
│   ├── SNIExtractor.java
│   └── TSQueue.java
│
├── test_dpi.pcap
├── output.pcap
└── README.md
```

---

# 🧠 Core Concepts Implemented

- Deep Packet Inspection (DPI)
- TLS Handshake Parsing
- SNI Extraction
- HTTP Host Parsing
- Packet Parsing
- Flow Tracking
- Five Tuple Hashing
- Thread Synchronization
- Concurrent Queues
- Load Balancing
- High Throughput Processing
- Network Traffic Classification
- Producer-Consumer Pattern

---

# 🔬 Supported Protocols

| Layer | Protocols |
|---|---|
| Data Link | Ethernet |
| Network | IPv4 |
| Transport | TCP, UDP |
| Application | HTTP, HTTPS, DNS |

---

# 📈 Sample Output

```text
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded Java)          ║
╠══════════════════════════════════════════════════════════════╣
║  Load Balancers:  2    FPs per LB:  2    Total FPs:  4      ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked domain: facebook

════════════════ PROCESSING REPORT ════════════════

Total Packets:      77
Forwarded Packets:  69
Dropped Packets:     8

Detected Applications:
- YouTube
- Facebook
- Google
- GitHub
```

---

# 🚀 How to Run

## 🔨 Compile

```bash
javac -d out src/com/dpi/pcap/*.java
```

---

## ▶️ Run

```bash
java -cp out com.dpi.pcap.Main test_dpi.pcap output.pcap
```

---

## 🚫 Run with Blocking Rules

```bash
java -cp out com.dpi.pcap.Main test_dpi.pcap output.pcap ^
--block-app YouTube ^
--block-domain facebook
```

---

# 🎯 Why This Project Stands Out

✅ Demonstrates strong understanding of:
- Computer Networks
- Operating Systems
- Concurrent Programming
- Cybersecurity
- Systems Design

✅ Shows real-world engineering concepts:
- Multi-threaded architecture
- High-performance packet processing
- Low-level protocol parsing
- Traffic classification pipelines
- Concurrent packet scheduling

✅ Relevant for:
- Backend Engineering
- Systems Engineering
- Cybersecurity Roles
- Network Security
- Infrastructure Engineering
- Cloud Networking

---

# 📚 What I Learned

Through this project, I gained hands-on experience in:

- Designing scalable concurrent systems
- Understanding TCP/IP internals
- Parsing binary packet structures
- TLS protocol inspection
- High-performance networking
- Traffic analysis pipelines
- Thread-safe system design
- Producer-Consumer concurrency models

---

# 🔮 Future Improvements

- QUIC / HTTP3 Support
- Real-time Live Packet Capture
- GUI Monitoring Dashboard
- AI-based Traffic Classification
- Redis-backed Flow Cache
- Dockerized Deployment
- Kubernetes Scaling
- REST API Integration

---

# 👨‍💻 Author

## Khushbu Chauhan

M.Tech Computer Science Engineer passionate about:
- Backend Development
- Systems Programming
- Network Security
- Distributed Systems
- High Performance Computing

---

# ⭐ Star This Repository

If you found this project interesting or useful, consider giving it a ⭐ on GitHub!

---

<div align="center">

## 🔥 Built with Java + Networking + Multithreading + Cybersecurity

</div>