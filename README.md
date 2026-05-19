# DPI Engine - Deep Packet Inspection System (JavaScript Version)

This document explains everything about this project — from basic networking concepts to the complete JavaScript architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

## Table of Contents

- [What is DPI?](#what-is-dpi)
- [Networking Background](#networking-background)
- [Project Overview](#project-overview)
- [File Structure](#file-structure)
- [The Journey of a Packet (JavaScript Version)](#the-journey-of-a-packet-javascript-version)
- [The Processing Architecture](#the-processing-architecture)
- [Deep Dive: Each Component](#deep-dive-each-component)
- [How SNI Extraction Works](#how-sni-extraction-works)
- [How Blocking Works](#how-blocking-works)
- [Installation and Running](#installation-and-running)
- [Understanding the Output](#understanding-the-output)
- [Performance Notes](#performance-notes)
- [Extending the Project](#extending-the-project)

## 1. What is DPI?

Deep Packet Inspection (DPI) is a technology used to inspect network packets as they travel through a network.

Unlike normal firewalls that only inspect:

- Source IP
- Destination IP
- Ports
- Protocols

DPI examines the actual payload data inside packets.

### Real-World Uses

| Use Case | Example |
|---|---|
| ISP Traffic Management | Throttle BitTorrent |
| Enterprise Security | Block social media |
| Parental Control | Block adult websites |
| Threat Detection | Detect malware traffic |
| Analytics | Identify applications |

### What Our DPI Engine Does

```text
Input PCAP
     │
     ▼
┌───────────────────────┐
│      DPI Engine       │
│───────────────────────│
│ • Parse packets       │
│ • Track connections   │
│ • Extract SNI/Host    │
│ • Detect applications │
│ • Apply blocking      │
│ • Generate reports    │
└───────────────────────┘
     │
     ▼
Filtered Output PCAP
```

## 2. Networking Background

### Network Layers

Every network packet travels through multiple layers:

```text
┌──────────────────────────────────────────────┐
│ Layer 7 - Application │ HTTP, TLS, DNS       │
├──────────────────────────────────────────────┤
│ Layer 4 - Transport   │ TCP / UDP            │
├──────────────────────────────────────────────┤
│ Layer 3 - Network     │ IP                   │
├──────────────────────────────────────────────┤
│ Layer 2 - Data Link   │ Ethernet / MAC       │
└──────────────────────────────────────────────┘
```

### Packet Structure

A packet is made of nested headers:

```text
┌──────────────────────────────────────────────┐
│ Ethernet Header                              │
│ ┌──────────────────────────────────────────┐ │
│ │ IP Header                                │ │
│ │ ┌──────────────────────────────────────┐ │ │
│ │ │ TCP/UDP Header                       │ │ │
│ │ │ ┌──────────────────────────────────┐ │ │ │
│ │ │ │ Payload (TLS / HTTP / DNS)       │ │ │ │
│ │ │ └──────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

### The Five-Tuple

A connection is identified using five values:

| Field | Example |
|---|---|
| Source IP | 192.168.1.5 |
| Destination IP | 142.250.183.14 |
| Source Port | 54321 |
| Destination Port | 443 |
| Protocol | TCP |

This is called the Five-Tuple.

### What is SNI?

SNI (Server Name Indication) is part of the TLS handshake.

When visiting:

`https://www.youtube.com`

the browser sends:

```text
Client Hello
 └── SNI = "www.youtube.com"
```

before encryption starts.

This allows the DPI engine to identify websites even on HTTPS.

## 3. Project Overview

```text
Input → Processing → Output
┌──────────────┐
│ input.pcap   │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│ JavaScript DPI Engine │
├──────────────────────┤
│ Packet Parsing        │
│ Flow Tracking         │
│ TLS Inspection        │
│ Rule Filtering        │
│ Statistics            │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ output.pcap          │
└──────────────────────┘
```

### Key Features

- PCAP reading and writing
- Ethernet/IP/TCP/UDP parsing
- TLS SNI extraction
- HTTP Host extraction
- DNS query parsing
- Application identification
- Connection tracking
- Blocking by:
  - App
  - IP
  - Domain
- Statistics reporting

## 4. File Structure

```text
Packet_analyzer/
│
├── src/
│   ├── main.js
│   ├── dpiEngine.js
│   ├── pcapReader.js
│   ├── packetParser.js
│   ├── sniExtractor.js
│   ├── connectionTracker.js
│   ├── ruleManager.js
│   ├── loadBalancer.js
│   ├── fastPath.js
│   └── types.js
│
├── test_dpi.pcap
├── rules.txt
├── output.pcap
├── package.json
└── README.md
```

### File Mapping (C++ → JavaScript)

```text
C++                          →  JavaScript
─────────────────────────────────────────────────
include/types.h              →  src/types.js
include/pcap_reader.h        →  src/pcapReader.js
include/packet_parser.h      →  src/packetParser.js
include/sni_extractor.h      →  src/sniExtractor.js
include/connection_tracker.h →  src/connectionTracker.js
include/rule_manager.h       →  src/ruleManager.js
include/fast_path.h          →  src/fastPath.js
include/load_balancer.h      →  src/loadBalancer.js
include/dpi_engine.h         →  src/dpiEngine.js
src/main_dpi.cpp             →  src/main.js
```

## 5. The Journey of a Packet (JavaScript Version)

Let's trace one packet through the engine.

### Step 1: Read PCAP File

```js
const reader = new PcapReader(inputFile);
reader.open();
```

What happens:

- Open file using Node.js `fs`
- Read PCAP global header
- Validate PCAP format

#### PCAP File Structure

```text
┌────────────────────────────┐
│ Global Header              │
├────────────────────────────┤
│ Packet Header              │
│ Packet Data                │
├────────────────────────────┤
│ Packet Header              │
│ Packet Data                │
└────────────────────────────┘
```

### Step 2: Read Individual Packets

```js
const rawPacket = reader.readNextPacket();
```

Each packet contains:

```js
{
  header: {
    tsSec,
    tsUsec,
    inclLen,
    origLen
  },
  data: Buffer
}
```

### Step 3: Parse Protocol Headers

```js
const parsed = PacketParser.parse(rawPacket);
```

The parser extracts:

```js
{
  srcIP,
  dstIP,
  srcPort,
  dstPort,
  protocol,
  payload,
  payloadOffset
}
```

#### Ethernet Parsing

- Bytes 0-5 → Destination MAC
- Bytes 6-11 → Source MAC
- Bytes 12-13 → EtherType

#### IP Parsing

- Byte 0 → Version + Header Length
- Byte 9 → Protocol
- Bytes 12-15 → Source IP
- Bytes 16-19 → Destination IP

#### TCP Parsing

- Bytes 0-1 → Source Port
- Bytes 2-3 → Destination Port
- Bytes 4-7 → Sequence Number
- Bytes 8-11 → ACK Number

### Step 4: Create Flow Key

```js
const flowKey = `${srcIP}:${srcPort}-${dstIP}:${dstPort}-${protocol}`;
```

This uniquely identifies a connection.

### Step 5: Connection Tracking

```js
const flow = connectionTracker.getOrCreate(flowKey);
```

The engine stores:

```js
{
  appType,
  sni,
  blocked,
  packetCount,
  byteCount
}
```

### Step 6: Extract SNI / Host

For HTTPS traffic:

```js
const sni = SNIExtractor.extract(payload);
```

Possible result:

`"www.youtube.com"`

### Step 7: Detect Application

```js
if (sni.includes("youtube")) {
  flow.appType = "YOUTUBE";
}
```

### Step 8: Apply Blocking Rules

```js
if (ruleManager.isBlocked(flow)) {
  flow.blocked = true;
}
```

Rules can block:

- IPs
- Apps
- Domains

### Step 9: Forward or Drop

```js
if (!flow.blocked) {
  writer.write(packet);
}
```

Blocked packets are discarded.

## 6. The Processing Architecture

Although Node.js is single-threaded, this project simulates a high-performance DPI architecture using asynchronous processing.

```text
                ┌────────────────┐
                │ PCAP Reader    │
                └──────┬─────────┘
                       │
                       ▼
            ┌────────────────────┐
            │ Load Balancer      │
            └──────┬─────────────┘
                   │
     ┌─────────────┼─────────────┐
     ▼             ▼             ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ FastPath │ │ FastPath │ │ FastPath │
│ Queue 0  │ │ Queue 1  │ │ Queue 2  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │             │            │
     └─────────────┴────────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ Output Writer   │
          └─────────────────┘
```

### Why Use Queues?

Queues help:

- distribute work
- isolate processing stages
- simulate parallel pipelines
- avoid blocking operations

### Hash-Based Distribution

```js
const index = hash(flowKey) % numFastPaths;
```

This ensures packets from the same connection always go to the same Fast Path.

### Why This Matters

Without consistent hashing:

```text
Packet 1 → FP0
Packet 2 → FP2
Packet 3 → FP1
```

Flow tracking would break.

With hashing:

```text
Packet 1 → FP2
Packet 2 → FP2
Packet 3 → FP2
```

All packets stay together.

## 7. Deep Dive: Each Component

### `pcapReader.js`

Purpose:

- Read PCAP files
- Parse packet headers
- Return raw packet buffers

Main functions:

- `open()`
- `readNextPacket()`
- `close()`

### `packetParser.js`

Purpose:

- Parse Ethernet/IP/TCP/UDP headers

Main tasks:

- `parseEthernet()`
- `parseIPv4()`
- `parseTCP()`
- `parseUDP()`

### `sniExtractor.js`

Purpose:

- Extract TLS SNI
- Extract HTTP Host header
- Extract DNS query names

Main functions:

- `extractTLS()`
- `extractHTTPHost()`
- `extractDNS()`

### `connectionTracker.js`

Purpose:

- Track active flows

Stores:

- `Map<flowKey, Flow>`

### `ruleManager.js`

Purpose:

- Store blocking rules

Supports:

- `blockedIPs`
- `blockedApps`
- `blockedDomains`

### `loadBalancer.js`

Purpose:

- Distribute packets across processing queues

### `fastPath.js`

Purpose:

- Core packet processing logic

Responsibilities:

- flow lookup
- classification
- filtering
- statistics

### `dpiEngine.js`

Main orchestrator.

Controls:

- startup
- queues
- readers
- processors
- writers
- reports

## 8. How SNI Extraction Works

```text
Browser                         Server
   │                               │
   ├── Client Hello ─────────────► │
   │      SNI: youtube.com         │
   │                               │
   ◄── Server Hello ──────────────┤
   │                               │
   ═══ Encrypted Traffic ══════════
```

The SNI is visible before encryption.

### TLS Structure

- TLS Record Header
  - Content Type
  - Version
  - Length

- Handshake Header
  - Handshake Type
  - Length

- Extensions
  - SNI Extension
    - Hostname

### Simplified JavaScript Extraction

```js
function extractSNI(buffer) {
  if (buffer[0] !== 0x16) return null;

  const serverName = findSNIExtension(buffer);
  return serverName;
}
```

Example:

- `www.youtube.com`

gets mapped to:

- `AppType.YOUTUBE`

## 9. How Blocking Works

### Rule Types

| Rule | Example |
|---|---|
| IP | 192.168.1.50 |
| App | YOUTUBE |
| Domain | facebook |

### Decision Flow

```text
Packet Arrives
      │
      ▼
Blocked IP?
      │
     Yes ───► DROP
      │
      No
      ▼
Blocked App?
      │
     Yes ───► DROP
      │
      No
      ▼
Blocked Domain?
      │
     Yes ───► DROP
      │
      No
      ▼
FORWARD
```

### Flow-Based Blocking

Example:

```text
Packet 1 → SYN → FORWARD
Packet 2 → ACK → FORWARD
Packet 3 → TLS Client Hello
             SNI = youtube.com
             BLOCK FLOW
Packet 4 → DROP
Packet 5 → DROP
```

## 10. Installation and Running

### Requirements

Install:

- Node.js 18+

Check version:

```bash
node --version
```

### Running the Engine

#### Basic Usage

```bash
node src/main.js -i test_dpi.pcap -o output.pcap
```

#### With Rules

```bash
node src/main.js -i test_dpi.pcap -o output.pcap -r rules.txt
```

#### Custom Configuration

```bash
node src/main.js -i test_dpi.pcap -o output.pcap --lbs 4 --fps-per-lb 8
```

#### Using npm

```bash
npm test
```

### Output Files

| File | Purpose |
|---|---|
| `output.pcap` | Filtered packets |
| Console Report | Statistics |

Open output in Wireshark:

```bash
wireshark output.pcap
```

## 11. Understanding the Output

### Example Console Output

```text
================================
  Deep Packet Inspection Engine
  JavaScript Version
================================

[DPIEngine] Processing: test_dpi.pcap

[Reader] Finished reading 500 packets

╔════════════════════════════════════════════╗
║             DPI STATISTICS                ║
╠════════════════════════════════════════════╣
║ Total Packets: 500                        ║
║ TCP Packets:   350                        ║
║ UDP Packets:   150                        ║
║ Forwarded:     420                        ║
║ Dropped:       80                         ║
╚════════════════════════════════════════════╝
```

### Application Breakdown

- YOUTUBE — 120 packets
- FACEBOOK — 80 packets
- GOOGLE — 60 packets
- DNS — 40 packets
- UNKNOWN — 200 packets

### Domain Detection

Detected SNIs:

- youtube.com
- google.com
- facebook.com
- github.com

## 12. Performance Notes

### JavaScript vs C++

| Feature | C++ | JavaScript |
|---|---|---|
| Compilation | Required | Not required |
| Threads | Real OS Threads | Async/Event Loop |
| Performance | Faster | Simpler |
| Portability | Compiler dependent | Cross-platform |
| Dependencies | Compiler | Node.js |

### Important Difference

The JavaScript version:

- preserves the same architecture
- preserves the same DPI logic
- preserves the same filtering behavior

but uses:

- Asynchronous queues
- instead of native multi-threading

## 13. Extending the Project

### Add More App Signatures

```js
if (sni.includes("netflix")) {
  return "NETFLIX";
}
```

### Add QUIC Support

QUIC uses:

- UDP port 443

Future enhancement:

- parse QUIC Initial packets
- extract SNI from TLS-over-QUIC

### Add Live Dashboard

Possible additions:

- WebSocket server
- React frontend
- Real-time traffic graphs

### Add Persistent Rules

Store rules in:

- `rules.json`

and auto-load at startup.

## Summary

This project demonstrates:

- Network packet parsing
- Deep packet inspection
- TLS SNI extraction
- Stateful flow tracking
- Rule-based filtering
- Queue-based processing architecture
- High-performance packet analysis in Node.js

The most important insight:

Even encrypted HTTPS traffic exposes the destination hostname during the TLS handshake using SNI.

That is the foundation of modern DPI systems.

## Final Notes

To fully understand the project flow:

Start reading:

- `src/main.js`

then follow:

- `dpiEngine.js`
- `packetParser.js`
- `sniExtractor.js`
- `connectionTracker.js`
- `fastPath.js`
