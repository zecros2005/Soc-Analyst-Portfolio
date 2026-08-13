# Windows Baseline Network Traffic Analysis — Wireshark

## Overview

This project documents the capture and analysis of **normal Windows network traffic** using Wireshark.

The goal was to create a realistic network baseline that resembles legitimate activity from a normal Windows user and operating system. The capture included web browsing, DNS resolution, connectivity checks, TCP connections, encrypted HTTPS/TLS and QUIC traffic, ARP, DHCP, NTP, and other common network protocols.

This baseline is the first part of a larger Wireshark network-forensics project. A separate PCAP was later created for Kali-to-Windows reconnaissance activity.

> **Project goal:** Build practical skills in packet capture, protocol analysis, network baselining, and evidence collection.

---

## Objectives

- Capture realistic Windows network activity.
- Learn Wireshark's statistics, endpoint, and conversation features.
- Establish a baseline of normal network behavior.
- Analyze common network protocols.
- Investigate TCP connection establishment and termination.
- Examine DNS queries and responses.
- Identify normal encrypted TLS/HTTPS and QUIC traffic.
- Analyze ARP and DHCP behavior.
- Use Wireshark display filters during investigation.
- Document findings using screenshots and evidence.
- Practice distinguishing normal activity from genuinely suspicious behavior.

---

## Lab Environment

| Component | Details |
|---|---|
| Capture Host | Windows VM |
| Capture Tool | Wireshark |
| Traffic Type | Normal / legitimate user and OS activity |
| PCAP | `01-Windows-Normal-Traffic.pcapng` |
| Investigation Type | Network Baseline / Protocol Analysis |

---

# 1. Traffic Capture Methodology

Wireshark was started on the Windows VM's active network interface. Traffic was intentionally generated to resemble normal user activity rather than malicious behavior.

The capture included both user-generated and operating-system-generated traffic.

## 1.1 Web Browsing

Several legitimate websites were visited during the capture, including sites such as:

- GitHub
- Microsoft
- Cloudflare
- Wikipedia
- YouTube

This generated realistic:

- DNS queries
- TCP connections
- TLS handshakes
- Encrypted application traffic
- QUIC traffic where supported

The purpose was to understand what ordinary modern web traffic looks like in a packet capture.

---

## 1.2 DNS Resolution

DNS activity was generated naturally through browsing and also using `nslookup` against selected domains.

Example:

```cmd
nslookup cloudflare.com
nslookup google.com
```

Wireshark filters used:

```text
dns
```

```text
dns.flags.response == 0
```

```text
dns.flags.response == 1 && dns.flags.rcode == 3
```

The investigation looked for queried domains, returned IP addresses, repeated requests, unusual domain names, and NXDOMAIN responses.

### Finding

DNS traffic was consistent with normal browsing and Windows background activity. No clearly anomalous DNS behavior was identified.

---

## 1.3 Connectivity Testing — ICMP

Connectivity to external hosts was tested using commands such as:

```cmd
ping google.com
```

This generated ICMP Echo Request and Echo Reply traffic.

Wireshark filter:

```text
icmp
```

More specific filter:

```text
icmp.type == 8 || icmp.type == 0
```

### Finding

The observed ICMP traffic was consistent with normal connectivity testing.

---

## 1.4 TCP Three-Way Handshake

Normal web activity generated many TCP sessions. A representative TCP handshake with a YouTube-associated endpoint was examined.

Expected sequence:

```text
SYN
  ↓
SYN/ACK
  ↓
ACK
```

Filters used:

```text
tcp.flags.syn == 1
```

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

TCP reset traffic was also checked:

```text
tcp.flags.reset == 1
```

### Finding

Normal TCP connection establishment was observed. No abnormal reset pattern was identified.

---

## 1.5 HTTP Analysis

HTTP traffic was investigated with:

```text
http
```

and:

```text
http.request
```

Only a small number of HTTP packets were present. The visible HTTP activity appeared to be associated with Microsoft/Windows-related traffic.

The APK download performed during the capture was **not attributed to cleartext HTTP**, so it was not presented as an HTTP file-transfer finding. The download may have used HTTPS or QUIC instead.

### Finding

Limited HTTP traffic was observed and no suspicious cleartext HTTP request or download was identified.

---

## 1.6 HTTPS / TLS Analysis

TLS traffic was investigated with:

```text
tls
```

and:

```text
tls.handshake
```

A TLS handshake associated with YouTube was identified.

The analysis examined visible metadata such as:

- Client Hello
- Server Hello
- TLS version
- SNI, where available
- Cipher negotiation
- ALPN
- Source and destination endpoints

### Important Visibility Limitation

TLS session keys were **not configured before the capture was created**, so encrypted application payloads could not be decrypted.

This is an important lesson in network forensics: without session keys, an analyst can often investigate connection metadata and behavior, but not the protected application content.

### Finding

The observed TLS traffic was consistent with normal encrypted web browsing. A YouTube TLS handshake was captured and documented.

---

## 1.7 QUIC Analysis

QUIC traffic was investigated using:

```text
quic
```

Modern browser traffic contained encrypted QUIC sessions.

Because the application data was protected, the investigation focused on the existence of the traffic and visible metadata rather than attempting to interpret encrypted payloads.

### Finding

QUIC traffic was consistent with modern browser activity. No malicious conclusion was drawn from encrypted traffic alone.

---

## 1.8 ARP Analysis

ARP traffic was investigated with:

```text
arp
```

The analysis checked:

- IP-to-MAC relationships
- ARP requests
- ARP replies
- Consistency of address mappings
- Possible conflicting mappings

### Finding

Normal ARP resolution was observed. No obvious ARP spoofing or poisoning pattern was identified.

---

## 1.9 UDP Analysis

UDP traffic was investigated using:

```text
udp
```

Common UDP-based traffic included:

- DNS
- QUIC
- NTP
- DHCP

The purpose was to understand the different forms of normal UDP communication present during routine Windows activity.

---

## 1.10 NTP / Time Synchronization

Windows time synchronization was triggered using:

```cmd
w32tm /resync
```

This was used to generate observable NTP-related traffic.

Typical filter:

```text
udp.port == 123
```

### Finding

The observed time-synchronization activity was consistent with normal Windows operation.

---

## 1.11 DHCP Lease Activity

DHCP traffic was investigated using:

```text
dhcp
```

The capture contained a DHCP sequence including:

```text
DHCP Discover
      ↓
DHCP Offer
      ↓
DHCP Request
      ↓
DHCP ACK
```

A DHCP Release was also present.

The DHCP packets were examined for information such as:

- Assigned IP address
- DHCP server
- Subnet mask
- Default gateway
- DNS servers

### Finding

The observed DHCP sequence was consistent with normal IP address allocation and lease management.

---

## 1.12 SMB / NetBIOS Check

SMB and NetBIOS traffic were checked using:

```text
smb || smb2 || nbns
```

Only limited activity was visible in the baseline capture.

### Finding

No significant SMB/NetBIOS anomaly was identified.

---

## 1.13 Additional Protocol Checks

The following protocols were also checked:

```text
ftp
ftp-data
smtp
telnet
pop
imap
ldap
```

No significant traffic was identified for these protocols during the capture.

This is useful evidence because documenting **what was absent** helps define the baseline as well.

---

# 2. Wireshark Statistics and Baseline Triage

Before investigating individual protocols, Wireshark's built-in statistics were used to understand the overall capture.

## Protocol Hierarchy

Navigation:

**Statistics → Protocol Hierarchy**

Used to identify which protocols were present and which ones represented the largest portions of the capture.

## IPv4 Endpoints

Navigation:

**Statistics → Endpoints → IPv4**

Used to identify active hosts and the most active IP addresses.

## IPv4 Conversations

Navigation:

**Statistics → Conversations → IPv4**

Used to identify who communicated with whom and compare packet/byte counts.

## TCP Conversations

Navigation:

**Statistics → Conversations → TCP**

The conversations were reviewed and sorted by bytes to identify dominant TCP sessions.

## I/O Graph

Navigation:

**Statistics → I/O Graph**

Used to visualize traffic volume over time and identify periods of increased activity.

---

# 3. Key Findings Summary

| Area | Finding | Assessment |
|---|---|---|
| DNS | Normal domain resolution | No clear anomaly |
| HTTP | Limited Microsoft/Windows-related HTTP | Normal |
| TLS | YouTube TLS handshake observed | Normal encrypted traffic |
| QUIC | Encrypted QUIC sessions observed | Normal modern web traffic |
| ARP | Normal IP/MAC resolution | No obvious spoofing |
| ICMP | Echo request/reply observed | Normal connectivity testing |
| TCP | Normal three-way handshake(s) | No unusual reset pattern |
| UDP | DNS/QUIC/NTP/DHCP traffic | Expected |
| DHCP | Discover/Offer/Request/ACK + Release | Normal |
| SMB/NetBIOS | Limited activity | No significant anomaly |
| FTP/SMTP/Telnet/POP/IMAP/LDAP | No significant activity | Not observed |

---

# 4. SOC Interpretation

This PCAP represents a **baseline**, not an incident.

The primary value of the capture is establishing what normal Windows behavior looks like before investigating more suspicious traffic.

A SOC analyst can use this baseline to understand:

- Normal DNS activity
- Normal TCP connection establishment
- Normal ICMP behavior
- Normal DHCP lease activity
- Normal ARP resolution
- Modern encrypted web traffic
- Typical browser-related TLS and QUIC traffic
- Which protocols are present or absent in the environment

This makes future malicious or suspicious PCAPs easier to triage because the analyst has a reference point for normal behavior.

---

# 5. MITRE ATT&CK Considerations

This capture is intentionally **benign baseline traffic**, so malicious MITRE ATT&CK techniques should not be forced onto normal protocol activity.

For example:

- DNS traffic is not automatically malicious.
- TLS traffic is not automatically Command and Control.
- ICMP is not automatically reconnaissance.
- A TCP connection is not automatically an attack.

MITRE ATT&CK mappings will be more appropriate in the later **Kali reconnaissance** and **public malware/attack PCAP** investigations, where adversarial behavior is supported by evidence.

This keeps the project evidence-driven and avoids overclaiming.

---

# 6. Evidence and Screenshot Strategy

Screenshots were captured only when they supported a specific observation.

Recommended organization:

```text
Part-1-Windows-Baseline/
├── PCAP/
│   └── 01-Windows-Normal-Traffic.pcapng
│
├── Screenshots/
│   ├── 01-protocol-hierarchy.png
│   ├── 02-ipv4-conversations.png
│   ├── 03-ipv4-endpoints.png
│   ├── 04-dns.png
│   ├── 05-tls handshake.png
│   ├── 06-icmp.png
│   ├── 07-tcp-handshake.png
│   ├── 08-ntp.png
│   ├── 09-dhcp.png
└── README.md
```

> Rename the examples above to match the actual screenshot filenames in the repository.

---

# 7. Useful Wireshark Filters

```text
dns
```

```text
dns.flags.response == 0
```

```text
http
```

```text
http.request
```

```text
tls
```

```text
tls.handshake
```

```text
quic
```

```text
arp
```

```text
icmp
```

```text
tcp.flags.syn == 1
```

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

```text
tcp.flags.reset == 1
```

```text
tcp.analysis.retransmission
```

```text
udp
```

```text
dhcp
```

```text
smb || smb2 || nbns
```

---

# 8. Lessons Learned

### Baselines matter

A normal PCAP may not contain an obvious security incident, but it provides the reference needed to recognize abnormal behavior later.

### Encryption limits visibility

TLS and QUIC protect application payloads. Without session keys, analysts may still use metadata, endpoints, timing, and handshake information, but they cannot simply read the encrypted contents.

### Don't force suspicious findings

A retransmission, RST, unusual-looking domain, or encrypted connection is not automatically malicious. Investigation should be based on context and multiple pieces of evidence.

### Start with statistics

Protocol Hierarchy, Endpoints, and Conversations provide a fast way to understand a PCAP before drilling into individual packets.

### Evidence should support conclusions

Screenshots are most useful when each one proves a specific technical observation. More screenshots do not automatically mean a better investigation.

---

# 9. Limitations

- TLS and QUIC application payloads were not decrypted.
- TLS key logging was not enabled before the capture.
- The environment was a controlled Windows VM rather than a production enterprise network.
- The traffic represents a limited capture window and cannot represent every possible Windows behavior.
- Absence of traffic in this PCAP does not prove that a protocol never occurs in the environment.
- The APK download was not attributed to cleartext HTTP based on the available packets.

---

# 10. Conclusion

This investigation produced a practical **Windows network baseline** using Wireshark.

The capture covered:

- DNS
- HTTP
- HTTPS/TLS
- QUIC
- ARP
- ICMP
- TCP
- UDP
- DHCP
- NTP
- SMB/NetBIOS
- Additional common protocol checks

The observed traffic was consistent with normal Windows operation, legitimate browsing, connectivity testing, network configuration, and encrypted modern web communications.

No clearly malicious behavior was identified in this baseline PCAP.

The resulting baseline will be used as a reference for the next phase of the project: investigating **Kali reconnaissance traffic and public malware/attack PCAPs** from a SOC/network-forensics perspective.

---
---

## Tools Used

- **Wireshark** — packet capture and network protocol analysis
- **Windows Command Prompt** — network and diagnostic commands
- **`ping`** — ICMP connectivity testing
- **`nslookup`** — DNS resolution testing
- **`w32tm`** — Windows time synchronization
- **Web browser** — realistic user web activity

---

## Project Focus

**SOC Analysis | Network Forensics | Wireshark | Traffic Baselining | Protocol Analysis | Evidence Documentation**
