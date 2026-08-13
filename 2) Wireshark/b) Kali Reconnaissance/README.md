# PCAP 2 — Kali → Windows Network Reconnaissance

## Wireshark Network Forensics Investigation

---

## 1. Overview

This project documents the analysis of a network capture generated in a controlled lab environment where a **Kali Linux VM performed network reconnaissance against a Windows VM**.

The objective was to understand how reconnaissance activity appears at the packet level and how a SOC analyst can identify, validate, and document that activity using Wireshark.

The investigation covered:

- ARP discovery
- ICMP connectivity testing
- TCP SYN reconnaissance
- TCP SYN/ACK responses
- TCP RST/ACK responses
- UDP reconnaissance
- ICMP Port Unreachable responses
- Nmap service discovery
- Nmap Scripting Engine (NSE)
- HTTP service enumeration
- Splunk service discovery
- TCP connection establishment
- TLS communication
- SMB/NetBIOS service negotiation
- Wireshark conversations and packet-level analysis

> **Lab purpose:** Defensive security training, packet analysis, SOC investigation practice, and network-forensics documentation.

---

# 2. Lab Environment

| System | IP Address | Role |
|---|---|---|
| Kali Linux VM | `192.168.20.11` | Reconnaissance / Testing Host |
| Windows VM | `192.168.20.10` | Target / Lab Host |
| Analysis Tool | Wireshark | Packet Capture & Investigation |

### Network Layout

```text
              Controlled Lab Network

        Kali Linux
        192.168.20.11
              |
              | ARP / ICMP
              | TCP Scan
              | UDP Scan
              | Service Enumeration
              |
              v
        Windows VM
        192.168.20.10
```

---

# 3. Investigation Objectives

The investigation was designed to answer the following questions:

1. Can the Kali host reach the Windows host?
2. What local network information can be observed through ARP?
3. What TCP ports are being probed?
4. Which TCP ports respond as open?
5. Which TCP ports respond as closed?
6. What happens when UDP ports are scanned?
7. Which services are exposed on the Windows machine?
8. Does Kali interact with any discovered services?
9. Can Nmap activity be identified directly from packet contents?
10. Can the reconnaissance sequence be supported with packet-level evidence?

---

# 4. Investigation Methodology

The investigation followed a realistic reconnaissance workflow:

```text
Connectivity
     |
     v
ARP / ICMP
     |
     v
TCP SYN Reconnaissance
     |
     v
Open / Closed Port Analysis
     |
     v
UDP Reconnaissance
     |
     v
Service Discovery
     |
     v
Nmap NSE
     |
     v
HTTP / TLS / SMB Analysis
```

Wireshark was used to validate the activity rather than relying solely on Nmap's terminal output.

---

# 5. Connectivity Testing — ICMP

The first step was to verify connectivity between Kali and Windows.

Kali:

```text
192.168.20.11
```

Windows:

```text
192.168.20.10
```

ICMP traffic was generated using `ping`.

### Wireshark Filter

```text
icmp
```

### Evidence

**Screenshot:** `PING_Req.png`

### What was observed

ICMP Echo Request and response traffic demonstrated that the two lab hosts were able to communicate.

### SOC Interpretation

ICMP ping is common for connectivity testing, troubleshooting, and host discovery.

A single ping is not inherently suspicious. When ICMP is followed by systematic port scanning, however, it can form part of a broader reconnaissance sequence.

---

# 6. ARP Analysis

ARP was examined to understand how the Kali host resolved the Windows host's IP address to its MAC address.

### Wireshark Filter

```text
arp
```

### Evidence

**Screenshot:** `ARP.png`

### What ARP Provides

ARP allows a host on a local IPv4 network to determine:

```text
IP Address -> MAC Address
```

### SOC Interpretation

ARP activity is normal on a local network. The capture showed ARP resolution, not evidence of ARP poisoning.

No conflicting IP/MAC mapping was identified during this portion of the investigation.

---

# 7. Nmap Reconnaissance

After connectivity was established, Kali performed Nmap reconnaissance against:

```text
192.168.20.10
```

The objective was to identify accessible TCP services and determine what applications were exposed.

### Evidence

- `NMAP Commands_1.png`
- `NMAP Commands_2.png`

These screenshots document the Nmap commands used during the lab.

---

# 8. TCP SYN Scan

A TCP SYN scan was analyzed at the packet level.

A SYN scan sends TCP SYN packets to destination ports to determine how the target responds.

### Wireshark Filter

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Evidence

**Screenshot:** `TCP SYN Scan Filtering.png`

### Packet Pattern

```text
Kali                         Windows

SYN ------------------------>
```

The Windows host then responds according to the state of the destination port.

### SOC Interpretation

A large number of TCP SYN probes targeting multiple ports from a single source is a strong reconnaissance pattern.

---

# 9. Identifying Open TCP Ports

A listening TCP service commonly responds to a SYN with a SYN/ACK.

### Wireshark Filter

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

### Evidence

**Screenshot:** `TCP SYN ACK Filtering.png`

### TCP Sequence

```text
Kali                         Windows

SYN ------------------------>

        <-------------------- SYN/ACK

ACK ------------------------>
```

### SOC Interpretation

A SYN/ACK response provides evidence that a TCP port is reachable and accepting connection attempts. During reconnaissance, this information can be used to identify potentially accessible services.

---

# 10. Closed TCP Ports

Ports that are not listening may respond with a TCP reset.

Typical sequence:

```text
Kali                         Windows

SYN ------------------------>

        <-------------------- RST/ACK
```

This behavior was observed during the scan.

### SOC Interpretation

The difference between:

```text
SYN -> SYN/ACK
```

and:

```text
SYN -> RST/ACK
```

helps an analyst understand the state of destination ports.

A large number of SYN probes targeting many ports from the same source is a recognizable reconnaissance pattern.

---

# 11. Wireshark Conversations — Port Scan

Wireshark's conversation statistics were used to examine the overall communication generated by the scan.

### Wireshark

```text
Statistics -> Conversations
```

### Evidence

**Screenshot:** `Conversations(Port Scan).png`

### Why This Is Useful

The Conversations view helps identify:

- Source and destination hosts
- Packet counts
- Bytes transferred
- Frequently contacted endpoints
- Dominant communication patterns

This provides a higher-level view before investigating individual packets.

---

# 12. UDP Reconnaissance

A UDP scan was also performed against the Windows host.

Unlike TCP, UDP does not use a TCP three-way handshake.

### Wireshark Filter

```text
udp && ip.src == 192.168.20.11 && ip.dst == 192.168.20.10
```

### Evidence

**Screenshot:** `UDP_Scan_Analysis.png`

### SOC Interpretation

UDP scanning is useful for discovering services that communicate over UDP. Because UDP is connectionless, determining whether a port is open can be less straightforward than TCP scanning.

---

# 13. UDP Closed Ports — ICMP Port Unreachable

During the UDP investigation, responses were observed in the form of:

```text
ICMP
Type: 3 — Destination Unreachable
Code: 3 — Port Unreachable
```

### Wireshark Filter

```text
icmp.type == 3 && icmp.code == 3
```

### Evidence

**Screenshot:** `UDP_Close Port.png`

### Example Packet Meaning

```text
Windows -> Kali

ICMP Destination Unreachable
Code 3 — Port Unreachable
```

The ICMP message contained information about the original UDP probe.

### SOC Interpretation

This response indicates that a UDP probe reached the Windows host and the destination UDP port was unavailable. A sequence of such responses can provide evidence of UDP reconnaissance.

---

# 14. Nmap Service Discovery

The Nmap scan identified multiple services exposed by the Windows VM.

Observed TCP services included:

```text
135/tcp
139/tcp
445/tcp
8000/tcp
8089/tcp
```

The most interesting discovery was the Splunk-related service:

```text
8000/tcp   open   http       Splunkd httpd
8089/tcp   open   ssl/http   Splunkd httpd
```

### Important Clarification

Port numbers do **not** permanently belong to applications.

For example:

```text
TCP 8000 != automatically Splunk
```

In this lab, the Windows VM already had Splunk installed and running from earlier lab work. Nmap identified the service through service detection, and the packet capture showed the corresponding service interaction.

The relationship was:

```text
Splunk installed
       |
       v
Splunk service running
       |
       v
Splunk listens on configured ports
       |
       v
Nmap scans Windows
       |
       v
Nmap identifies Splunk service
```

---

# 15. Nmap Scripting Engine — HTTP Enumeration

One of the strongest packet-level findings was an HTTP request generated by the Nmap Scripting Engine.

The captured request included:

```http
GET /nmaplowercheck1786409127 HTTP/1.1
Host: 192.168.20.10:8000
Connection: close
User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

### Evidence

**Screenshot:** `NMAP_Scripting_Engine_HTTP.png`

### Why This Is Important

The HTTP `User-Agent` explicitly identifies:

```text
Nmap Scripting Engine
```

Therefore, this is strong evidence that the Kali host was performing automated service enumeration against the HTTP service on port 8000.

### SOC Finding

> **Kali (`192.168.20.11`) performed application-layer service enumeration against the Windows host (`192.168.20.10`) using the Nmap Scripting Engine.**

This is stronger evidence than simply assuming that HTTP traffic came from Nmap.

---

# 16. HTTP Stream Analysis

The HTTP conversation was followed using Wireshark's HTTP stream functionality.

### Wireshark

```text
Right Click Packet
-> Follow
-> HTTP Stream
```

### Evidence

**Screenshot:** `HTTP_Stream_NMAP.png`

The stream confirmed communication with:

```text
192.168.20.10:8000
```

and showed the Nmap-generated HTTP request.

### SOC Value

Following the HTTP stream allows an analyst to correlate:

```text
Source IP
Destination IP
Destination Port
HTTP Method
URI
User-Agent
Connection behavior
```

into a single application-layer event.

---

# 17. Successful Open-Port Connection

A successful TCP connection to one of the discovered services was also examined.

### Evidence

**Screenshot:** `Open_Port_Connection.png`

The successful connection demonstrated that the discovered service was reachable from Kali.

A normal TCP establishment sequence is:

```text
SYN
 ↓
SYN/ACK
 ↓
ACK
```

This provides packet-level confirmation that communication with the service was successfully established.

---

# 18. Splunk Service — TCP/8089

The Windows VM also exposed a Splunk-related service on:

```text
TCP/8089
```

This service uses TLS.

The capture showed a successful connection and TLS handshake activity.

Typical sequence:

```text
TCP SYN
     |
     v
TCP SYN/ACK
     |
     v
TCP ACK
     |
     v
TLS Client Hello
     |
     v
TLS Server Hello
     |
     v
Encrypted Traffic
```

Some earlier connection attempts produced TCP resets, while a later connection successfully established TCP and proceeded into TLS negotiation.

A TCP retransmission observed later in the connection was **not automatically treated as malicious**. A retransmission means that a TCP segment was sent again because the expected acknowledgment was not received within the required time.

```text
TCP Retransmission != Attack
TCP Retransmission != TCP Reset
```

The retransmission was therefore interpreted in context rather than classified as suspicious by itself.

---

# 19. SMB / NetBIOS Analysis

The Windows host exposed:

```text
139/tcp
445/tcp
```

Both are associated with Windows networking and SMB.

The capture showed SMB protocol negotiation traffic.

### What SMB Negotiation Means

A protocol negotiation is essentially:

```text
Kali:
"What SMB protocol/features can you support?"

Windows:
"Here are the SMB versions/features I support."
```

This occurs before later SMB operations such as authentication or file-share access.

### Wireshark Filter

```text
smb || smb2 || nbns
```

### SOC Interpretation

The SMB negotiation demonstrates that Kali interacted with an exposed Windows SMB service.

However, the capture does **not** provide evidence of successful SMB authentication, file access, or compromise.

Those activities were therefore not claimed.

---

# 20. DNS Investigation

DNS traffic generated by Kali was also checked.

### Wireshark Filter

```text
dns && ip.src == 192.168.20.11
```

No meaningful DNS traffic was identified for Kali during this portion of the capture.

### Result

```text
DNS activity from Kali:
No significant traffic observed
```



---


# 22. SOC Analysis

From a SOC perspective, the most important behavior is the progression:

```text
1. Connectivity testing
        |
        v
2. ARP resolution
        |
        v
3. ICMP activity
        |
        v
4. Systematic TCP SYN scanning
        |
        v
5. Open/closed port identification
        |
        v
6. UDP reconnaissance
        |
        v
7. Service discovery
        |
        v
8. Nmap NSE HTTP enumeration
        |
        v
9. Interaction with discovered services
        |
        v
10. SMB/TLS service communication
```

The sequence is consistent with **network reconnaissance and service enumeration**.

The finding is supported by multiple independent indicators rather than a single packet.

```text
Nmap commands
      +
TCP SYN scan
      +
SYN/ACK responses
      +
RST responses
      +
UDP probes
      +
ICMP Port Unreachable
      +
Nmap NSE User-Agent
      +
HTTP stream
      =
Reconnaissance activity
```

---

# 23. MITRE ATT&CK Mapping

The activity observed in this lab is most closely associated with reconnaissance techniques.

## T1046 — Network Service Scanning

## T1018 — Remote System Discovery

---

# 25. Key Wireshark Filters

### ICMP

```text
icmp
```

### ARP

```text
arp
```

### TCP SYN

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### TCP SYN/ACK

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

### TCP Reset

```text
tcp.flags.reset == 1
```

### UDP

```text
udp
```

### UDP Port Unreachable

```text
icmp.type == 3 && icmp.code == 3
```

### HTTP

```text
http
```

### SMB

```text
smb || smb2 || nbns
```

### Port 8000

```text
tcp.port == 8000
```

### Splunk 8089

```text
tcp.port == 8089
```

### Retransmissions

```text
tcp.analysis.retransmission
```





