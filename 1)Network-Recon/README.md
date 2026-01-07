# Network Recon Lab

## Objective
Detect and analyze reconnaissance activity from a Linux VM targeting a Windows VM using Wireshark.

## Lab Setup
- Attacker VM: Linux
- Target VM: Windows
- Tools: Nmap, Wireshark
- Network: Host-only/Internal

## Steps
1. Run `nmap 192.168.56.102` from Linux VM.
2. Capture incoming packets on Windows VM using Wireshark.
3. Filter TCP SYN packets: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
4. Observe port scanning patterns.

## Observations
- Multiple SYN packets to different ports
- Short intervals between packets
- No full TCP handshake for closed ports
- Indicates reconnaissance (T1046 – Network Service Scanning)

## Evidence
- Screenshots: `screenshots/`
- Wireshark capture: `pcap_files/scan_capture.pcap`
- Notes: `notes/analysis.txt`

