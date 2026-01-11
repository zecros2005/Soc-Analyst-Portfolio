# Network Reconnaissance Detection – SOC Lab

## Objective
Detect and analyze internal network reconnaissance activity by establishing a baseline of normal traffic and identifying a port-scanning attack using Wireshark.

## Lab Environment
- **Attacker VM:** Linux  
- **Target VM:** Windows  
- **Tools:** Wireshark, Nmap  
- **Network Setup:**
  - NAT adapter – baseline traffic
  - Host-only/Internal adapter – attack traffic

## Methodology

### Step 1: Baseline Traffic Analysis
- Captured normal browsing traffic on Windows VM (NAT interface)
- Identified legitimate traffic using:
  - DNS queries (google.com, youtube.com)
  - TLS Server Name Indication (SNI)
- Established normal network behavior baseline

### Step 2: Reconnaissance Simulation
- Performed SYN port scan from Linux VM:
nmap -sS -p 1-1000 <Windows-VM-IP>
- Captured traffic on Windows VM (Host-only interface)
- Applied Wireshark filter:
tcp.flags.syn == 1 && tcp.flags.ack == 0



## Analysis & Observations
- Multiple TCP SYN packets sent to sequential ports
- Same source IP targeting the Windows VM
- No TCP handshake completion
- No payload transmission
- Pattern consistent with reconnaissance activity

**Conclusion:**  
The observed traffic behavior indicates internal network service scanning.

## MITRE ATT&CK Mapping
- **T1046 – Network Service Scanning**

## Evidence
- **PCAP files:** `pcap_files/`
  - Baseline traffic capture
  - Reconnaissance scan capture
- **Screenshots:** `screenshots/`
  - DNS traffic identification
  - TLS SNI evidence
  - SYN scan packet evidence
- **Analysis Notes:** `Analysis Text/`

## Key Takeaways
- Network-based detection can identify reconnaissance before host logs generate alerts
- SYN-only scanning is a common pre-attack technique
- Establishing a baseline is essential for anomaly detection
- Demonstrates SOC skills: traffic capture, filtering, analysis, and MITRE mapping
