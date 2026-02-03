# Pcredz v5.0

**Ultimate Network Credential Extraction Tool**

High-performance credential sniffer written in C. Extracts credentials from network traffic with full TCP reassembly, WPA handshake capture, and 30+ protocol support.

![Version](https://img.shields.io/badge/version-5.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

## Features

- **60x faster** than Python version (~3-5M packets/second)
- **68KB standalone binary** - minimal dependencies
- **Full TCP reassembly** with ISN tracking and out-of-order handling
- **WPA/WPA2 handshake capture** (hashcat mode 22000)
- **30 protocols** supported
- **6 output formats**: JSON, CSV, Hashcat, HASHSCAN, SQLite, HTML
- **Live capture** with BPF filter support
- **Import** from Responder and Secretsdump

## Supported Protocols

| Category | Protocols |
|----------|-----------|
| **Network** | FTP, Telnet, SMTP, POP3, IMAP, HTTP (Basic/Digest/Form), LDAP, SNMP |
| **Database** | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis |
| **IoT/Remote** | MQTT, VNC, RDP |
| **Windows** | SMB1/2/3, NTLMv1/v2, Kerberos (AS-REP, TGS-REP) |
| **Enterprise** | RADIUS (MS-CHAPv2), SIP (Digest), SOCKS5 |
| **Wireless** | WPA/WPA2 EAPOL 4-way Handshakes |
| **Other** | TLS (SNI extraction), SSH (Banner) |

## Installation

### Dependencies

```bash
# Debian/Ubuntu
apt-get install -y libpcap-dev libsqlite3-dev

# RHEL/CentOS
yum install -y libpcap-devel sqlite-devel

# Arch
pacman -S libpcap sqlite
```

### Build

```bash
git clone https://github.com/Axel051171/tools.git
cd tools/pcredz
make
```

Or manually:

```bash
gcc -O3 -o pcredz pcredz.c -lpcap -lpthread -lsqlite3
```

### Install (optional)

```bash
sudo make install
# Installs to /usr/local/bin/pcredz
```

## Usage

### Basic Usage

```bash
# Analyze PCAP file
./pcredz -f capture.pcap -o ./results

# Live capture (requires root)
sudo ./pcredz -i eth0 -o ./live_results

# With BPF filter
sudo ./pcredz -i eth0 --filter 'port 445 or port 88' -o ./filtered

# Capture with timeout
sudo ./pcredz -i eth0 --timeout 60 -o ./timed
```

### WiFi / WPA Handshakes

```bash
# From aircrack-ng capture
./pcredz -f wifi_capture.cap -o ./wifi_results

# The tool auto-detects radiotap/802.11 frames
# Extracts EAPOL 4-way handshakes in hashcat 22000 format
```

### Import External Sources

```bash
# Import Responder logs
./pcredz --responder /opt/Responder/logs/ -o ./responder_creds

# Import secretsdump output
./pcredz --secretsdump domain_dump.txt -o ./ad_creds

# Combine multiple sources
./pcredz -f capture.pcap --responder ./logs --secretsdump dump.txt -o ./combined
```

### Options

```
Input:
  -f, --file FILE       PCAP/PCAP-NG file to analyze
  -i, --interface IF    Network interface for live capture
  --responder DIR       Import Responder log directory
  --secretsdump FILE    Import secretsdump output file

Output:
  -o, --output DIR      Output directory (default: ./output)
  --json                Export JSON (default: enabled)
  --csv                 Export CSV (default: enabled)
  --hashcat             Export hashcat format (default: enabled)
  --hashscan            Export HASHSCAN format (default: enabled)
  --sqlite              Export SQLite database (default: enabled)

Options:
  --filter EXPR         BPF filter expression
  --timeout SEC         Capture timeout in seconds
  -v, --verbose         Show credentials as found
  --no-banner           Suppress startup banner
  -h, --help            Show help
```

## Output Formats

### JSON (`credentials.json`)
```json
{
  "meta": {"tool": "pcredz", "version": "5.0.0", "total": 42},
  "credentials": [
    {"id": 1, "proto": "ntlm", "user": "admin", "hash": "admin::CORP:...", "mode": 5600}
  ]
}
```

### Hashcat (`hashes.txt`)
Direct input for hashcat - one hash per line, ready to crack.

### SQLite (`credentials.db`)
Indexed database with full metadata for analysis.

## Hashcat Integration

```bash
# NetNTLMv1
hashcat -m 5500 hashes.txt rockyou.txt

# NetNTLMv2
hashcat -m 5600 hashes.txt rockyou.txt

# WPA/WPA2 (PMKID/EAPOL)
hashcat -m 22000 hashes.txt rockyou.txt

# Kerberoasting (TGS-REP)
hashcat -m 13100 hashes.txt rockyou.txt

# AS-REP Roasting
hashcat -m 18200 hashes.txt rockyou.txt

# SIP Digest
hashcat -m 11400 hashes.txt rockyou.txt

# MySQL Native Auth
hashcat -m 11200 hashes.txt rockyou.txt

# MSSQL
hashcat -m 1433 hashes.txt rockyou.txt

# Domain Cached Credentials 2 (DCC2)
hashcat -m 2100 hashes.txt rockyou.txt

# NT Hash (from SAM/NTDS)
hashcat -m 1000 hashes.txt rockyou.txt
```

## Performance

| Metric | Python Original | C v5.0 |
|--------|----------------|--------|
| Speed | ~50k pkt/s | ~3-5M pkt/s |
| Memory (1GB PCAP) | 500MB+ | <100MB |
| Binary Size | Python + deps | 68KB |
| Protocols | 15 | 30 |
| TCP Reassembly | Basic | Full (ISN, OOO) |
| WPA Support | No | Yes |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PCAP Input                              │
│              (file / live / radiotap)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Packet Processor                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │Ethernet │→ │  VLAN   │→ │  IPv4/6 │→ │ TCP/UDP │        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 TCP Stream Reassembly                        │
│  • ISN tracking (client/server)                              │
│  • Sequence number validation                                │
│  • Out-of-order segment queuing                              │
│  • Retransmit detection                                      │
│  • 128KB buffers per direction                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                  Protocol Parsers (30)                       │
│  FTP│SMTP│POP3│IMAP│HTTP│LDAP│SNMP│MySQL│MSSQL│...         │
│  SMB│NTLM│Kerberos│RADIUS│SIP│SOCKS│WPA│...                │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              Credential Store (Hash Table)                   │
│  • Deduplication via FNV-1a                                  │
│  • Thread-safe with mutex                                    │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Export Formats                            │
│        JSON │ CSV │ Hashcat │ HASHSCAN │ SQLite             │
└─────────────────────────────────────────────────────────────┘
```

## Examples

### Pentest Workflow

```bash
# 1. Capture traffic during engagement
sudo ./pcredz -i eth0 --filter 'not port 22' --timeout 3600 -o ./engagement

# 2. Analyze existing captures
./pcredz -f responder_capture.pcap -o ./analysis

# 3. Import all credential sources
./pcredz \
  -f network.pcap \
  --responder /opt/Responder/logs \
  --secretsdump ntds_dump.txt \
  -o ./all_creds

# 4. Crack with hashcat
hashcat -m 5600 ./all_creds/hashes.txt /usr/share/wordlists/rockyou.txt
```

### WiFi Assessment

```bash
# Capture with aircrack-ng
airodump-ng -w capture --output-format pcap wlan0mon

# Extract handshakes
./pcredz -f capture-01.cap -o ./wifi

# Crack WPA
hashcat -m 22000 ./wifi/hashes.txt rockyou.txt
```

## Credits

- Original Pcredz: [Laurent Gaffie](https://github.com/lgandx/PCredz)
- C Rewrite: Axel

## License

MIT License - See LICENSE file

## Disclaimer

This tool is intended for authorized security testing and research only. Users are responsible for compliance with applicable laws. The authors assume no liability for misuse.
