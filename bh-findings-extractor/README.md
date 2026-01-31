# 🩸 BH Findings Extractor

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-5.0-green.svg)](https://github.com/Axel051171/tools)

**Offline Security Analysis Tool for BloodHound/SharpHound JSON Data**

Extract, analyze, and report Active Directory security findings without needing BloodHound's Neo4j database.

![Risk Score](https://img.shields.io/badge/dynamic/json?color=red&label=Sample%20Risk&query=HIGH&url=https://example.com)

---

## 🎯 Features

### Security Analysis
- **27 Security Checks** including RBCD, Shadow Admins, GPO Abuse, DCSync, Kerberoasting
- **Attack Path Analysis** with NetworkX graph algorithms
- **Risk Scoring** (0-1000) with severity classification
- **Legacy + CE Format** support for all BloodHound versions

### Workflow
- **Multiple Inputs** - Combine data from different scans
- **Incremental Scanning** - `--append` mode with smart caching
- **Diff Reports** - Compare scans to track remediation progress
- **Task Filtering** - Run only specific security checks

### Output
- **Severity-sorted folders** (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **HTML Reports** - Professional Bootstrap 5 reports for management
- **CSV/JSON Export** - For integration with other tools
- **Deterministic Output** - Reproducible results for diffing

---

## 📦 Installation

```bash
# Optional: Install NetworkX for attack path analysis
pip install networkx
```

**Requirements:** Python 3.8+

---

## 🚀 Quick Start

```bash
# Basic analysis
python bh_findings_extractor.py -i ./bloodhound_data

# With HTML report
python bh_findings_extractor.py -i ./data -o ./report --html

# Compare two scans
python bh_findings_extractor.py --diff ./scan_january ./scan_february
```

---

## 📖 Usage

### Basic Commands

```bash
# Single directory
python bh_findings_extractor.py -i ./bloodhound_data

# Multiple sources (merge)
python bh_findings_extractor.py -i ./scan1 -i ./scan2 -o ./report

# Incremental scan (use cache)
python bh_findings_extractor.py -i ./new_scan -o ./existing_report --append

# Force reload (ignore cache)
python bh_findings_extractor.py -i ./data -o ./report --force
```

### Advanced Options

```bash
# Generate HTML report
python bh_findings_extractor.py -i ./data --html

# Compare two reports (diff)
python bh_findings_extractor.py --diff ./old_report ./new_report

# Run specific tasks only
python bh_findings_extractor.py -i ./data --tasks "dcsync,rbcd,shadow_admins"

# Quiet mode (for scripts)
python bh_findings_extractor.py -i ./data -q
# Output: RISK: 720/1000 (HIGH)

# Verbose mode (debugging)
python bh_findings_extractor.py -i ./data -v
```

### All Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Input directory (can be used multiple times) |
| `-o, --output` | Output directory |
| `--append` | Add to existing report (use cache) |
| `--force` | Ignore cache, reload everything |
| `--diff OLD NEW` | Compare two report directories |
| `--html` | Generate HTML report |
| `--tasks` | Run only specific tasks (comma-separated) |
| `-q, --quiet` | Minimal output (for scripting) |
| `-v, --verbose` | Verbose output (for debugging) |

---

## 🔍 Security Findings

### CRITICAL
| Finding | Description |
|---------|-------------|
| DCSync Rights | DS-Replication permissions (GetChanges/GetChangesAll) |
| RBCD | Resource-Based Constrained Delegation abuse |
| Unconstrained Delegation | Kerberos delegation to any service |
| Shadow Admins | GenericAll on DA group without membership |
| Domain/Enterprise Admins | High-privilege group members |
| Attack Paths | Shortest paths to Domain Admins |

### HIGH
| Finding | Description |
|---------|-------------|
| Kerberoastable | Users with SPNs (offline password cracking) |
| AS-REP Roastable | Pre-authentication disabled |
| Dangerous ACLs | GenericAll, WriteDACL, WriteOwner, etc. |
| GPO Abuse | Write permissions on Group Policy Objects |
| Constrained Delegation | S4U2Proxy/S4U2Self abuse potential |
| Nested Groups | Indirect DA membership via group chains |
| Pre-2000 Group | Overprivileged compatibility group |
| AdminCount=1 | Protected users (SDProp) |

### MEDIUM
| Finding | Description |
|---------|-------------|
| Password Never Expires | Weak password policy |
| Never Changed Password | Potentially stale credentials |
| No LAPS | Computers without local admin password solution |
| Stale Computers | Inactive >90 days |
| Unsupported OS | End-of-life operating systems |

### LOW/INFO
| Finding | Description |
|---------|-------------|
| Enabled/Disabled Users | Account status overview |
| Inactive Users | Not logged in >180 days |
| SID History | Potential privilege persistence |

---

## 📁 Output Structure

```
report/
├── CRITICAL/
│   ├── dcsync_rights.txt
│   ├── rbcd_delegation.txt
│   ├── shadow_admins.txt
│   ├── domain_admins.txt
│   └── attack_paths.txt
├── HIGH/
│   ├── kerberoastable_users.txt
│   ├── asrep_roastable_users.txt
│   ├── dangerous_acls.txt
│   ├── gpo_abusable.txt
│   └── nested_group_chains.txt
├── MEDIUM/
│   ├── password_never_expires.txt
│   ├── stale_computers.txt
│   └── no_laps.txt
├── INFO/
│   ├── enabled_users.txt
│   └── disabled_users.txt
├── INDEX.txt              # Table of contents
├── SUMMARY_REPORT.txt     # Executive summary
├── REPORT.html            # HTML report (with --html)
├── DIFF_REPORT.txt        # Diff report (with --diff)
├── findings_critical.csv  # CSV export
├── findings_all.json      # JSON export
└── _cache.json            # Internal cache for --append
```

---

## 🔄 Diff Mode

Track remediation progress by comparing scans:

```bash
python bh_findings_extractor.py --diff ./january_scan ./february_scan
```

**Output:**
```
============================================================
BH FINDINGS EXTRACTOR v5.0 - DIFF REPORT
============================================================

Findings Alt: 45
Findings Neu: 38

NEUE FINDINGS (2):
----------------------------------------
  [CRITICAL] NEWSVC → DC01 (rbcd)
  [HIGH] BACKDOOR_USER → Domain Admins (memberof)

BEHOBENE FINDINGS (9):
----------------------------------------
  [CRITICAL] SVCACCOUNT → Domain (dcsync)
  [HIGH] OLDSVC → (kerberoastable)
  ...
```

---

## 🎨 HTML Report

Generate professional reports for management:

```bash
python bh_findings_extractor.py -i ./data --html
```

**Features:**
- Bootstrap 5 responsive design
- Risk score visualization
- Findings overview by priority
- Critical findings detail section
- Domain statistics dashboard

---

## 🧪 Testing

```bash
# Run golden tests
cd tests
python test_golden.py
```

---

## 📋 Data Sources

This tool works with JSON exports from:
- **SharpHound** (BloodHound data collector)
- **AzureHound** (Azure AD collector)
- **BloodHound CE** (Community Edition exports)

Simply point to a directory containing the JSON files.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research only. Always obtain proper authorization before testing systems you do not own.

---

## 🙏 Acknowledgments

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - The original AD attack path analysis tool
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) - BloodHound data collector

---

**Made with ❤️ for the InfoSec community**
