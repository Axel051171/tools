# Changelog

All notable changes to HASHSCAN are documented here.

## [10.2] - 2025-02-02

### Added
- **`--pcredz <file>` Parameter** - Direct parsing of Pcredz/Responder output files
- Dedicated Pcredz parser with optimized format recognition
- Support for Pcredz PLAINTEXT markers (`# PLAINTEXT [protocol] user:pass`)
- Protocol credential detection (FTP, SMTP, POP3, IMAP, Telnet, LDAP, HTTP)
- HTTP Basic Auth extraction from Pcredz output
- NTLM SSP detection

### Changed
- Pcredz mode skips filesystem scanning for faster processing
- Improved NetNTLMv1 vs v2 detection by colon count heuristic

## [10.1] - 2025-02-02

### Added
- **Pcredz/Responder Compatibility** - Auto-detects network capture output files
- **NETWORK_AUTH Category** - Dedicated category for network authentication captures
- **Network Auth Patterns:**
  - MySQL Native Auth (`$mysqlna$`) - hashcat mode 11200
  - VNC Challenge (`$vnc$`) - hashcat mode 10000
  - PostgreSQL SCRAM (`SCRAM-SHA-256$`) - hashcat mode 28600
  - SNMPv3 (`$SNMPv3$`) - hashcat mode 25000
  - TACACS+ (`$tacacs-plus$`) - hashcat mode 16100
  - HTTP NTLM (Base64 Type 3 messages)
  - FTP/Telnet/SMTP/POP3/IMAP/LDAP clear text credentials
  - SNMP community strings
  - WiFi handshake/PMKID references
- **Direct File Scanning** - Can now scan individual files (not just directories)
- **Improved NetNTLMv1/v2 Detection** - Better parsing with challenge validation

### Changed
- Kerberos patterns now support longer tickets (up to 5000 chars)
- NetNTLM detection moved to CAT_NETWORK_AUTH category
- Binary size: 76 KB (Linux), 312 KB (Windows)

## [10.0] - 2025-02-01

### Added
- **User-Hash Correlation Map** - Automatically maps users to discovered hash types
- **Password Reuse Detection** - Detects credentials appearing multiple times
- **Hashcat Command Generator** - Ready-to-run hashcat commands with `--hashcat`
- **Entropy Scoring** - Flags low-entropy tokens as potential placeholders
- **Lateral Movement Hints** - Suggests pivot commands for NetNTLM hashes
- NetNTLMv1 detection (in addition to v2)

### Changed
- Improved table formatting in correlation output
- Binary size: 76 KB (Linux), 306 KB (Windows)

## [9.1] - 2025-02-01

### Added
- NetNTLMv1 pattern detection with hashcat mode 5500

### Fixed
- Forward declaration ordering for cross-platform compilation

## [9.0] - 2025-02-01

### Added
- **Archive Collector** - Extracts and scans ZIP/TAR/GZ/BZ2 using system tools
- **SQLite Collector** - Dumps databases via `sqlite3` or `strings` fallback
- **Git Collector** - Scans commit history for leaked secrets
- **Windows Artifact Discovery** - Reports SAM/SYSTEM/SECURITY presence
- `--no-collectors` flag to disable collectors
- Automatic tool detection (tar, unzip, sqlite3, git, strings)

### Changed
- Collectors use system tools instead of embedded libraries (zero dependencies)

## [8.0] - 2025-02-01

### Added
- **Credential Discovery Engine** with 70+ patterns
- Variable assignment detection for multiple formats:
  - ENV/Shell: `PASSWORD=value`
  - YAML: `password: value`
  - JSON: `"password": "value"`
  - XML: `<password>value</password>`
  - PHP: `$password = "value"`
- URL credential detection (`mysql://user:pass@host`)
- HTTP Basic Auth detection
- SQL INSERT/UPDATE credential extraction
- Connection string password extraction

### Changed
- Significantly expanded credential keyword list

## [7.0] - 2025-02-01

### Added
- **Cloud/API Token Detection** (25+ patterns):
  - AWS (AKIA..., Secret Key)
  - GitHub (ghp_, gho_, ghu_, ghr_)
  - GitLab (glpat-)
  - Slack (xoxb-, xoxp-)
  - Stripe (sk_live_, sk_test_)
  - OpenAI (sk-...)
  - And many more
- .NET MachineKey detection (validationKey, decryptionKey)
- Kubernetes secrets detection
- Base64-encoded secrets with context detection

## [6.0] - 2025-02-01

### Added
- **Binary Detection** - Skips binary files via nullbyte ratio
- **UTF-16 Support** - BOM detection and conversion
- **Deduplication Engine** - FNV-1a hash table for finding dedup
- **Context Lines** - Circular buffer with `--context` flag
- **Proper JSON Escaping** - Handles `"`, `\`, `\n`, `\r`, `\t`
- **Windows Owner Extraction** - Path-based heuristic
- **Symlink Loop Protection** - Inode tracking on Linux
- **Dynamic Memory** - No fixed findings limit
- **Timeout Support** - `--timeout` flag

### Added Patterns
- bcrypt_2x ($2x$)
- gost_yescrypt ($gy$)
- argon2d ($argon2d$)
- Django variants (pbkdf2$, bcrypt$, argon2$)
- SSHA256, SSHA512
- Spring Security ({bcrypt}, {scrypt})
- SCRAM-SHA-256, SCRAM-SHA-1
- DCC2/MSCache2
- krb5pa
- MediaWiki ($B$)

### Improved
- Smart false positive filtering (UUID, Git, Docker, checksums)

## [5.0] - 2025-01-31

### Added
- Initial C rewrite from Python
- Profile system (quick, htb, web, full)
- 30+ hash patterns
- /etc/shadow collector
- Cross-platform support (Linux + Windows)
- JSON output

---

## Version Numbering

- Major version: Significant new features or architecture changes
- Minor version: Bug fixes and small improvements

## Links

- Repository: https://github.com/Axel051171/tools
- Issues: https://github.com/Axel051171/tools/issues
