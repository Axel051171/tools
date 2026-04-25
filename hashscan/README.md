# HASHSCAN v11.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-blue)]()
[![Language](https://img.shields.io/badge/language-C-orange)]()
[![No Dependencies](https://img.shields.io/badge/dependencies-none-green)]()

**Superman-Level Hash & Credential Scanner with Intelligence Features**

A fast, lightweight, cross-platform tool for discovering password hashes, credentials, and secrets during penetration testing and security assessments. **v11.0 adds full Linux/Windows credential collectors, pwdump/GPP/BitLocker/WPA-PMKID detection, and a hardened security-reviewed core.**

## Features

- 🔐 **60+ Hash Patterns** - Unix crypt, bcrypt, Argon2, NetNTLM, Kerberos, VNC, MySQL Native, pwdump, LM/NTLM, etc.
- 🔑 **70+ Credential Patterns** - ENV, YAML, JSON, XML, PHP, Python configs
- ☁️ **25+ Cloud Token Patterns** - AWS, GitHub, Slack, OpenAI, Stripe, etc.
- 🌐 **Network Auth Detection** - NetNTLMv1/v2, FTP, Telnet, SMTP, LDAP, SNMP, HTTP NTLM
- 🪟 **Windows Collectors** - Unattend.xml, GPP cpassword, PowerShell history, WiFi profiles, Credential Manager, .rdp/.kdbx
- 🐧 **Linux Collectors** - /etc/passwd+shadow, htpasswd, shell history, NetworkManager WiFi, opasswd, /proc/environ, crontabs
- 🧨 **Special Formats** - pwdump (user:RID:LM:NT:::), GPP cpassword decryption hint, BitLocker recovery keys, WPA PMKID
- 👥 **User Registry** - Correlates discovered hashes with /etc/passwd entries
- 📦 **Archive Scanning** - Automatically extracts and scans ZIP/TAR/GZ/BZ2
- 🗄️ **SQLite Scanning** - Dumps databases or falls back to strings
- 📜 **Git History** - Scans commit history for leaked secrets
- 🧠 **Intelligence Features** - User correlation, reuse detection, hashcat generator
- 🎯 **Pcredz Compatible** - Special handling for Pcredz/Responder output files
- 🛡️ **Hardened** - Shell-injection-safe, signal handlers, atexit cleanup, no fixed buffers
- ⚡ **Fast & Lightweight** - Single C file, zero external dependencies

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Axel051171/tools.git
cd tools/hashscan

# Build
make

# Run
./hashscan --profile htb
```

## Installation

### From Source

```bash
# Linux
gcc -O2 -o hashscan hashscan.c -lm

# Windows (cross-compile from Linux)
x86_64-w64-mingw32-gcc -O2 -o hashscan.exe hashscan.c -lm
```

### System-wide Installation

```bash
sudo make install
# Installs to /usr/local/bin/hashscan
```

## Usage

```bash
# Basic scan with HTB profile
./hashscan --profile htb

# Generate hashcat commands
./hashscan --profile htb --hashcat

# Show actual values (not redacted)
./hashscan --profile htb --show-values

# JSON output
./hashscan --profile htb --json -o report.json

# Verbose mode
./hashscan --profile htb -v
```

### Profiles

| Profile | Scans |
|---------|-------|
| `quick` | Web dirs + User home + Cloud configs |
| `htb` | quick + /etc + /var/backups + /var/log |
| `web` | Web directories only |
| `full` | Full filesystem (use with --timeout) |

### Options

```
Usage: hashscan [options] [paths...]

Options:
  --profile <p>     quick, htb, web, full
  --wide            Include low-confidence patterns
  --show-values     Show actual credential values
  --context <n>     Context lines (default: 1)
  --json            JSON output
  -o <file>         Output file
  -v, --verbose     Verbose mode
  -q, --quiet       Suppress banner and status output
  --max-files <n>   Max files to scan (default: 50000)
  --timeout <s>     Max runtime in seconds
  --no-collectors   Disable archive/sqlite/git collectors

Intelligence:
  --hashcat         Generate hashcat commands
  --no-correlation  Disable user-hash correlation

Pcredz Integration:
  --pcredz <file>   Parse Pcredz/Responder hashes.txt directly
```

### Linux Collectors (auto-run by `htb`/`full` profile)

| Source | What is collected |
|--------|-------------------|
| `/etc/passwd` + `/etc/shadow` | User registry + password hashes |
| `htpasswd` files | Apache/Nginx user:hash inline pairs |
| Shell history (`.bash_history`, `.zsh_history`, ...) | Passwords passed on command line |
| NetworkManager / wpa_supplicant | WiFi PSK plaintext extraction |
| `/etc/security/opasswd` | PAM password history |
| `/proc/*/environ` | Secrets in process environments |
| Crontabs (`/etc/cron*`, user crontabs) | Hardcoded credentials in scheduled jobs |

### Windows Collectors (auto-run when `_WIN32`)

| Source | What is collected |
|--------|-------------------|
| `Unattend.xml` / `sysprep.xml` | AdminPassword (cleartext or base64) |
| GPP `Groups.xml` / `Services.xml` / `ScheduledTasks.xml` | `cpassword` (publicly known AES key) |
| PowerShell history | `ConsoleHost_history.txt` credential leaks |
| WiFi profiles (`netsh wlan show profile`) | Stored PSKs |
| Credential Manager artifacts | DPAPI blob detection |
| `.rdp` / `.kdbx` / `KeePass*.config` | Stored RDP creds, KeePass DB markers |
| SAM / SYSTEM / NTDS.dit | Artifact detection (no parsing — flagged for offline use) |

## Intelligence Features

### User-Hash Correlation

Automatically maps users to their discovered hash types:

```
══════════════════════════════════════════════════════════════════════
  [USER-HASH CORRELATION]
══════════════════════════════════════════════════════════════════════

  User             Hash Types                     Sources
  ──────────────── ────────────────────────────── ───────────────────
  admin            bcrypt, sha512crypt            shadow, config.php
  www-data         MySQL5, phpass                 wp-config.php
```

### Password Reuse Detection

Detects when credentials appear multiple times:

```
══════════════════════════════════════════════════════════════════════
  [!] PASSWORD REUSE DETECTED
══════════════════════════════════════════════════════════════════════

  Value: $2y$10$abc...
    → Users: admin, backup
    → Files: config.php, .env.bak
```

### Hashcat Command Generator

```bash
./hashscan --profile htb --hashcat
```

```
  # sha512crypt (mode 1800)
  hashcat -m 1800 -a 0 hashes_sha512crypt.txt wordlist.txt

  # [PIVOT] netntlmv2 found - Lateral Movement Options:
  # evil-winrm -i <target> -u <user> -H <hash>
  # psexec.py <domain>/<user>@<target> -hashes :<hash>
```

## Pcredz / Responder Compatibility

HASHSCAN automatically detects and specially processes output from network credential capture tools:

**Auto-detected files:**
- `*hashes*`, `*credentials*`, `*pcredz*`, `*responder*`, `*ntlm*`, `*capture*`, `*loot*`

**Network Auth patterns detected:**

| Protocol | Pattern | Hashcat Mode |
|----------|---------|--------------|
| NetNTLMv1 | `user::domain:lm:nt:challenge` | 5500 |
| NetNTLMv2 | `user::domain:challenge:proof:blob` | 5600 |
| Kerberos TGS | `$krb5tgs$23$*user$realm$spn*$...` | 13100 |
| Kerberos AS-REP | `$krb5asrep$23$user@REALM:...` | 18200 |
| VNC | `$vnc$*challenge*response` | 10000 |
| MySQL Native | `$mysqlna$challenge$response` | 11200 |
| PostgreSQL SCRAM | `SCRAM-SHA-256$...` | 28600 |
| HTTP NTLM | `Authorization: NTLM <base64>` | - |
| FTP/Telnet/SMTP | Clear text captures | - |
| SNMP | Community strings | - |

**Direct Pcredz parsing (NEW in v10.2):**

```bash
# Direct parsing mode - fastest, optimized for Pcredz format
./hashscan --pcredz hashes.txt --hashcat --json -o report.json

# With full values
./hashscan --pcredz /path/to/Pcredz-Session-hashes.txt --show-values
```

**Filesystem scanning (auto-detects Pcredz files):**

```bash
# Scan Responder logs directory
./hashscan /usr/share/responder/logs/ --hashcat

# Scan loot folder
./hashscan ./loot/ --show-values
```

## Supported Patterns

<details>
<summary><b>Password Hashes (60+)</b></summary>

| Category | Patterns |
|----------|----------|
| Unix Crypt | sha512crypt, sha256crypt, md5crypt, bcrypt, yescrypt, scrypt |
| Argon2 | argon2i, argon2d, argon2id |
| PHP/CMS | phpass, Drupal7, MediaWiki |
| Django | pbkdf2_sha256, pbkdf2_sha1, django_bcrypt |
| Apache/LDAP | apr1, {SHA}, {SSHA}, {SSHA256}, {SSHA512} |
| Spring | {bcrypt}, {scrypt} |
| Database | MySQL5, PostgreSQL md5, MSSQL 2000/2005/2012 |
| Windows | LM, NTLM, NetNTLMv1, NetNTLMv2, DCC2/MSCache2, pwdump (`user:RID:LM:NT:::`) |
| Kerberos | krb5tgs, krb5asrep, krb5pa |
| Cisco | Type 8, Type 9 |
| Wireless | WPA PMKID (hashcat 22000), WPA-EAPOL hccapx markers |
| Disk Encryption | BitLocker recovery keys (48-digit) |
| Group Policy | GPP `cpassword` (AES-256, public key) |

</details>

<details>
<summary><b>Plaintext Credentials (70+)</b></summary>

- `password=`, `passwd=`, `pwd=`, `pass=`
- `db_password=`, `mysql_password=`, `postgres_password=`
- `api_key=`, `secret_key=`, `jwt_secret=`
- `smtp_password=`, `admin_password=`, `root_password=`
- URL embedded: `mysql://user:pass@host`
- HTTP Basic Auth: `Authorization: Basic`
- SQL dumps: `INSERT INTO users VALUES`
- JSON: `{"password": "value"}`
- XML: `<password>value</password>`

</details>

<details>
<summary><b>Cloud/API Tokens (25+)</b></summary>

| Provider | Pattern |
|----------|---------|
| AWS | `AKIA...`, Secret Key |
| GitHub | `ghp_`, `gho_`, `ghu_` |
| GitLab | `glpat-` |
| Slack | `xoxb-`, `xoxp-` |
| Stripe | `sk_live_`, `sk_test_` |
| OpenAI | `sk-` |
| Anthropic | `sk-ant-` |
| npm | `npm_` |
| PyPI | `pypi-` |

</details>

## Collectors

HASHSCAN automatically detects and uses system tools:

| Collector | Tools Used | Fallback |
|-----------|------------|----------|
| Archive | `unzip`, `tar` | - |
| SQLite | `sqlite3` | `strings` |
| Git | `git` | `.git/config` scan |

## Example Output

```
██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║███████║███████╗███████║███████╗██║     ███████║██╔██╗ ██║
██╔══██║██╔══██║╚════██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║  ██║███████║██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
Superman Hash Artifact Scanner v11.0
════════════════════════════════════════════════════════════════════

[*] Collectors: archive=yes sqlite=yes git=yes
[*] Mode: strict | Context: 1 | Max: 50000 files
[*] Profile: htb

══════════════════════════════════════════════════════════════════════
  [PASSWORD_HASH] - 5
══════════════════════════════════════════════════════════════════════

  [1] sha512crypt (high)
      File   : /etc/shadow:1
      Owner  : root
      Value  : $6$rounds...
      Hashcat: -m 1800

  [2] bcrypt_2y (high)
      File   : /var/www/html/config.php:42
      Owner  : www-data
      Value  : $2y$10$...
      Hashcat: -m 3200

══════════════════════════════════════════════════════════════════════
  SUMMARY: HIGH=52  MEDIUM=15  LOW=1
```

## HTB Workflow

```bash
# On target machine
./hashscan --profile htb -o loot.json

# Extract hashes for cracking
cat loot.json | jq -r '.findings[] | select(.category=="PASSWORD_HASH") | .value'

# Generate hashcat commands
./hashscan --profile htb --hashcat --show-values
```

## What's New in v11.0

- **9 Linux + 7 Windows credential collectors** (see tables above)
- **6 new pattern detections** in core scanner: pwdump, GPP cpassword, BitLocker recovery, WPA PMKID, htpasswd inline, LM/NTLM standalone
- **User Registry** ties discovered hashes back to `/etc/passwd` accounts
- **Hardened core**: shell-injection-safe (`shell_escape`/`path_is_safe`), signal handlers (SIGINT/SIGTERM/SIGHUP) with `atexit` temp cleanup, fixed `cc[5]` overflow, removed 20000-element stack array, plugged hashtable leaks
- **Coverage estimates**: Linux 70% → 92%, Windows 25% → 70%, pattern detection 80% → 95%, user correlation 50% → 85%
- `-q`/`--quiet` flag for scripting

> Remaining ~8% Windows gap (live SAM/NTDS.dit/DPAPI parsing) requires external libraries and conflicts with the zero-dependency design.

## Contributing

Pull requests welcome! Please ensure your code:
- Compiles without warnings (`-Wall`)
- Works on both Linux and Windows
- Maintains zero external dependencies

## License

MIT License - see [LICENSE](LICENSE)

## Disclaimer

**For authorized penetration testing and security assessments only.**

The author is not responsible for misuse of this tool. Always obtain proper authorization before scanning systems you do not own.

## Author

Axel - [@Axel051171](https://github.com/Axel051171)
