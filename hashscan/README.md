# HASHSCAN v10.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-blue)]()
[![Language](https://img.shields.io/badge/language-C-orange)]()
[![No Dependencies](https://img.shields.io/badge/dependencies-none-green)]()

**Superman-Level Hash & Credential Scanner with Intelligence Features**

A fast, lightweight, cross-platform tool for discovering password hashes, credentials, and secrets during penetration testing and security assessments.

## Features

- 🔐 **45+ Hash Patterns** - Unix crypt, bcrypt, Argon2, NetNTLM, Kerberos, etc.
- 🔑 **70+ Credential Patterns** - ENV, YAML, JSON, XML, PHP, Python configs
- ☁️ **25+ Cloud Token Patterns** - AWS, GitHub, Slack, OpenAI, Stripe, etc.
- 📦 **Archive Scanning** - Automatically extracts and scans ZIP/TAR/GZ
- 🗄️ **SQLite Scanning** - Dumps databases or falls back to strings
- 📜 **Git History** - Scans commit history for leaked secrets
- 🧠 **Intelligence Features** - User correlation, reuse detection, hashcat generator
- ⚡ **Fast & Lightweight** - 76KB binary, zero dependencies

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
  --wide            Include low-confidence hex patterns
  --show-values     Show actual credential values
  --context <n>     Context lines (default: 1)
  --json            JSON output
  -o <file>         Output file
  -v, --verbose     Verbose mode
  --max-files <n>   Max files to scan (default: 50000)
  --timeout <s>     Max runtime in seconds
  --no-collectors   Disable archive/sqlite/git collectors

Intelligence:
  --hashcat         Generate hashcat commands
  --no-correlation  Disable user-hash correlation
```

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

## Supported Patterns

<details>
<summary><b>Password Hashes (45+)</b></summary>

| Category | Patterns |
|----------|----------|
| Unix Crypt | sha512crypt, sha256crypt, md5crypt, bcrypt, yescrypt, scrypt |
| Argon2 | argon2i, argon2d, argon2id |
| PHP/CMS | phpass, Drupal7, MediaWiki |
| Django | pbkdf2_sha256, pbkdf2_sha1, django_bcrypt |
| Apache/LDAP | apr1, {SHA}, {SSHA}, {SSHA256}, {SSHA512} |
| Spring | {bcrypt}, {scrypt} |
| Database | MySQL5, PostgreSQL md5, MSSQL 2000/2005/2012 |
| Windows | NetNTLMv1, NetNTLMv2, DCC2/MSCache2 |
| Kerberos | krb5tgs, krb5asrep, krb5pa |
| Cisco | Type 8, Type 9 |

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
Superman Hash Artifact Scanner v10.0
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

## Binary Size

| Platform | Size |
|----------|------|
| Linux x64 | 76 KB |
| Windows x64 | 306 KB |

## Contributing

Pull requests welcome! Please ensure your code:
- Compiles without warnings (`-Wall`)
- Works on both Linux and Windows
- Maintains zero external dependencies


## Disclaimer

**For authorized penetration testing and security assessments only.**

The author is not responsible for misuse of this tool. Always obtain proper authorization before scanning systems you do not own.

## Author

Axel - [@Axel051171](https://github.com/Axel051171)
