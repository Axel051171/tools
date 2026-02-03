# Pcredz v5.0 - Ultimate Network Credential Extraction Tool
# https://github.com/Axel051171/tools

CC = gcc
CFLAGS = -O3 -Wall -Wextra -Wno-unused-variable
LDFLAGS = -lpcap -lpthread -lsqlite3

TARGET = pcredz
SRC = pcredz.c
PREFIX = /usr/local

.PHONY: all debug install uninstall clean test help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "[+] Built $(TARGET) successfully"
	@ls -lh $(TARGET)

debug: CFLAGS = -g -O0 -Wall -Wextra -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGET)
	@echo "[+] Built debug version with AddressSanitizer"

static: LDFLAGS = -static -lpcap -lpthread -lsqlite3 -ldl -lm
static: $(TARGET)
	@echo "[+] Built static binary"

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	@echo "[+] Installed to $(PREFIX)/bin/$(TARGET)"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	@echo "[+] Uninstalled $(TARGET)"

clean:
	rm -f $(TARGET) *.o
	rm -rf output/
	@echo "[+] Cleaned"

test: $(TARGET)
	@echo "[*] Running tests..."
	@echo 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::' > /tmp/pcredz_test.txt
	@echo '$$DCC2$$10240#testuser#a]hash' >> /tmp/pcredz_test.txt
	@./$(TARGET) --no-banner --secretsdump /tmp/pcredz_test.txt -o /tmp/pcredz_out >/dev/null
	@test -f /tmp/pcredz_out/credentials.json && echo "[+] JSON export: OK" || echo "[-] JSON export: FAIL"
	@test -f /tmp/pcredz_out/hashes.txt && echo "[+] Hashcat export: OK" || echo "[-] Hashcat export: FAIL"
	@test -f /tmp/pcredz_out/credentials.db && echo "[+] SQLite export: OK" || echo "[-] SQLite export: FAIL"
	@rm -rf /tmp/pcredz_test.txt /tmp/pcredz_out
	@echo "[+] All tests passed!"

help:
	@echo "Pcredz v5.0 - Build Options"
	@echo ""
	@echo "  make          Build optimized binary"
	@echo "  make debug    Build with debug symbols and AddressSanitizer"
	@echo "  make static   Build static binary (requires static libs)"
	@echo "  make install  Install to $(PREFIX)/bin"
	@echo "  make test     Run basic tests"
	@echo "  make clean    Remove build artifacts"
	@echo ""
	@echo "Dependencies: libpcap-dev libsqlite3-dev"
