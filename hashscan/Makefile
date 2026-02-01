# ============================================================================
# HASHSCAN v10.0 - Makefile
# ============================================================================

CC       = gcc
MINGW    = x86_64-w64-mingw32-gcc
CFLAGS   = -O2 -Wall -Wextra
LDFLAGS  = -lm
SRC      = hashscan.c
BIN      = hashscan
BIN_WIN  = hashscan.exe
PREFIX   = /usr/local

# ============================================================================
# Targets
# ============================================================================

.PHONY: all linux windows clean install uninstall test help

all: linux windows
	@echo ""
	@echo "Build complete:"
	@ls -lh $(BIN) $(BIN_WIN) 2>/dev/null || ls -lh $(BIN)
	@echo ""
	@echo "Run './$(BIN) --help' for usage"

linux: $(BIN)

windows: $(BIN_WIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[+] Built: $@ ($(shell stat -c%s $@ 2>/dev/null || stat -f%z $@) bytes)"

$(BIN_WIN): $(SRC)
	@if command -v $(MINGW) >/dev/null 2>&1; then \
		$(MINGW) $(CFLAGS) -o $@ $< $(LDFLAGS); \
		echo "[+] Built: $@ ($(shell stat -c%s $@ 2>/dev/null || echo '?') bytes)"; \
	else \
		echo "[-] mingw-w64 not installed, skipping Windows build"; \
		echo "    Install with: apt install mingw-w64"; \
	fi

# ============================================================================
# Installation
# ============================================================================

install: $(BIN)
	@echo "[*] Installing to $(PREFIX)/bin/$(BIN)"
	@mkdir -p $(PREFIX)/bin
	@cp $(BIN) $(PREFIX)/bin/$(BIN)
	@chmod 755 $(PREFIX)/bin/$(BIN)
	@echo "[+] Installed successfully"
	@echo "    Run 'hashscan --help' to get started"

uninstall:
	@echo "[*] Removing $(PREFIX)/bin/$(BIN)"
	@rm -f $(PREFIX)/bin/$(BIN)
	@echo "[+] Uninstalled"

# ============================================================================
# Testing
# ============================================================================

test: $(BIN)
	@echo "[*] Running quick test..."
	@./$(BIN) --profile quick --max-files 100 --timeout 5

test-full: $(BIN)
	@echo "[*] Running full test..."
	@./$(BIN) --profile htb --hashcat --max-files 500 --timeout 30

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -f $(BIN) $(BIN_WIN)
	@echo "[+] Cleaned build artifacts"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "HASHSCAN Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build Linux and Windows binaries (default)"
	@echo "  linux     - Build Linux binary only"
	@echo "  windows   - Build Windows binary (requires mingw-w64)"
	@echo "  install   - Install to $(PREFIX)/bin"
	@echo "  uninstall - Remove from $(PREFIX)/bin"
	@echo "  test      - Run quick test"
	@echo "  test-full - Run comprehensive test"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)"
	@echo "  CC=$(CC)"
	@echo "  MINGW=$(MINGW)"
