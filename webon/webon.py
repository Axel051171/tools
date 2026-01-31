#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webon.py – HTTP + FTP Server für Pentesting/HTB

Features:
- HTTP-Server (Default Port 80)
- FTP-Server (Default Port 21) mit --ftp Flag
- Upload standardmäßig aktiviert (deaktivieren mit -n)
- Optionaler Port-Override mit -p <port>
- Modus 1: -f <file>   → Nur diese Datei bereitstellen
- Modus 2: -o <dir>    → Nur dieser Ordner (optional Listing)
- Detaillierte Logs mit Zeitstempel
- Konfigurierbare Upload-Größe

Sicherheit:
- Path Traversal Schutz via Path.relative_to()
- Hidden-Files (.*) standardmäßig blockiert, optional --allow-hidden
- Upload-Größenlimit konfigurierbar
- Sichere Dateinamen bei Uploads
- FTP Anonymous oder mit Authentifizierung
"""

from __future__ import annotations

import argparse
import http.server
import mimetypes
import os
import socketserver
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from typing import Optional, List, Any, Type

# =============================================================================
# Konstanten
# =============================================================================

# ANSI Colors (schlicht)
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
DIM = "\033[2m"
RESET = "\033[0m"

# Defaults
DEFAULT_HTTP_PORT = 80
DEFAULT_FTP_PORT = 21
DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
DEFAULT_BIND = "0.0.0.0"
CHUNK_SIZE = 64 * 1024  # 64 KB
FTP_PASSIVE_PORTS = range(60000, 60100)


# =============================================================================
# Helper Functions
# =============================================================================

def get_timestamp() -> str:
    """Gibt den aktuellen Timestamp zurück."""
    return datetime.now().strftime("%H:%M:%S")


def format_size(size: int) -> str:
    """Formatiert Dateigröße human-readable."""
    size_float = float(size)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_float < 1024.0:
            return f"{size_float:.1f}{unit}"
        size_float /= 1024.0
    return f"{size_float:.1f}TB"


def get_safe_filename(upload_dir: Path, filename: str) -> Path:
    """Generiert einen sicheren Dateinamen ohne Kollisionen."""
    safe_name = Path(filename).name
    save_path = upload_dir / safe_name
    
    counter = 1
    original_stem = save_path.stem
    original_suffix = save_path.suffix
    while save_path.exists():
        save_path = upload_dir / f"{original_stem}_{counter}{original_suffix}"
        counter += 1
    
    return save_path


def get_upload_dir(args_upload_dir: Optional[str]) -> Path:
    """Ermittelt das Upload-Verzeichnis."""
    if args_upload_dir:
        return Path(args_upload_dir).resolve()
    return Path.cwd()


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class ServerConfig:
    """Server-Konfiguration."""
    mode: str  # "file" | "dir"
    server_type: str  # "http" | "ftp"
    file_path: Optional[Path]
    root_dir: Optional[Path]
    allow_hidden: bool
    allow_listing: bool
    allow_upload: bool
    upload_dir: Path
    max_upload_size: int
    ftp_user: Optional[str]
    ftp_pass: Optional[str]


# =============================================================================
# HTTP Server
# =============================================================================

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP Server für parallele Verbindungen."""
    daemon_threads: bool = True
    allow_reuse_address: bool = True


class RestrictedHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler mit Upload-Funktion und Logging."""
    
    server_version: str = "webon/1.0"

    def do_HEAD(self) -> None:
        """Handle HEAD requests."""
        self._handle_request(send_body=False)

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._handle_request(send_body=True)

    def do_POST(self) -> None:
        """Handle file uploads via POST."""
        config: ServerConfig = getattr(self.server, "config")
        client: str = self.client_address[0]
        timestamp: str = get_timestamp()

        if not config.allow_upload:
            self._send_text(
                HTTPStatus.FORBIDDEN,
                "Upload disabled (remove -n flag)",
                client=client,
                color=RED,
            )
            return

        try:
            self._handle_upload(config, client, timestamp)
        except PermissionError as exc:
            print(f"{RED}[{timestamp}]{RESET} Permission denied: {exc} <- {client}")
            self._send_text(HTTPStatus.FORBIDDEN, f"Permission denied: {exc}", client, RED)
        except OSError as exc:
            print(f"{RED}[{timestamp}]{RESET} IO error: {exc} <- {client}")
            self._send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"IO error: {exc}", client, RED)
        except ValueError as exc:
            print(f"{RED}[{timestamp}]{RESET} Invalid data: {exc} <- {client}")
            self._send_text(HTTPStatus.BAD_REQUEST, f"Invalid data: {exc}", client, RED)
        except Exception as exc:
            print(f"{RED}[{timestamp}]{RESET} Upload error: {type(exc).__name__}: {exc} <- {client}")
            self._send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"Upload failed: {type(exc).__name__}", client, RED)

    def _handle_upload(self, config: ServerConfig, client: str, timestamp: str) -> None:
        """Verarbeitet den eigentlichen Upload."""
        content_length = int(self.headers.get('Content-Length', 0))
        
        if content_length == 0:
            raise ValueError("Keine Daten empfangen")

        if content_length > config.max_upload_size:
            max_mb = config.max_upload_size // 1024 // 1024
            self._send_text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"Datei zu groß (max. {max_mb}MB)", client, RED)
            return

        # Dateiname aus URL extrahieren oder generieren
        upath = urllib.parse.unquote(self.path.lstrip("/"))
        filename = upath if upath and upath != "/" else f"upload_{int(time.time())}.dat"

        # Upload-Verzeichnis erstellen
        config.upload_dir.mkdir(parents=True, exist_ok=True)
        save_path = get_safe_filename(config.upload_dir, filename)

        # Daten empfangen und speichern
        print(f"{DIM}[{timestamp}]{RESET} Receiving: {filename} ({content_length} bytes) <- {client}")
        
        post_data = self.rfile.read(content_length)
        save_path.write_bytes(post_data)

        size_str = format_size(len(post_data))
        print(f"{GREEN}[{timestamp}]{RESET} Saved: {save_path.name} ({size_str}) <- {client}")
        
        self._send_text(HTTPStatus.OK, f"Saved: {save_path.name} ({len(post_data)} bytes)", client, GREEN)

    def _handle_request(self, send_body: bool) -> None:
        """Verarbeitet GET/HEAD Requests."""
        config: ServerConfig = getattr(self.server, "config")
        client: str = self.client_address[0]

        upath = urllib.parse.unquote(self.path.split("?", 1)[0])
        rel = upath.lstrip("/")

        try:
            if config.mode == "file":
                if config.file_path is None:
                    raise ValueError("file_path ist None im file-mode")
                self._handle_file_mode(config.file_path, rel, client, send_body)
            else:
                if config.root_dir is None:
                    raise ValueError("root_dir ist None im dir-mode")
                self._handle_dir_mode(config.root_dir, rel, client, send_body, config)
                
        except PermissionError as exc:
            self._send_text(HTTPStatus.FORBIDDEN, f"Zugriff verweigert: {exc}", client, RED)
        except FileNotFoundError:
            self._send_text(HTTPStatus.NOT_FOUND, "Datei/Ordner nicht gefunden", client, RED)
        except OSError as exc:
            self._send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"IO-Fehler: {exc}", client, RED)
        except Exception as exc:
            self._send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"Serverfehler: {type(exc).__name__}", client, RED)

    def _handle_file_mode(self, file_path: Path, rel: str, client: str, send_body: bool) -> None:
        """Stellt eine einzelne Datei bereit."""
        if rel in ("", file_path.name):
            self._serve_file(file_path, client, send_body)
        else:
            self._send_text(HTTPStatus.NOT_FOUND, "Datei nicht gefunden", client, RED)

    def _handle_dir_mode(self, root: Path, rel: str, client: str, send_body: bool, config: ServerConfig) -> None:
        """Stellt einen Ordner bereit."""
        # Hidden-Files blockieren
        if not config.allow_hidden:
            if any(part.startswith(".") and part != "." for part in Path(rel).parts):
                self._send_text(HTTPStatus.FORBIDDEN, "Zugriff verweigert (hidden)", client, RED)
                return

        target = (root / rel).resolve()

        # Path Traversal Schutz
        try:
            target.relative_to(root.resolve())
        except ValueError:
            self._send_text(HTTPStatus.FORBIDDEN, "Zugriff verweigert (path traversal)", client, RED)
            return

        if target.is_dir():
            index = target / "index.html"
            if index.is_file():
                self._serve_file(index, client, send_body)
            elif config.allow_listing:
                self._serve_listing(target, rel, client, send_body)
            else:
                self._send_text(HTTPStatus.FORBIDDEN, "Directory Listing deaktiviert", client, RED)
        elif target.is_file():
            self._serve_file(target, client, send_body)
        else:
            self._send_text(HTTPStatus.NOT_FOUND, "Datei/Ordner nicht gefunden", client, RED)

    def _serve_file(self, path: Path, client: str, send_body: bool) -> None:
        """Sendet eine Datei zum Client."""
        timestamp = get_timestamp()
        try:
            ctype, _ = mimetypes.guess_type(str(path))
            ctype = ctype or "application/octet-stream"
            size = path.stat().st_size

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

            if send_body:
                with path.open("rb") as f:
                    while chunk := f.read(CHUNK_SIZE):
                        self.wfile.write(chunk)

            print(f"{GREEN}[{timestamp}]{RESET} 200 {path.name} ({format_size(size)}) -> {client}")
            
        except BrokenPipeError:
            print(f"{YELLOW}[{timestamp}]{RESET} Connection closed: {path.name} -> {client}")
        except (PermissionError, FileNotFoundError, OSError):
            raise

    def _serve_listing(self, directory: Path, relpath: str, client: str, send_body: bool) -> None:
        """Generiert und sendet Directory Listing."""
        timestamp = get_timestamp()
        entries = list(directory.iterdir())
        dirs = sorted([p for p in entries if p.is_dir()], key=lambda p: p.name.lower())
        files = sorted([p for p in entries if p.is_file()], key=lambda p: p.name.lower())

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if not send_body:
            print(f"{DIM}[{timestamp}]{RESET} HEAD {directory} -> {client}")
            return

        html = self._generate_listing_html(relpath, dirs, files)
        self.wfile.write(html.encode("utf-8"))
        print(f"{DIM}[{timestamp}]{RESET} Listing: {directory} ({len(dirs)} dirs, {len(files)} files) -> {client}")

    def _generate_listing_html(self, relpath: str, dirs: List[Path], files: List[Path]) -> str:
        """Generiert HTML für Directory Listing."""
        title = f"Index of /{relpath}".rstrip("/")
        out: List[str] = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            f"<title>{title}</title><style>",
            "body{{font-family:monospace;margin:2em;background:#1a1a2e;color:#eee}}",
            "a{{text-decoration:none;color:#00d4ff}}a:hover{{text-decoration:underline}}",
            ".dir{{font-weight:bold;color:#ffd700}}.size{{color:#888;margin-left:1em}}",
            f"h2{{color:#00d4ff}}</style></head><body><h2>📂 {title}</h2><ul>",
        ]

        if relpath:
            parent = "/".join(relpath.split("/")[:-1])
            out.append(f"<li class='dir'><a href='/{urllib.parse.quote(parent)}'>📁 ..</a></li>")

        for p in dirs:
            href = "/".join([x for x in [relpath.strip("/"), p.name + "/"] if x])
            out.append(f"<li class='dir'><a href='/{urllib.parse.quote(href)}'>📁 {p.name}/</a></li>")

        for p in files:
            href = "/".join([x for x in [relpath.strip("/"), p.name] if x])
            try:
                size_str = format_size(p.stat().st_size)
            except OSError:
                size_str = "???"
            out.append(f"<li><a href='/{urllib.parse.quote(href)}'>📄 {p.name}</a><span class='size'>{size_str}</span></li>")

        out.append("</ul></body></html>")
        return "".join(out)

    def _send_text(self, status: HTTPStatus, text: str, client: str, color: str) -> None:
        """Sendet eine Text-Antwort."""
        timestamp = get_timestamp()
        body = (text + "\n").encode("utf-8")
        
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            pass
            
        print(f"{color}[{timestamp}]{RESET} {status.value} {status.phrase}: {text} -> {client}")

    def log_message(self, format: str, *args: Any) -> None:
        """Unterdrückt Standard-Logging."""
        pass


# =============================================================================
# FTP Server
# =============================================================================

def create_ftp_handler(config: ServerConfig) -> Type[Any]:
    """Erstellt einen konfigurierten FTP Handler."""
    from pyftpdlib.handlers import FTPHandler

    class ColoredFTPHandler(FTPHandler):
        """FTP Handler mit Logging."""
        
        def on_connect(self) -> None:
            print(f"{DIM}[{get_timestamp()}]{RESET} FTP connect: {self.remote_ip}")

        def on_disconnect(self) -> None:
            print(f"{DIM}[{get_timestamp()}]{RESET} FTP disconnect: {self.remote_ip}")

        def on_login(self, username: str) -> None:
            print(f"{GREEN}[{get_timestamp()}]{RESET} FTP login: {username} <- {self.remote_ip}")

        def on_login_failed(self, username: str, password: str) -> None:
            print(f"{RED}[{get_timestamp()}]{RESET} FTP login failed: {username} <- {self.remote_ip}")

        def on_file_received(self, file: str) -> None:
            try:
                size_str = format_size(Path(file).stat().st_size)
            except OSError:
                size_str = "???"
            print(f"{GREEN}[{get_timestamp()}]{RESET} FTP upload: {Path(file).name} ({size_str}) <- {self.remote_ip}")

        def on_file_sent(self, file: str) -> None:
            try:
                size_str = format_size(Path(file).stat().st_size)
            except OSError:
                size_str = "???"
            print(f"{GREEN}[{get_timestamp()}]{RESET} FTP download: {Path(file).name} ({size_str}) -> {self.remote_ip}")

        def on_incomplete_file_received(self, file: str) -> None:
            print(f"{RED}[{get_timestamp()}]{RESET} FTP upload aborted: {Path(file).name} <- {self.remote_ip}")

        def on_incomplete_file_sent(self, file: str) -> None:
            print(f"{RED}[{get_timestamp()}]{RESET} FTP download aborted: {Path(file).name} -> {self.remote_ip}")

    return ColoredFTPHandler


def configure_ftp_authorizer(config: ServerConfig, root_path: Path) -> Any:
    """Konfiguriert den FTP Authorizer."""
    from pyftpdlib.authorizers import DummyAuthorizer
    
    authorizer = DummyAuthorizer()
    perms = "elradfmwMT" if config.allow_upload else "elr"

    if config.ftp_user:
        password = config.ftp_pass or ""
        authorizer.add_user(config.ftp_user, password, str(root_path), perm=perms)
        pass_info = "***" if config.ftp_pass else "(empty)"
        print(f"  Auth: user={config.ftp_user}, pass={pass_info}")
    else:
        authorizer.add_anonymous(str(root_path), perm=perms)
        print(f"  Auth: anonymous")
    
    return authorizer


def start_ftp_server(config: ServerConfig, bind: str, port: int) -> int:
    """Startet den FTP-Server."""
    try:
        from pyftpdlib.servers import FTPServer
    except ImportError:
        print(f"{RED}Error:{RESET} FTP mode requires pyftpdlib")
        print(f"  Install: pip install pyftpdlib --break-system-packages")
        return 1

    root_path = config.file_path.parent if config.mode == "file" and config.file_path else config.root_dir
    if not root_path:
        print(f"{RED}Error:{RESET} No root directory configured")
        return 1

    try:
        handler = create_ftp_handler(config)
        handler.authorizer = configure_ftp_authorizer(config, root_path)
        handler.max_upload_size = config.max_upload_size
        handler.banner = "webon FTP Server"
        handler.passive_ports = FTP_PASSIVE_PORTS

        server = FTPServer((bind, port), handler)
        server.max_cons = 256
        server.max_cons_per_ip = 5
    except PermissionError:
        print(f"{RED}Error:{RESET} Permission denied for port {port}")
        return 1
    except OSError as exc:
        print(f"{RED}Error:{RESET} {exc}")
        return 1

    # Startup-Meldung
    print(f"\n{DIM}{'─' * 60}{RESET}")
    print(f"FTP Server: ftp://{bind}:{port}")
    print(f"  Root: {root_path}")
    
    if config.allow_upload:
        print(f"  Upload: enabled (max {config.max_upload_size // 1024 // 1024}MB) -> {config.upload_dir}")
    else:
        print(f"  Upload: disabled")
    
    print(f"{DIM}{'─' * 60}{RESET}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{DIM}Shutting down...{RESET}")
    finally:
        server.close_all()

    return 0


# =============================================================================
# HTTP Server Startup
# =============================================================================

def start_http_server(config: ServerConfig, bind: str, port: int) -> int:
    """Startet den HTTP-Server."""
    try:
        httpd = ThreadedHTTPServer((bind, port), RestrictedHTTPRequestHandler)
    except PermissionError:
        print(f"{RED}Error:{RESET} Permission denied for port {port}")
        return 1
    except OSError as exc:
        print(f"{RED}Error:{RESET} {exc}")
        return 1

    httpd.config = config  # type: ignore[attr-defined]

    # Startup-Meldung
    print(f"\n{DIM}{'─' * 60}{RESET}")
    print(f"HTTP Server: http://{bind}:{port}")
    
    if config.allow_upload:
        print(f"  Upload: enabled (max {config.max_upload_size // 1024 // 1024}MB) -> {config.upload_dir}")
    else:
        print(f"  Upload: disabled")
    
    print(f"{DIM}{'─' * 60}{RESET}\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{DIM}Shutting down...{RESET}")
    finally:
        httpd.server_close()

    return 0


# =============================================================================
# CLI
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parst Kommandozeilenargumente."""
    epilog = """Beispiele:
  # HTTP mit Upload (Standard)
  sudo webon -o /opt/www
  
  # HTTP ohne Upload
  sudo webon -o /opt/www -n
  
  # FTP Anonymous
  sudo webon -o /opt/www --ftp
  
  # FTP mit Auth
  sudo webon -o . --ftp --ftp-user admin --ftp-pass secret
  
  # HTB: Downloads aus /opt/www, Uploads nach /opt/htb
  cd /opt/htb && sudo webon -o /opt/www
"""
    parser = argparse.ArgumentParser(
        description="webon – HTTP/FTP Server für Pentesting",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Einzelne Datei bereitstellen")
    group.add_argument("-o", "--ordner", help="Ordner bereitstellen")

    parser.add_argument("-p", "--port", type=int, help="Port (Default: 80/21)")
    parser.add_argument("-b", "--bind", default=DEFAULT_BIND, help="Bind-Adresse")
    parser.add_argument("-n", "--no-upload", action="store_true", help="Uploads deaktivieren")
    parser.add_argument("--upload-dir", help="Upload-Verzeichnis")
    parser.add_argument("--max-upload-size", type=int, default=DEFAULT_MAX_UPLOAD_SIZE, help="Max Upload (Bytes)")
    parser.add_argument("--allow-hidden", action="store_true", help="Hidden-Files erlauben")
    parser.add_argument("--no-listing", action="store_true", help="Directory Listing aus")
    parser.add_argument("--ftp", action="store_true", help="FTP statt HTTP")
    parser.add_argument("--ftp-user", help="FTP Username")
    parser.add_argument("--ftp-pass", help="FTP Passwort")

    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> ServerConfig:
    """Erstellt ServerConfig aus Argumenten."""
    server_type = "ftp" if args.ftp else "http"
    upload_dir = get_upload_dir(args.upload_dir)
    allow_upload = not args.no_upload
    
    if args.file:
        file_path = Path(args.file).resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        print(f"  File: {file_path}")
        
        return ServerConfig(
            mode="file", server_type=server_type, file_path=file_path, root_dir=None,
            allow_hidden=False, allow_listing=False, allow_upload=allow_upload,
            upload_dir=upload_dir, max_upload_size=args.max_upload_size,
            ftp_user=args.ftp_user, ftp_pass=args.ftp_pass,
        )

    root_dir = Path(args.ordner).resolve()
    if not root_dir.is_dir():
        raise NotADirectoryError(f"Directory not found: {root_dir}")
    print(f"  Root: {root_dir}")
    
    if allow_upload:
        upload_dir.mkdir(parents=True, exist_ok=True)
        print(f"  Upload dir: {upload_dir}")
    
    return ServerConfig(
        mode="dir", server_type=server_type, file_path=None, root_dir=root_dir,
        allow_hidden=args.allow_hidden, allow_listing=not args.no_listing,
        allow_upload=allow_upload, upload_dir=upload_dir,
        max_upload_size=args.max_upload_size, ftp_user=args.ftp_user, ftp_pass=args.ftp_pass,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """Hauptfunktion."""
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.port is None:
        args.port = DEFAULT_FTP_PORT if args.ftp else DEFAULT_HTTP_PORT

    if not 1 <= args.port <= 65535:
        print(f"{RED}Error:{RESET} Invalid port: {args.port}")
        return 2

    if args.port < 1024 and os.geteuid() != 0:
        print(f"{YELLOW}Warning:{RESET} Port {args.port} requires root")

    if args.ftp_pass and not args.ftp_user:
        print(f"{YELLOW}Warning:{RESET} --ftp-pass without --ftp-user ignored")
        args.ftp_pass = None

    try:
        config = build_config(args)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        print(f"{RED}Error:{RESET} {exc}")
        return 2

    return start_ftp_server(config, args.bind, args.port) if args.ftp else start_http_server(config, args.bind, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
