#!/usr/bin/env python3
"""
BH Findings Extractor
=====================
Offline-Analyse von BloodHound/SharpHound JSON-Daten.

Features:
- Legacy + CE Format Support
- Multiple Inputs + --append Modus
- SID-basierte Deduplizierung
- Graph-Analyse (Attack Paths)
- Robustes Error Handling

Usage:
  python bh_findings_extractor.py -i ./data
  python bh_findings_extractor.py -i ./data1 -i ./data2 -o ./report
  python bh_findings_extractor.py -i ./new_scan -o ./report --append
"""

import json
import sys
import re
import csv
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from time import time
from typing import List, Dict, Set, Optional, Tuple, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
import argparse

__version__ = "5.0"


# ============================================================================
# COLORED OUTPUT
# ============================================================================

class Colors:
    """ANSI Colors für Terminal-Output"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    
    @classmethod
    def disable(cls):
        """Deaktiviere Farben (für --quiet oder nicht-TTY)"""
        cls.RESET = cls.BOLD = cls.RED = cls.GREEN = ""
        cls.YELLOW = cls.BLUE = cls.MAGENTA = cls.CYAN = ""


class Logger:
    """Einfacher Logger mit Quiet/Verbose Support"""
    quiet = False
    verbose = False
    
    @classmethod
    def configure(cls, quiet: bool = False, verbose: bool = False):
        cls.quiet = quiet
        cls.verbose = verbose
        if quiet or not sys.stdout.isatty():
            Colors.disable()
    
    @classmethod
    def header(cls, text: str):
        if not cls.quiet:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
            print(f"  {text}")
            print(f"{'='*60}{Colors.RESET}\n")
    
    @classmethod
    def section(cls, num: int, text: str):
        if not cls.quiet:
            print(f"{Colors.BOLD}{num}. {text}...{Colors.RESET}")
    
    @classmethod
    def info(cls, text: str):
        if not cls.quiet:
            print(f"   {text}")
    
    @classmethod
    def success(cls, text: str):
        if not cls.quiet:
            print(f"   {Colors.GREEN}[OK]{Colors.RESET} {text}")
    
    @classmethod
    def skip(cls, text: str):
        if not cls.quiet:
            print(f"   {Colors.BLUE}[--]{Colors.RESET} {text}")
    
    @classmethod
    def warn(cls, text: str):
        if not cls.quiet:
            print(f"   {Colors.YELLOW}[!]{Colors.RESET} {text}")
    
    @classmethod
    def error(cls, text: str):
        print(f"   {Colors.RED}[!!]{Colors.RESET} {text}")
    
    @classmethod
    def debug(cls, text: str):
        if cls.verbose and not cls.quiet:
            print(f"   {Colors.MAGENTA}[D]{Colors.RESET} {text}")
    
    @classmethod
    def result(cls, score: int, level: str):
        if cls.quiet:
            print(f"RISK: {score}/1000 ({level})")
        else:
            color = Colors.RED if level in ("CRITICAL", "HIGH") else Colors.YELLOW if level == "MEDIUM" else Colors.GREEN
            print(f"\n{Colors.BOLD}{'='*60}")
            print(f"RISK SCORE: {color}{score}/1000 ({level}){Colors.RESET}")
            print(f"{'='*60}{Colors.RESET}")

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_edge_type(edge_type: Any) -> str:
    """Normalisiert Edge-Type zu lowercase"""
    if edge_type is None:
        return ""
    return str(edge_type).strip().lower()


def parse_epoch(value: Any) -> Optional[int]:
    """Parst Zeitstempel robust - None bei ungültigen Werten"""
    if value is None:
        return None
    try:
        v = float(value)
        if v <= 0 or v == -1:
            return None
        return int(v)
    except (ValueError, TypeError):
        return None


def get_enabled_state(props: dict) -> Optional[bool]:
    """Tri-State: True, False, oder None - robust für String/Int/Bool"""
    if "enabled" not in props:
        return None
    val = props["enabled"]
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return None


def safe_get(obj: dict, *keys, default=""):
    """Sicherer verschachtelter Zugriff"""
    current = obj
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current if current is not None else default


# ============================================================================
# FINDING
# ============================================================================

@dataclass
class Finding:
    """Strukturiertes Finding mit semantischem Dedup-Key"""
    task: str
    priority: str
    principal: str
    principal_sid: str = ""
    target: str = ""
    target_sid: str = ""
    edge_type: str = ""
    detail: str = ""
    source_file: str = ""
    
    @property
    def dedup_key(self) -> tuple:
        """Key für Deduplizierung (ohne Provenance)"""
        return (self.task, 
                self.principal_sid or self.principal.upper(), 
                self.target_sid or self.target.upper(), 
                self.edge_type.lower())
    
    def to_line(self, provenance: bool = True) -> str:
        parts = [self.principal]
        if self.edge_type:
            parts.append(f"--[{self.edge_type}]-->")
        if self.target:
            parts.append(self.target)
        if self.detail:
            parts.append(f"| {self.detail}")
        if provenance and self.source_file:
            parts.append(f"[{self.source_file}]")
        return " ".join(parts)
    
    def to_dict(self) -> dict:
        return asdict(self)


class FindingCollection:
    """Sammlung mit Deduplizierung nach semantischem Key"""
    _truncated = False
    """Sammlung mit Deduplizierung nach semantischem Key"""
    
    def __init__(self):
        self._findings: Dict[tuple, Finding] = {}
        self._truncated = False
    
    def add(self, finding: Finding):
        key = finding.dedup_key
        if key not in self._findings:
            self._findings[key] = finding
    
    def get_all(self) -> List[Finding]:
        """Sortiert nach principal für deterministische Ausgabe"""
        return sorted(self._findings.values(), key=lambda f: (f.principal, f.target, f.edge_type))
    
    def __len__(self):
        return len(self._findings)
    
    def __iter__(self):
        return iter(self._findings.values())


# ============================================================================
# IDENTITY STORE
# ============================================================================

class IdentityStore:
    """SID-basierter Object Store"""
    
    CACHE_FILE = "_cache.json"
    
    def __init__(self):
        self.users: Dict[str, dict] = {}
        self.computers: Dict[str, dict] = {}
        self.groups: Dict[str, dict] = {}
        self.domains: Dict[str, dict] = {}
        self.gpos: Dict[str, dict] = {}
        self.ous: Dict[str, dict] = {}
        
        self.name_to_sid: Dict[str, str] = {}
        self.sid_to_name: Dict[str, str] = {}
        self.edges: List[dict] = []
        
        self.loaded_files: Set[str] = set()  # Track welche Dateien geladen wurden
        
        self.stats = {
            "users": 0, "computers": 0, "groups": 0, "domains": 0,
            "edges": 0, "duplicates_merged": 0, "unknown_enabled": 0,
        }
    
    def save_cache(self, output_dir: Path):
        """Speichert Store als Cache für --append"""
        cache = {
            "version": __version__,
            "loaded_files": list(self.loaded_files),
            "users": self.users,
            "computers": self.computers,
            "groups": self.groups,
            "domains": self.domains,
            "gpos": self.gpos,
            "ous": self.ous,
            "edges": self.edges,
            "name_to_sid": self.name_to_sid,
            "sid_to_name": self.sid_to_name,
            "stats": self.stats,
        }
        
        cache_path = output_dir / self.CACHE_FILE
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    
    @classmethod
    def load_cache(cls, output_dir: Path) -> Optional["IdentityStore"]:
        """Lädt Store aus Cache"""
        cache_path = output_dir / cls.CACHE_FILE
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, encoding="utf-8") as f:
                cache = json.load(f)
            
            store = cls()
            store.loaded_files = set(cache.get("loaded_files", []))
            store.users = cache.get("users", {})
            store.computers = cache.get("computers", {})
            store.groups = cache.get("groups", {})
            store.domains = cache.get("domains", {})
            store.gpos = cache.get("gpos", {})
            store.ous = cache.get("ous", {})
            store.edges = cache.get("edges", [])
            store.name_to_sid = cache.get("name_to_sid", {})
            store.sid_to_name = cache.get("sid_to_name", {})
            store.stats = cache.get("stats", store.stats)
            
            return store
        except Exception as e:
            print(f"   [!] Cache laden fehlgeschlagen: {e}")
            return None
    
    def add_object(self, obj: dict, obj_type: str, source_file: str):
        props = obj.get("Properties", {})
        
        sid = (obj.get("ObjectIdentifier") or 
               props.get("objectid") or 
               props.get("objectsid") or
               props.get("securityidentifier"))
        
        if not sid:
            name = props.get("name", "")
            sid = f"PSEUDO-{obj_type.upper()}-{hash(name) & 0xFFFFFFFF:08X}"
        
        name = props.get("name", "")
        if name:
            self.name_to_sid[name.upper()] = sid
            self.sid_to_name[sid] = name
        
        obj["_sid"] = sid
        obj["_source_file"] = source_file
        obj["_type"] = obj_type
        
        # unknown_enabled nur für Users zählen (nicht Computer/Groups)
        if obj_type == "user" and get_enabled_state(props) is None:
            self.stats["unknown_enabled"] += 1
        
        store = getattr(self, f"{obj_type}s", None)
        if store is not None:
            if sid in store:
                self._merge_objects(store[sid], obj)
                self.stats["duplicates_merged"] += 1
            else:
                store[sid] = obj
                self.stats[f"{obj_type}s"] += 1
    
    def _merge_objects(self, existing: dict, new: dict):
        if "Properties" in new:
            if "Properties" not in existing:
                existing["Properties"] = {}
            for k, v in new["Properties"].items():
                if v and not existing["Properties"].get(k):
                    existing["Properties"][k] = v
        
        for key in ["Aces", "Members", "SPNTargets", "AllowedToDelegate"]:
            if key in new and new[key]:
                if key not in existing:
                    existing[key] = []
                existing[key].extend(new[key])
    
    def add_edge(self, edge: dict, source_file: str):
        edge["_source_file"] = source_file
        raw_type = edge.get("EdgeType") or edge.get("RightName") or edge.get("Type", "")
        edge["_edge_type_norm"] = normalize_edge_type(raw_type)
        self.edges.append(edge)
        self.stats["edges"] += 1
    
    def resolve_sid(self, val: str) -> Optional[str]:
        if not val:
            return None
        if str(val).startswith("S-1-"):
            return val
        return self.name_to_sid.get(str(val).upper())
    
    def resolve_name(self, sid: str) -> str:
        return self.sid_to_name.get(sid, sid)


# ============================================================================
# SCHEMA DETECTOR
# ============================================================================

class SchemaDetector:
    def __init__(self):
        self.collector = "Unknown"
        self.version = "Unknown"
        self.schema = "Unknown"
        self.collection_date = None
        self.domain = {}
    
    def detect(self, json_files: List[Path]) -> dict:
        for fp in json_files:
            try:
                with open(fp, encoding="utf-8") as f:
                    content = json.load(f)
                self._analyze(content, fp.name)
            except json.JSONDecodeError:
                pass  # Erwartbar bei kaputten JSON-Dateien
            except (IOError, OSError):
                pass  # Datei nicht lesbar
            except Exception:
                pass  # Unerwarteter Fehler, Schema-Detection ist optional
        
        return {
            "collector": self.collector,
            "version": self.version,
            "schema": self.schema,
            "collection_date": self.collection_date,
            "domain": self.domain,
        }
    
    def _analyze(self, content: dict, filename: str):
        if "meta" in content:
            meta = content["meta"]
            if "version" in meta:
                self.schema = str(meta["version"])
            if "collectorversion" in meta:
                self.version = meta["collectorversion"]
        
        if "data" in content and isinstance(content["data"], list) and content["data"]:
            props = content["data"][0].get("Properties", {})
            if "domain" in props:
                self.domain["name"] = props["domain"]
            if "domainsid" in props:
                self.domain["sid"] = props["domainsid"]
            if "lastlogontimestamp" in props:
                self.collector = "SharpHound"
            if "tenantid" in props:
                self.collector = "AzureHound"
        
        if "users" in content or "computers" in content:
            self.schema = "Legacy (pre-v5)"
        
        dm = re.search(r'(\d{8})', filename)
        if dm:
            d = dm.group(1)
            self.collection_date = f"{d[:4]}-{d[4:6]}-{d[6:8]}"


# ============================================================================
# DATA LOADER
# ============================================================================

class BloodHoundLoader:
    def __init__(self, json_files: List[Path] = None, input_dir: Path = None, 
                 existing_store: IdentityStore = None):
        """Kann mit Datei-Liste ODER Verzeichnis initialisiert werden.
        Bei --append: existing_store übergeben zum Weiterarbeiten."""
        self.json_files = json_files or []
        self.input_dir = input_dir
        self.store = existing_store or IdentityStore()
        self.schema = SchemaDetector()
        self.files_loaded: List[str] = []
        self.files_skipped: List[str] = []  # Bereits im Cache
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.load_stats = {
            "files_ok": 0,
            "files_failed": 0,
            "files_skipped": 0,
            "items_ok": 0,
            "items_skipped": 0,
            "edges_ok": 0,
            "edges_skipped": 0,
        }
    
    def load_all(self) -> Tuple[IdentityStore, dict]:
        # Dateien sammeln
        if self.input_dir:
            self.json_files = sorted(self.input_dir.glob("*.json"))
        
        json_files = sorted(self.json_files, key=lambda p: p.name)
        schema_info = self.schema.detect(json_files)
        
        for jf in json_files:
            # Skip wenn bereits im Cache
            if jf.name in self.store.loaded_files:
                self.files_skipped.append(jf.name)
                self.load_stats["files_skipped"] += 1
                continue
            
            self._load_file(jf)
        
        return self.store, schema_info
    
    def _load_file(self, filepath: Path):
        try:
            with open(filepath, encoding="utf-8") as f:
                content = json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"{filepath.name}: JSON Parse Error - {e}")
            self.load_stats["files_failed"] += 1
            return
        except (IOError, OSError) as e:
            self.errors.append(f"{filepath.name}: File Read Error - {e}")
            self.load_stats["files_failed"] += 1
            return
        except Exception as e:
            self.errors.append(f"{filepath.name}: Unexpected Error - {type(e).__name__}: {e}")
            self.load_stats["files_failed"] += 1
            return
        
        src = filepath.name
        
        try:
            if "data" in content and isinstance(content["data"], list):
                self._process_ce_format(content["data"], src)
            elif any(k in content for k in ("users", "computers", "groups", "sessions", "domains")):
                self._process_legacy(content, src)
            else:
                self.warnings.append(f"{src}: Unbekannte JSON-Struktur - keine erkannten Collections")
                self.load_stats["files_failed"] += 1
                return
            
            self.files_loaded.append(f"{filepath.name}: OK")
            self.load_stats["files_ok"] += 1
            self.store.loaded_files.add(filepath.name)  # Für --append
            
        except Exception as e:
            self.errors.append(f"{filepath.name}: Processing Error - {type(e).__name__}: {e}")
            self.load_stats["files_failed"] += 1
    
    def _process_ce_format(self, data: list, src: str):
        """BloodHound CE Format (v5+)"""
        for idx, item in enumerate(data):
            try:
                obj_type = self._detect_type(item)
                if obj_type:
                    self.store.add_object(item, obj_type, src)
                    self.load_stats["items_ok"] += 1
                
                # ACEs
                for ace in item.get("Aces", []):
                    try:
                        start = ace.get("PrincipalSID") or ace.get("PrincipalName") or "?"
                        end_name = safe_get(item, "Properties", "name") or "?"
                        end_sid = item.get("ObjectIdentifier", "")
                        
                        edge = {
                            "StartNode": start,
                            "StartNodeSID": ace.get("PrincipalSID"),
                            "EndNode": end_name,
                            "EndNodeSID": end_sid,
                            "EdgeType": ace.get("RightName") or ace.get("Type", "Unknown"),
                        }
                        self.store.add_edge(edge, src)
                        self.load_stats["edges_ok"] += 1
                    except Exception as e:
                        self.load_stats["edges_skipped"] += 1
                
                # Members
                if "Members" in item:
                    group_name = safe_get(item, "Properties", "name") or "?"
                    group_sid = item.get("ObjectIdentifier", "")
                    
                    for m in item.get("Members", []):
                        try:
                            edge = {
                                "StartNode": m.get("MemberName") or m.get("ObjectIdentifier", "?"),
                                "StartNodeSID": m.get("ObjectIdentifier"),
                                "EndNode": group_name,
                                "EndNodeSID": group_sid,
                                "EdgeType": "MemberOf",
                            }
                            self.store.add_edge(edge, src)
                            self.load_stats["edges_ok"] += 1
                        except Exception:
                            self.load_stats["edges_skipped"] += 1
                            
            except Exception as e:
                self.warnings.append(f"{src}[{idx}]: Item skipped - {type(e).__name__}")
                self.load_stats["items_skipped"] += 1
    
    def _process_legacy(self, content: dict, src: str):
        """Legacy Format"""
        for coll_name, obj_type in [("users", "user"), ("computers", "computer"), 
                                     ("groups", "group"), ("domains", "domain"),
                                     ("gpos", "gpo"), ("ous", "ou")]:
            for idx, item in enumerate(content.get(coll_name, [])):
                try:
                    self.store.add_object(item, obj_type, src)
                    self.load_stats["items_ok"] += 1
                    
                    # ACEs
                    self._extract_aces_safe(item, src)
                    
                    # Members für Groups
                    if coll_name == "groups":
                        self._extract_members_safe(item, src)
                        
                except Exception as e:
                    self.warnings.append(f"{src}/{coll_name}[{idx}]: Item skipped - {type(e).__name__}")
                    self.load_stats["items_skipped"] += 1
        
        # Sessions
        for idx, item in enumerate(content.get("sessions", [])):
            try:
                edge = {
                    "StartNode": item.get("UserName", "?"),
                    "EndNode": item.get("ComputerName", "?"),
                    "EdgeType": "HasSession",
                }
                self.store.add_edge(edge, src)
                self.load_stats["edges_ok"] += 1
            except Exception:
                self.load_stats["edges_skipped"] += 1
    
    def _extract_aces_safe(self, item: dict, src: str):
        """Extrahiert ACEs mit Error Handling"""
        for ace in item.get("Aces", []):
            try:
                start = ace.get("PrincipalSID") or ace.get("PrincipalName") or "?"
                edge = {
                    "StartNode": start,
                    "StartNodeSID": ace.get("PrincipalSID"),
                    "EndNode": safe_get(item, "Properties", "name") or "?",
                    "EndNodeSID": item.get("ObjectIdentifier"),
                    "EdgeType": ace.get("RightName") or ace.get("Type", "Unknown"),
                }
                self.store.add_edge(edge, src)
                self.load_stats["edges_ok"] += 1
            except Exception:
                self.load_stats["edges_skipped"] += 1
    
    def _extract_members_safe(self, item: dict, src: str):
        """Extrahiert Members mit Error Handling"""
        gn = safe_get(item, "Properties", "name") or "?"
        gs = item.get("ObjectIdentifier", "")
        for m in item.get("Members", []):
            try:
                edge = {
                    "StartNode": m.get("MemberName") or m.get("ObjectIdentifier", "?"),
                    "StartNodeSID": m.get("ObjectIdentifier"),
                    "EndNode": gn, 
                    "EndNodeSID": gs,
                    "EdgeType": "MemberOf",
                }
                self.store.add_edge(edge, src)
                self.load_stats["edges_ok"] += 1
            except Exception:
                self.load_stats["edges_skipped"] += 1
    
    def _detect_type(self, item: dict) -> Optional[str]:
        if "meta" in item and "type" in item.get("meta", {}):
            t = item["meta"]["type"].lower()
            if t in ("user", "computer", "group", "domain", "gpo", "ou"):
                return t
        
        props = item.get("Properties", {})
        if "samaccountname" in props:
            return "computer" if "operatingsystem" in props else "user"
        if "operatingsystem" in props:
            return "computer"
        if "admincount" in props and "samaccountname" not in props:
            return "group"
        if props.get("functionallevel") is not None:
            return "domain"
        return None
    
    def write_reports(self, output_dir: Path):
        """Schreibt FILES_LOADED.txt und ERRORS.txt"""
        # FILES_LOADED.txt
        with open(output_dir / "FILES_LOADED.txt", "w", encoding="utf-8") as f:
            f.write(f"BH Findings Extractor v{__version__}\n")
            f.write(f"Geladen: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("STATISTIK:\n")
            f.write(f"  Dateien OK:         {self.load_stats['files_ok']}\n")
            f.write(f"  Dateien Fehler:     {self.load_stats['files_failed']}\n")
            if self.load_stats.get('files_skipped', 0) > 0:
                f.write(f"  Dateien übersprungen (bereits im Cache): {self.load_stats['files_skipped']}\n")
            f.write(f"  Items OK:           {self.load_stats['items_ok']}\n")
            f.write(f"  Items übersprungen: {self.load_stats['items_skipped']}\n")
            f.write(f"  Edges OK:           {self.load_stats['edges_ok']}\n")
            f.write(f"  Edges übersprungen: {self.load_stats['edges_skipped']}\n")
            if self.store.stats.get("duplicates_merged", 0) > 0:
                f.write(f"  Duplikate gemerged: {self.store.stats['duplicates_merged']}\n")
            f.write("\n" + "=" * 60 + "\n\n")
            
            f.write("DATEIEN (neu geladen):\n")
            for line in self.files_loaded:
                f.write(f"  [OK] {line}\n")
            f.write(f"\nTotal: {len(self.files_loaded)} Dateien neu geladen\n")
            
            if self.files_skipped:
                f.write(f"\nDATEIEN (bereits im Cache - übersprungen):\n")
                for fn in self.files_skipped:
                    f.write(f"  [SKIP] {fn}\n")
            
            if self.store.loaded_files:
                f.write(f"\nALLE DATEIEN IM STORE ({len(self.store.loaded_files)}):\n")
                for fn in sorted(self.store.loaded_files):
                    f.write(f"  {fn}\n")
        
        # ERRORS.txt (nur wenn Fehler oder Warnungen)
        if self.errors or self.warnings:
            with open(output_dir / "ERRORS.txt", "w", encoding="utf-8") as f:
                f.write(f"BH Findings Extractor v{__version__} - FEHLER & WARNUNGEN\n")
                f.write(f"Erstellt: {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")
                
                if self.errors:
                    f.write(f"FEHLER ({len(self.errors)}):\n")
                    f.write("-" * 40 + "\n")
                    for err in self.errors:
                        f.write(f"  [ERROR] {err}\n")
                    f.write("\n")
                
                if self.warnings:
                    f.write(f"WARNUNGEN ({len(self.warnings)}):\n")
                    f.write("-" * 40 + "\n")
                    for warn in self.warnings[:50]:  # Max 50 Warnungen
                        f.write(f"  [WARN] {warn}\n")
                    if len(self.warnings) > 50:
                        f.write(f"  ... und {len(self.warnings) - 50} weitere Warnungen\n")


# ============================================================================
# GRAPH ANALYZER
# ============================================================================

class GraphAnalyzer:
    HIGH_VALUE = ["domain admins", "enterprise admins", "administrators", 
                  "schema admins", "account operators", "backup operators"]
    
    def __init__(self, store: IdentityStore):
        self.store = store
        self.graph = None
        self.hv_sids: Set[str] = set()
    
    def build_graph(self) -> bool:
        if not HAS_NETWORKX:
            return False
        
        self.graph = nx.DiGraph()
        
        for sid, obj in self.store.users.items():
            name = safe_get(obj, "Properties", "name") or sid
            self.graph.add_node(sid, name=name, type="user")
        
        for sid, obj in self.store.computers.items():
            name = safe_get(obj, "Properties", "name") or sid
            self.graph.add_node(sid, name=name, type="computer")
        
        for sid, obj in self.store.groups.items():
            name = safe_get(obj, "Properties", "name") or sid
            self.graph.add_node(sid, name=name, type="group")
            if any(hv in name.lower() for hv in self.HIGH_VALUE):
                self.hv_sids.add(sid)
        
        for edge in self.store.edges:
            src = edge.get("StartNodeSID") or self.store.resolve_sid(edge.get("StartNode", ""))
            tgt = edge.get("EndNodeSID") or self.store.resolve_sid(edge.get("EndNode", ""))
            if src and tgt:
                self.graph.add_edge(src, tgt, 
                    type=edge.get("_edge_type_norm", ""),
                    type_raw=edge.get("EdgeType", ""))
        
        return True
    
    def find_paths_to_da(self, max_paths=50, max_depth=8) -> List[dict]:
        if not self.graph or not self.hv_sids:
            return []
        
        paths = []
        for sid, obj in self.store.users.items():
            if get_enabled_state(obj.get("Properties", {})) is False:
                continue
            if sid in self.hv_sids:
                continue
            
            for hv in self.hv_sids:
                try:
                    if nx.has_path(self.graph, sid, hv):
                        path = nx.shortest_path(self.graph, sid, hv)
                        if 1 < len(path) <= max_depth:
                            edges = []
                            for i in range(len(path)-1):
                                d = self.graph.get_edge_data(path[i], path[i+1], {})
                                edges.append(d.get("type_raw", d.get("type", "?")))
                            
                            paths.append({
                                "source_sid": sid,
                                "source_name": self.store.resolve_name(sid),
                                "target_sid": hv,
                                "target_name": self.store.resolve_name(hv),
                                "length": len(path)-1,
                                "path": [self.store.resolve_name(p) for p in path],
                                "edges": edges,
                            })
                            if len(paths) >= max_paths:
                                return sorted(paths, key=lambda x: x["length"])
                except nx.NetworkXNoPath:
                    pass  # Kein Pfad vorhanden - erwartbar
                except nx.NodeNotFound:
                    pass  # Node nicht im Graph - erwartbar bei unvollständigen Daten
                except Exception:
                    pass  # Andere Graph-Fehler ignorieren
        
        return sorted(paths, key=lambda x: x["length"])
    
    def get_stats(self) -> dict:
        if not self.graph:
            return {}
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "high_value_targets": len(self.hv_sids),
        }


# ============================================================================
# RISK SCORER
# ============================================================================

class RiskScorer:
    WEIGHTS = {
        'dcsync_rights.txt': 100, 'attack_paths.txt': 40,
        'unconstrained_delegation.txt': 50, 'asrep_roastable_users.txt': 30,
        'kerberoastable_users.txt': 20, 'sid_history.txt': 35,
        'dangerous_acls.txt': 12, 'constrained_delegation.txt': 15,
        'no_password_required.txt': 15, 'no_laps.txt': 2,
    }
    
    def calculate(self, results: Dict[str, FindingCollection]) -> tuple:
        score = sum(len(fc) * self.WEIGHTS.get(fn, 1) for fn, fc in results.items())
        score = min(score, 1000)
        
        if score <= 50:
            return score, "LOW", "Niedriges Risiko"
        elif score <= 150:
            return score, "MEDIUM", "Mittleres Risiko"
        elif score <= 400:
            return score, "HIGH", "Hohes Risiko"
        else:
            return score, "CRITICAL", "Kritisch!"


# ============================================================================
# ANALYSIS TASKS
# ============================================================================

class AnalysisTask(ABC):
    name = "generic"
    output_filename = "output.txt"
    description = "Generic"
    priority = "LOW"
    
    @abstractmethod
    def run(self, store: IdentityStore, graph: GraphAnalyzer = None) -> FindingCollection:
        pass


class EnabledUsersTask(AnalysisTask):
    name = "enabled_users"
    output_filename = "enabled_users.txt"
    description = "Aktive User"
    priority = "INFO"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if get_enabled_state(p) is True:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=p.get("samaccountname", ""),
                              source_file=obj.get("_source_file", "")))
        return fc


class DisabledUsersTask(AnalysisTask):
    name = "disabled_users"
    output_filename = "disabled_users.txt"
    description = "Deaktivierte User"
    priority = "INFO"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if get_enabled_state(p) is False:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              source_file=obj.get("_source_file", "")))
        return fc


class UnknownEnabledTask(AnalysisTask):
    name = "unknown_enabled"
    output_filename = "unknown_enabled_state.txt"
    description = "User mit unbekanntem Status"
    priority = "INFO"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if get_enabled_state(p) is None:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail="enabled-Status fehlt",
                              source_file=obj.get("_source_file", "")))
        return fc


class InactiveUsersTask(AnalysisTask):
    name = "inactive_users"
    output_filename = "inactive_users.txt"
    description = "Inaktive User (>180d)"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        now = int(datetime.now().timestamp())
        cutoff = now - (180 * 86400)
        
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if get_enabled_state(p) is not True:
                continue
            ll = parse_epoch(p.get("lastlogontimestamp"))
            if ll and ll < cutoff:
                days = (now - ll) // 86400
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=f"{days} Tage",
                              source_file=obj.get("_source_file", "")))
        return fc


class DomainAdminsTask(AnalysisTask):
    name = "domain_admins"
    output_filename = "domain_admins.txt"
    description = "Domain Admins"
    priority = "CRITICAL"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        da_sids = set()
        
        # 1. Finde Domain Admins Group SIDs
        for sid, obj in store.groups.items():
            p = obj.get("Properties", {})
            if "domain admins" in p.get("name", "").lower():
                da_sids.add(sid)
                
                # Members aus Group-Objekt
                for m in obj.get("Members", []):
                    name = m.get("MemberName") or m.get("ObjectIdentifier", "?")
                    fc.add(Finding(self.name, self.priority, name,
                                  principal_sid=m.get("ObjectIdentifier", ""),
                                  target="Domain Admins (Members[])",
                                  source_file=obj.get("_source_file", "")))
        
        # 2. Zusätzlich: MemberOf-Edges auswerten (für CE-Format)
        for edge in store.edges:
            if edge.get("_edge_type_norm") == "memberof":
                end_sid = edge.get("EndNodeSID") or store.resolve_sid(edge.get("EndNode", ""))
                if end_sid in da_sids:
                    start = edge.get("StartNode") or edge.get("StartNodeSID") or "?"
                    start_sid = edge.get("StartNodeSID", "")
                    start_name = store.resolve_name(start_sid) if start_sid else start
                    
                    fc.add(Finding(self.name, self.priority, start_name,
                                  principal_sid=start_sid,
                                  target="Domain Admins (Edge)",
                                  source_file=edge.get("_source_file", "")))
        
        return fc


class EnterpriseAdminsTask(AnalysisTask):
    name = "enterprise_admins"
    output_filename = "enterprise_admins.txt"
    description = "Enterprise Admins"
    priority = "CRITICAL"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        ea_sids = set()
        
        # 1. Finde Enterprise Admins Group SIDs
        for sid, obj in store.groups.items():
            p = obj.get("Properties", {})
            if "enterprise admins" in p.get("name", "").lower():
                ea_sids.add(sid)
                
                # Members aus Group-Objekt
                for m in obj.get("Members", []):
                    name = m.get("MemberName") or m.get("ObjectIdentifier", "?")
                    fc.add(Finding(self.name, self.priority, name,
                                  principal_sid=m.get("ObjectIdentifier", ""),
                                  target="Enterprise Admins (Members[])",
                                  source_file=obj.get("_source_file", "")))
        
        # 2. Zusätzlich: MemberOf-Edges auswerten (für CE-Format)
        for edge in store.edges:
            if edge.get("_edge_type_norm") == "memberof":
                end_sid = edge.get("EndNodeSID") or store.resolve_sid(edge.get("EndNode", ""))
                if end_sid in ea_sids:
                    start = edge.get("StartNode") or edge.get("StartNodeSID") or "?"
                    start_sid = edge.get("StartNodeSID", "")
                    start_name = store.resolve_name(start_sid) if start_sid else start
                    
                    fc.add(Finding(self.name, self.priority, start_name,
                                  principal_sid=start_sid,
                                  target="Enterprise Admins (Edge)",
                                  source_file=edge.get("_source_file", "")))
        
        return fc


class KerberoastableTask(AnalysisTask):
    name = "kerberoastable"
    output_filename = "kerberoastable_users.txt"
    description = "Kerberoastable"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if p.get("hasspn") and get_enabled_state(p) is True:
                spns = p.get("serviceprincipalnames", [])
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=f"SPN: {spns[0]}" if spns else "",
                              source_file=obj.get("_source_file", "")))
        return fc


class ASREPRoastableTask(AnalysisTask):
    name = "asrep_roastable"
    output_filename = "asrep_roastable_users.txt"
    description = "AS-REP Roastable"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if p.get("dontreqpreauth") and get_enabled_state(p) is True:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              source_file=obj.get("_source_file", "")))
        return fc


class UnconstrainedDelegationTask(AnalysisTask):
    name = "unconstrained_delegation"
    output_filename = "unconstrained_delegation.txt"
    description = "Unconstrained Delegation"
    priority = "CRITICAL"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.computers.items():
            p = obj.get("Properties", {})
            if p.get("unconstraineddelegation"):
                fc.add(Finding(self.name, self.priority, 
                              f"[COMPUTER] {p.get('name', '?')}", sid,
                              detail=p.get("operatingsystem", ""),
                              source_file=obj.get("_source_file", "")))
        
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if p.get("unconstraineddelegation"):
                fc.add(Finding(self.name, self.priority,
                              f"[USER] {p.get('name', '?')}", sid,
                              source_file=obj.get("_source_file", "")))
        return fc


class ConstrainedDelegationTask(AnalysisTask):
    name = "constrained_delegation"
    output_filename = "constrained_delegation.txt"
    description = "Constrained Delegation"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for coll in [store.computers, store.users]:
            for sid, obj in coll.items():
                p = obj.get("Properties", {})
                allowed = p.get("allowedtodelegate", [])
                if allowed:
                    targets = ", ".join(allowed[:3])
                    if len(allowed) > 3:
                        targets += f" (+{len(allowed)-3})"
                    fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                                  target=targets,
                                  source_file=obj.get("_source_file", "")))
        return fc


class DCSyncTask(AnalysisTask):
    name = "dcsync_rights"
    output_filename = "dcsync_rights.txt"
    description = "DCSync Rechte"
    priority = "CRITICAL"
    
    # NORMALIZED lowercase - bekannte Varianten
    DCSYNC = {
        "getchanges", "getchangesall", "getchangesinfilteredset",
        "ds-replication-get-changes", "ds-replication-get-changes-all",
        "ds-replication-get-changes-in-filtered-set",
        "dcsync", "replicating directory changes", 
        "replicating directory changes all",
        "replicating directory changes in filtered set",
        "synclastarribute",
    }
    
    def _is_dcsync_edge(self, et: str) -> bool:
        """Prüft ob Edge-Type DCSync ist - mit Fallback für unbekannte Varianten"""
        if et in self.DCSYNC:
            return True
        # Fallback: enthält "replication" und "changes"?
        if "replication" in et and "changes" in et:
            return True
        # Fallback: enthält "get-changes" oder "getchanges"?
        if "get-changes" in et or "getchanges" in et:
            return True
        return False
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for edge in store.edges:
            et = edge.get("_edge_type_norm", "")
            if self._is_dcsync_edge(et):
                start = edge.get("StartNode") or edge.get("PrincipalSID") or "?"
                start_name = store.resolve_name(start) if str(start).startswith("S-1-") else start
                fc.add(Finding(self.name, self.priority, start_name,
                              principal_sid=edge.get("StartNodeSID", ""),
                              target=edge.get("EndNode", "?"),
                              edge_type=edge.get("EdgeType", et),
                              source_file=edge.get("_source_file", "")))
        return fc


class DangerousACLsTask(AnalysisTask):
    name = "dangerous_acls"
    output_filename = "dangerous_acls.txt"
    description = "Gefaehrliche ACLs"
    priority = "HIGH"
    
    # NORMALIZED lowercase!
    DANGEROUS = {"genericall", "genericwrite", "writeowner", "writedacl",
                "forcechangepassword", "addmember", "addself", "owns"}
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for edge in store.edges:
            et = edge.get("_edge_type_norm", "")
            if et in self.DANGEROUS:
                start = edge.get("StartNode") or edge.get("PrincipalSID") or "?"
                start_name = store.resolve_name(start) if str(start).startswith("S-1-") else start
                fc.add(Finding(self.name, self.priority, start_name,
                              principal_sid=edge.get("StartNodeSID", ""),
                              target=edge.get("EndNode", "?"),
                              target_sid=edge.get("EndNodeSID", ""),
                              edge_type=edge.get("EdgeType", et),
                              source_file=edge.get("_source_file", "")))
        
        # Limit mit Hinweis
        if len(fc) > 200:
            fc._truncated = True
            fc._findings = dict(list(fc._findings.items())[:200])
        return fc


class AttackPathsTask(AnalysisTask):
    name = "attack_paths"
    output_filename = "attack_paths.txt"
    description = "Attack Paths zu DA"
    priority = "CRITICAL"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        if not graph or not HAS_NETWORKX:
            fc.add(Finding(self.name, "INFO", "NetworkX nicht installiert",
                          detail="pip install networkx"))
            return fc
        
        for p in graph.find_paths_to_da(50, 8):
            fc.add(Finding(self.name, self.priority, p["source_name"],
                          principal_sid=p["source_sid"],
                          target=p["target_name"],
                          target_sid=p["target_sid"],
                          detail=f"{p['length']} hops: {' -> '.join(p['edges'])}"))
        return fc


class PasswordNeverExpiresTask(AnalysisTask):
    name = "password_never_expires"
    output_filename = "password_never_expires.txt"
    description = "Password Never Expires"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        now = int(datetime.now().timestamp())
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if p.get("pwdneverexpires") and get_enabled_state(p) is True:
                ps = parse_epoch(p.get("pwdlastset"))
                age = f"{(now - ps) // 86400} Tage" if ps else ""
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=age, source_file=obj.get("_source_file", "")))
        return fc


class NeverChangedPasswordTask(AnalysisTask):
    name = "never_changed_password"
    output_filename = "never_changed_passwords.txt"
    description = "Passwort nie geaendert"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if parse_epoch(p.get("pwdlastset")) is None and get_enabled_state(p) is True:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              source_file=obj.get("_source_file", "")))
        return fc


class NoPasswordRequiredTask(AnalysisTask):
    name = "no_password_required"
    output_filename = "no_password_required.txt"
    description = "Kein Passwort noetig"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if (p.get("passwordnotreqd") or p.get("dontreqpass")) and get_enabled_state(p) is True:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              source_file=obj.get("_source_file", "")))
        return fc


class DescriptionPasswordsTask(AnalysisTask):
    name = "description_passwords"
    output_filename = "description_passwords.txt"
    description = "Passwoerter in Description"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        kw = ["password", "pwd", "pass", "pw", "kennwort", "passwort"]
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            desc = p.get("description", "")
            if desc and any(k in desc.lower() for k in kw):
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=desc[:60], source_file=obj.get("_source_file", "")))
        return fc


class NoLAPSTask(AnalysisTask):
    name = "no_laps"
    output_filename = "no_laps.txt"
    description = "Computer ohne LAPS"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.computers.items():
            p = obj.get("Properties", {})
            if not p.get("haslaps") and get_enabled_state(p) is not False:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=p.get("operatingsystem", ""),
                              source_file=obj.get("_source_file", "")))
        return fc


class UnsupportedOSTask(AnalysisTask):
    name = "unsupported_os"
    output_filename = "unsupported_os.txt"
    description = "Veraltete OS"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        old = ("2003", "2008", "xp", "vista", "windows 7", "2000", "nt 4")
        for sid, obj in store.computers.items():
            p = obj.get("Properties", {})
            os = p.get("operatingsystem", "")
            if any(v in os.lower() for v in old):
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=os, source_file=obj.get("_source_file", "")))
        return fc


class SIDHistoryTask(AnalysisTask):
    name = "sid_history"
    output_filename = "sid_history.txt"
    description = "SID History"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            sh = p.get("sidhistory", [])
            if sh:
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=f"{len(sh)} SID(s)",
                              source_file=obj.get("_source_file", "")))
        return fc


class AdminCountTask(AnalysisTask):
    name = "admincount"
    output_filename = "admincount_users.txt"
    description = "AdminCount=1"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        for sid, obj in store.users.items():
            p = obj.get("Properties", {})
            if p.get("admincount"):
                e = get_enabled_state(p)
                status = "aktiv" if e is True else ("deaktiviert" if e is False else "?")
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=status, source_file=obj.get("_source_file", "")))
        return fc


# ============================================================================
# NEUE FINDINGS (v5.0)
# ============================================================================

class RBCDTask(AnalysisTask):
    """Resource-Based Constrained Delegation - sehr exploitbar!"""
    name = "rbcd"
    output_filename = "rbcd_delegation.txt"
    description = "RBCD (Resource-Based Constrained Delegation)"
    priority = "CRITICAL"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        
        # Wer kann AllowedToAct schreiben?
        for edge in store.edges:
            et = edge.get("_edge_type_norm", "")
            if et in ("writeallowedtoact", "addallowedtoact", "genericall", "genericwrite"):
                target_props = {}
                end_sid = edge.get("EndNodeSID", "")
                if end_sid in store.computers:
                    target_props = store.computers[end_sid].get("Properties", {})
                
                start = edge.get("StartNode") or edge.get("StartNodeSID") or "?"
                start_name = store.resolve_name(start) if str(start).startswith("S-1-") else start
                
                fc.add(Finding(self.name, self.priority, start_name,
                              principal_sid=edge.get("StartNodeSID", ""),
                              target=edge.get("EndNode", "?"),
                              target_sid=end_sid,
                              edge_type=et.upper(),
                              detail="Kann RBCD konfigurieren",
                              source_file=edge.get("_source_file", "")))
        
        # Computer mit AllowedToActOnBehalfOfOtherIdentity
        for sid, obj in store.computers.items():
            p = obj.get("Properties", {})
            allowed = p.get("allowedtoact") or p.get("allowedtoactprincipals") or []
            if allowed:
                for principal in allowed if isinstance(allowed, list) else [allowed]:
                    fc.add(Finding(self.name, self.priority, 
                                  principal if isinstance(principal, str) else str(principal),
                                  target=p.get("name", "?"),
                                  target_sid=sid,
                                  detail="AllowedToAct konfiguriert",
                                  source_file=obj.get("_source_file", "")))
        return fc


class ShadowAdminsTask(AnalysisTask):
    """User mit GenericAll/WriteDACL auf DA-Group aber nicht Mitglied"""
    name = "shadow_admins"
    output_filename = "shadow_admins.txt"
    description = "Shadow Admins (GenericAll auf DA)"
    priority = "CRITICAL"
    
    DANGEROUS = {"genericall", "genericwrite", "writeowner", "writedacl"}
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        
        # Finde DA/EA Group SIDs
        hv_sids = set()
        for sid, obj in store.groups.items():
            name = obj.get("Properties", {}).get("name", "").lower()
            if any(x in name for x in ("domain admins", "enterprise admins", "administrators")):
                hv_sids.add(sid)
        
        # Finde DA-Mitglieder
        da_members = set()
        for edge in store.edges:
            if edge.get("_edge_type_norm") == "memberof":
                end_sid = edge.get("EndNodeSID", "")
                if end_sid in hv_sids:
                    da_members.add(edge.get("StartNodeSID", ""))
        
        # Finde User mit GenericAll auf DA aber nicht Mitglied
        for edge in store.edges:
            et = edge.get("_edge_type_norm", "")
            if et in self.DANGEROUS:
                end_sid = edge.get("EndNodeSID", "")
                if end_sid in hv_sids:
                    start_sid = edge.get("StartNodeSID", "")
                    # Nur wenn NICHT bereits DA-Mitglied
                    if start_sid and start_sid not in da_members:
                        start = edge.get("StartNode") or start_sid or "?"
                        start_name = store.resolve_name(start_sid) if start_sid else start
                        
                        fc.add(Finding(self.name, self.priority, start_name,
                                      principal_sid=start_sid,
                                      target=edge.get("EndNode", "?"),
                                      edge_type=et.upper(),
                                      detail="Shadow Admin - nicht Mitglied aber volle Kontrolle",
                                      source_file=edge.get("_source_file", "")))
        return fc


class NestedGroupsTask(AnalysisTask):
    """Indirekte DA-Membership über lange Ketten"""
    name = "nested_groups"
    output_filename = "nested_group_chains.txt"
    description = "Nested Group Chains zu DA"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        
        if not graph or not graph.graph:
            return fc
        
        # Finde DA Group SIDs
        da_sids = set()
        for sid, obj in store.groups.items():
            name = obj.get("Properties", {}).get("name", "").lower()
            if "domain admins" in name:
                da_sids.add(sid)
        
        if not da_sids:
            return fc
        
        # Finde Pfade mit >2 Hops (indirekte Membership)
        try:
            import networkx as nx
            for user_sid in list(store.users.keys())[:500]:  # Limit für Performance
                for da_sid in da_sids:
                    try:
                        if nx.has_path(graph.graph, user_sid, da_sid):
                            path = nx.shortest_path(graph.graph, user_sid, da_sid)
                            # Nur wenn Pfad >2 Hops und nur MemberOf
                            if len(path) > 3:  # User -> Group1 -> Group2 -> DA
                                # Prüfe ob alles MemberOf ist
                                is_memberof_chain = True
                                for i in range(len(path)-1):
                                    edge_data = graph.graph.get_edge_data(path[i], path[i+1], {})
                                    if edge_data.get("type", "") != "memberof":
                                        is_memberof_chain = False
                                        break
                                
                                if is_memberof_chain:
                                    user_name = store.resolve_name(user_sid)
                                    chain = " → ".join(store.resolve_name(p) for p in path)
                                    fc.add(Finding(self.name, self.priority, user_name,
                                                  principal_sid=user_sid,
                                                  target="Domain Admins",
                                                  detail=f"{len(path)-1} Hops: {chain}",
                                                  source_file=""))
                    except:
                        pass
        except:
            pass
        return fc


class StaleComputersTask(AnalysisTask):
    """Computer die >90 Tage nicht eingeloggt waren"""
    name = "stale_computers"
    output_filename = "stale_computers.txt"
    description = "Stale Computers (>90 Tage inaktiv)"
    priority = "MEDIUM"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        now = int(datetime.now().timestamp())
        threshold = 90 * 86400  # 90 Tage
        
        for sid, obj in store.computers.items():
            p = obj.get("Properties", {})
            ll = parse_epoch(p.get("lastlogontimestamp") or p.get("lastlogon"))
            
            if ll and (now - ll) > threshold:
                days = (now - ll) // 86400
                os_info = p.get("operatingsystem", "?")
                fc.add(Finding(self.name, self.priority, p.get("name", "?"), sid,
                              detail=f"{days} Tage inaktiv | OS: {os_info}",
                              source_file=obj.get("_source_file", "")))
        return fc


class Pre2000GroupTask(AnalysisTask):
    """Pre-Windows 2000 Compatible Access - oft overprivileged"""
    name = "pre2000_group"
    output_filename = "pre2000_compatible_access.txt"
    description = "Pre-Windows 2000 Compatible Access"
    priority = "HIGH"
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        
        # Finde die Gruppe
        pre2000_sid = None
        for sid, obj in store.groups.items():
            name = obj.get("Properties", {}).get("name", "").lower()
            if "pre-windows 2000" in name or "pre-win2k" in name:
                pre2000_sid = sid
                break
        
        if not pre2000_sid:
            return fc
        
        # Finde Mitglieder
        obj = store.groups.get(pre2000_sid, {})
        for m in obj.get("Members", []):
            name = m.get("MemberName") or m.get("ObjectIdentifier", "?")
            # Interessant wenn "Everyone" oder "Authenticated Users" Mitglied
            if any(x in name.lower() for x in ("everyone", "authenticated", "anonymous")):
                fc.add(Finding(self.name, self.priority, name,
                              principal_sid=m.get("ObjectIdentifier", ""),
                              target="Pre-Windows 2000 Compatible Access",
                              detail="Overprivileged - sollte entfernt werden",
                              source_file=obj.get("_source_file", "")))
        
        # Auch aus Edges
        for edge in store.edges:
            if edge.get("_edge_type_norm") == "memberof":
                if edge.get("EndNodeSID") == pre2000_sid:
                    name = edge.get("StartNode", "?")
                    if any(x in name.lower() for x in ("everyone", "authenticated", "anonymous")):
                        fc.add(Finding(self.name, self.priority, name,
                                      principal_sid=edge.get("StartNodeSID", ""),
                                      target="Pre-Windows 2000 Compatible Access",
                                      detail="Overprivileged - sollte entfernt werden",
                                      source_file=edge.get("_source_file", "")))
        return fc


class GPOAbusableTask(AnalysisTask):
    """User die GPOs modifizieren können"""
    name = "gpo_abusable"
    output_filename = "gpo_abusable.txt"
    description = "GPO Abuse möglich"
    priority = "HIGH"
    
    DANGEROUS = {"genericall", "genericwrite", "writeowner", "writedacl", "writeproperty"}
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        
        # Finde GPO SIDs
        gpo_sids = set(store.gpos.keys())
        
        for edge in store.edges:
            et = edge.get("_edge_type_norm", "")
            if et in self.DANGEROUS:
                end_sid = edge.get("EndNodeSID", "")
                if end_sid in gpo_sids:
                    gpo = store.gpos.get(end_sid, {})
                    gpo_name = gpo.get("Properties", {}).get("name", edge.get("EndNode", "?"))
                    
                    start = edge.get("StartNode") or edge.get("StartNodeSID") or "?"
                    start_name = store.resolve_name(start) if str(start).startswith("S-1-") else start
                    
                    fc.add(Finding(self.name, self.priority, start_name,
                                  principal_sid=edge.get("StartNodeSID", ""),
                                  target=gpo_name,
                                  target_sid=end_sid,
                                  edge_type=et.upper(),
                                  detail="Kann GPO modifizieren",
                                  source_file=edge.get("_source_file", "")))
        return fc


ALL_TASKS = [
    EnabledUsersTask, DisabledUsersTask, UnknownEnabledTask, InactiveUsersTask,
    DomainAdminsTask, EnterpriseAdminsTask,
    KerberoastableTask, ASREPRoastableTask,
    UnconstrainedDelegationTask, ConstrainedDelegationTask, RBCDTask,
    DCSyncTask, DangerousACLsTask, ShadowAdminsTask, GPOAbusableTask,
    AttackPathsTask, NestedGroupsTask,
    PasswordNeverExpiresTask, NeverChangedPasswordTask, NoPasswordRequiredTask, DescriptionPasswordsTask,
    NoLAPSTask, UnsupportedOSTask, StaleComputersTask,
    SIDHistoryTask, AdminCountTask, Pre2000GroupTask,
]


# ============================================================================
# DIFF MODE
# ============================================================================

class DiffAnalyzer:
    """Vergleicht zwei Report-Verzeichnisse"""
    
    def __init__(self, old_dir: Path, new_dir: Path):
        self.old_dir = old_dir
        self.new_dir = new_dir
    
    def run(self) -> dict:
        """Führt Diff durch, gibt dict mit 'new', 'fixed', 'unchanged' zurück"""
        old_findings = self._load_findings(self.old_dir)
        new_findings = self._load_findings(self.new_dir)
        
        old_keys = set(old_findings.keys())
        new_keys = set(new_findings.keys())
        
        return {
            "new": {k: new_findings[k] for k in (new_keys - old_keys)},
            "fixed": {k: old_findings[k] for k in (old_keys - new_keys)},
            "unchanged": {k: new_findings[k] for k in (old_keys & new_keys)},
            "old_count": len(old_findings),
            "new_count": len(new_findings),
        }
    
    def _load_findings(self, dir_path: Path) -> dict:
        """Lädt findings_all.json und erzeugt Key-Index"""
        json_path = dir_path / "findings_all.json"
        if not json_path.exists():
            raise FileNotFoundError(f"findings_all.json nicht gefunden in {dir_path}")
        
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        
        findings = {}
        for task_name, task_data in data.items():
            for f in task_data.get("findings", []):
                # Eindeutiger Key
                key = (f.get("task", ""), f.get("principal_sid", ""), 
                       f.get("target_sid", ""), f.get("edge_type", ""))
                findings[key] = f
        
        return findings
    
    def write_diff_report(self, output_path: Path, diff_result: dict):
        """Schreibt Diff-Report"""
        lines = [
            "=" * 60,
            f"BH FINDINGS EXTRACTOR v{__version__} - DIFF REPORT",
            f"Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            "",
            f"Alt:  {self.old_dir}",
            f"Neu:  {self.new_dir}",
            "",
            f"Findings Alt: {diff_result['old_count']}",
            f"Findings Neu: {diff_result['new_count']}",
            "",
        ]
        
        # Neue Findings
        new_findings = diff_result["new"]
        if new_findings:
            lines.append(f"NEUE FINDINGS ({len(new_findings)}):")
            lines.append("-" * 40)
            by_prio = defaultdict(list)
            for key, f in new_findings.items():
                by_prio[f.get("priority", "?")].append(f)
            
            for prio in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if prio in by_prio:
                    for f in by_prio[prio][:20]:  # Max 20 pro Prio
                        lines.append(f"  [{prio}] {f.get('principal', '?')} → {f.get('target', '?')} ({f.get('task', '?')})")
                    if len(by_prio[prio]) > 20:
                        lines.append(f"  ... und {len(by_prio[prio]) - 20} weitere")
            lines.append("")
        
        # Behobene Findings
        fixed_findings = diff_result["fixed"]
        if fixed_findings:
            lines.append(f"BEHOBENE FINDINGS ({len(fixed_findings)}):")
            lines.append("-" * 40)
            by_prio = defaultdict(list)
            for key, f in fixed_findings.items():
                by_prio[f.get("priority", "?")].append(f)
            
            for prio in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if prio in by_prio:
                    for f in by_prio[prio][:20]:
                        lines.append(f"  [{prio}] {f.get('principal', '?')} → {f.get('target', '?')} ({f.get('task', '?')})")
                    if len(by_prio[prio]) > 20:
                        lines.append(f"  ... und {len(by_prio[prio]) - 20} weitere")
            lines.append("")
        
        if not new_findings and not fixed_findings:
            lines.append("Keine Änderungen gefunden.")
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        
        return output_path


# ============================================================================
# HTML REPORT
# ============================================================================

class HTMLReportGenerator:
    """Generiert professionellen HTML Report"""
    
    def generate(self, output_dir: Path, results: Dict[str, FindingCollection], 
                 schema: dict, stats: dict, risk_score: int, risk_level: str):
        
        html = self._build_html(results, schema, stats, risk_score, risk_level)
        
        report_path = output_dir / "REPORT.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        return report_path
    
    def _build_html(self, results, schema, stats, risk_score, risk_level) -> str:
        # Farbe basierend auf Level
        color_map = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14", 
            "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#17a2b8"
        }
        risk_color = color_map.get(risk_level, "#6c757d")
        
        # Findings by Priority
        findings_by_prio = defaultdict(list)
        for task_name, fc in results.items():
            for f in fc.get_all():
                findings_by_prio[f.priority].append((task_name, f))
        
        # Task summaries
        task_rows = ""
        for tc in ALL_TASKS:
            t = tc()
            fc = results.get(t.output_filename)
            cnt = len(fc) if fc else 0
            if cnt > 0:
                prio_color = color_map.get(t.priority, "#6c757d")
                task_rows += f"""
                <tr>
                    <td><span class="badge" style="background:{prio_color}">{t.priority}</span></td>
                    <td>{t.description}</td>
                    <td class="text-end"><strong>{cnt}</strong></td>
                </tr>"""
        
        # Critical findings detail
        critical_detail = ""
        for prio in ["CRITICAL", "HIGH"]:
            if findings_by_prio[prio]:
                critical_detail += f'<h4 class="mt-4" style="color:{color_map[prio]}">{prio} Findings</h4><ul>'
                for task_name, f in findings_by_prio[prio][:30]:
                    critical_detail += f"<li><strong>{f.principal}</strong>"
                    if f.target:
                        critical_detail += f" → {f.target}"
                    if f.edge_type:
                        critical_detail += f" <code>[{f.edge_type}]</code>"
                    if f.detail:
                        critical_detail += f" <small class='text-muted'>({f.detail})</small>"
                    critical_detail += "</li>"
                if len(findings_by_prio[prio]) > 30:
                    critical_detail += f"<li><em>... und {len(findings_by_prio[prio]) - 30} weitere</em></li>"
                critical_detail += "</ul>"
        
        return f'''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BloodHound Findings Report - {schema.get("domain", {}).get("name", "Unknown")}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .risk-score {{ font-size: 3rem; font-weight: bold; color: {risk_color}; }}
        .badge {{ padding: 0.4em 0.8em; }}
        .finding-card {{ border-left: 4px solid {risk_color}; }}
    </style>
</head>
<body class="bg-light">
    <div class="container py-5">
        <div class="card shadow mb-4">
            <div class="card-header bg-dark text-white">
                <h1 class="h3 mb-0">🔍 BloodHound Findings Report</h1>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4 text-center border-end">
                        <div class="risk-score">{risk_score}/1000</div>
                        <div class="h5"><span class="badge" style="background:{risk_color}">{risk_level}</span></div>
                    </div>
                    <div class="col-md-8">
                        <table class="table table-sm mb-0">
                            <tr><td>Domain:</td><td><strong>{schema.get("domain", {}).get("name", "?")}</strong></td></tr>
                            <tr><td>Collector:</td><td>{schema.get("collector", "?")}</td></tr>
                            <tr><td>Schema:</td><td>{schema.get("schema", "?")}</td></tr>
                            <tr><td>Erstellt:</td><td>{datetime.now().strftime("%Y-%m-%d %H:%M")}</td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-3">
                <div class="card text-center bg-primary text-white mb-3">
                    <div class="card-body">
                        <h2>{stats.get("users", 0)}</h2>
                        <div>Users</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-info text-white mb-3">
                    <div class="card-body">
                        <h2>{stats.get("computers", 0)}</h2>
                        <div>Computers</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-secondary text-white mb-3">
                    <div class="card-body">
                        <h2>{stats.get("groups", 0)}</h2>
                        <div>Groups</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center bg-dark text-white mb-3">
                    <div class="card-body">
                        <h2>{stats.get("edges", 0)}</h2>
                        <div>Edges</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card shadow mb-4">
            <div class="card-header"><h5 class="mb-0">📊 Findings Übersicht</h5></div>
            <div class="card-body">
                <table class="table table-hover">
                    <thead><tr><th>Priorität</th><th>Finding</th><th class="text-end">Anzahl</th></tr></thead>
                    <tbody>{task_rows}</tbody>
                </table>
            </div>
        </div>
        
        <div class="card shadow mb-4 finding-card">
            <div class="card-header"><h5 class="mb-0">🚨 Kritische Findings</h5></div>
            <div class="card-body">
                {critical_detail if critical_detail else "<p class='text-muted'>Keine kritischen Findings gefunden.</p>"}
            </div>
        </div>
        
        <footer class="text-center text-muted py-3">
            <small>BH Findings Extractor v{__version__} | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small>
        </footer>
    </div>
</body>
</html>'''


# ============================================================================
# OUTPUT WRITER
# ============================================================================

class OutputWriter:
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    def __init__(self, output_dir: Path):
        self.dir = output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Severity-Ordner erstellen
        for sev in self.SEVERITY_ORDER:
            (output_dir / sev).mkdir(exist_ok=True)
    
    def write_findings(self, fn: str, fc: FindingCollection, truncated_note: str = None, 
                      priority: str = "INFO"):
        # Datei in Severity-Ordner schreiben
        sev_dir = self.dir / priority if priority in self.SEVERITY_ORDER else self.dir / "INFO"
        sev_dir.mkdir(exist_ok=True)
        
        with open(sev_dir / fn, "w", encoding="utf-8") as f:
            if truncated_note:
                f.write(f"# HINWEIS: {truncated_note}\n\n")
            for finding in fc.get_all():  # get_all() ist sortiert → deterministisch
                f.write(f"{finding.to_line()}\n")
    
    def write_index(self, results: Dict[str, FindingCollection], schema: dict, 
                   stats: dict, gstats: dict, elapsed: float):
        lines = [
            "=" * 60,
            f"BH FINDINGS EXTRACTOR v{__version__} - INDEX",
            f"Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Laufzeit: {elapsed:.1f}s",
            "=" * 60, "",
            f"Domain: {schema.get('domain', {}).get('name', '?')}",
            f"Collector: {schema.get('collector', '?')}",
            f"Schema: {schema.get('schema', '?')}", "",
            f"Users: {stats.get('users', 0)} | Computers: {stats.get('computers', 0)} | Groups: {stats.get('groups', 0)}",
            f"Edges: {stats.get('edges', 0)}", "",
            "STRUKTUR:",
            "-" * 40,
        ]
        
        # Nach Severity gruppieren
        by_severity = {sev: [] for sev in self.SEVERITY_ORDER}
        for tc in ALL_TASKS:
            t = tc()
            fc = results.get(t.output_filename)
            cnt = len(fc) if fc else 0
            truncated = " (gekürzt)" if fc and getattr(fc, '_truncated', False) else ""
            by_severity[t.priority].append((t.output_filename, cnt, truncated))
        
        for sev in self.SEVERITY_ORDER:
            items = by_severity[sev]
            if any(cnt > 0 for _, cnt, _ in items):
                lines.append(f"\n{sev}/")
                for fn, cnt, trunc in items:
                    if cnt > 0:
                        lines.append(f"  [{cnt:>4}] {fn}{trunc}")
        
        lines.extend(["", "ROOT:", 
                     "  FILES_LOADED.txt", "  ERRORS.txt (wenn Fehler)",
                     "  findings_critical.csv", "  findings_all.json", 
                     "  SUMMARY_REPORT.txt", "  _cache.json"])
        
        with open(self.dir / "INDEX.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    
    def write_csv(self, results: Dict[str, FindingCollection]):
        crit = {"dcsync_rights.txt", "attack_paths.txt", "unconstrained_delegation.txt",
               "domain_admins.txt", "enterprise_admins.txt"}
        rows = [f.to_dict() for fn, fc in results.items() if fn in crit for f in fc]
        if rows:
            with open(self.dir / "findings_critical.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows)
    
    def write_json(self, results: Dict[str, FindingCollection]):
        out = {fn: {"count": len(fc), "findings": [f.to_dict() for f in fc]} 
               for fn, fc in results.items()}
        with open(self.dir / "findings_all.json", "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
    
    def write_summary(self, results: Dict[str, FindingCollection], schema: dict, stats: dict, 
                      load_stats: dict = None):
        scorer = RiskScorer()
        score, level, desc = scorer.calculate(results)
        
        lines = [
            "=" * 60, "BH FINDINGS EXTRACTOR - ZUSAMMENFASSUNG",
            f"Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "=" * 60, "",
            "DATENQUELLE:", "-" * 40,
            f"  Schema: {schema.get('schema', 'Unknown')}",
            f"  Collector: {schema.get('collector', 'Unknown')}",
            f"  Domain: {schema.get('domain', {}).get('name', 'Unknown')}",
            "",
            f"RISK SCORE: {score}/1000 ({level})", f"Bewertung: {desc}", "",
            f"Users: {stats.get('users', 0)} | DA-Mitglieder: {len(results.get('domain_admins.txt', []))}",
        ]
        
        # Load-Statistiken
        if load_stats:
            if load_stats.get("items_skipped", 0) > 0 or load_stats.get("files_failed", 0) > 0:
                lines.extend(["", "LADE-STATISTIK:", "-" * 40])
                if load_stats.get("files_failed", 0) > 0:
                    lines.append(f"  Dateien fehlgeschlagen: {load_stats['files_failed']}")
                if load_stats.get("items_skipped", 0) > 0:
                    lines.append(f"  Items übersprungen: {load_stats['items_skipped']}")
                if load_stats.get("edges_skipped", 0) > 0:
                    lines.append(f"  Edges übersprungen: {load_stats['edges_skipped']}")
        
        # Collection-Warnungen
        warnings = []
        if stats.get('edges', 0) == 0:
            warnings.append("WARNUNG: Keine Edges/Relationships geladen - ACL-Findings unvollstaendig!")
        if stats.get('users', 0) == 0:
            warnings.append("WARNUNG: Keine Users geladen!")
        if stats.get('groups', 0) == 0:
            warnings.append("WARNUNG: Keine Groups geladen!")
        if stats.get('unknown_enabled', 0) > stats.get('users', 1) * 0.5:
            warnings.append(f"WARNUNG: {stats.get('unknown_enabled', 0)} User ohne enabled-Status!")
        
        if warnings:
            lines.extend(["", "WARNUNGEN:", "-" * 40])
            for w in warnings:
                lines.append(f"  ! {w}")
        
        lines.extend(["", "SCHWACHSTELLEN:", "-" * 40])
        
        for prio, files in [("CRITICAL", ["dcsync_rights.txt", "attack_paths.txt", "unconstrained_delegation.txt"]),
                           ("HIGH", ["kerberoastable_users.txt", "asrep_roastable_users.txt", "dangerous_acls.txt"])]:
            shown = False
            for fn in files:
                cnt = len(results.get(fn, []))
                if cnt > 0:
                    if not shown:
                        lines.append(f"\n{prio}:")
                        shown = True
                    lines.append(f"  [{cnt:>4}] {fn.replace('.txt', '').replace('_', ' ')}")
        
        with open(self.dir / "SUMMARY_REPORT.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# ============================================================================
# MAIN
# ============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="BH Findings Extractor - BloodHound Offline Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s -i ./data                           # Einfache Analyse
  %(prog)s -i ./scan1 -i ./scan2 -o ./report   # Mehrere Quellen
  %(prog)s -i ./new -o ./report --append       # Inkrementell
  %(prog)s --diff ./old_report ./new_report    # Vergleichen
  %(prog)s -i ./data --html                    # Mit HTML Report
        """
    )
    ap.add_argument("-i", "--input", action="append", 
                    help="Input-Verzeichnis (kann mehrfach angegeben werden)")
    ap.add_argument("-o", "--output", default=f"./bh_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}", 
                    help="Output-Verzeichnis")
    ap.add_argument("--append", action="store_true", 
                    help="Zu bestehendem Output hinzufügen")
    ap.add_argument("--force", action="store_true",
                    help="Cache ignorieren, alles neu laden")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                    help="Vergleiche zwei Report-Verzeichnisse")
    ap.add_argument("--html", action="store_true",
                    help="HTML Report generieren")
    ap.add_argument("--tasks", metavar="TASK1,TASK2",
                    help="Nur bestimmte Tasks ausführen")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Minimale Ausgabe")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Ausführliche Ausgabe")
    args = ap.parse_args()
    
    # Logger konfigurieren
    Logger.configure(quiet=args.quiet, verbose=args.verbose)
    
    # === DIFF MODE ===
    if args.diff:
        old_dir, new_dir = Path(args.diff[0]), Path(args.diff[1])
        if not old_dir.exists() or not new_dir.exists():
            Logger.error(f"Report-Verzeichnis nicht gefunden")
            sys.exit(1)
        
        Logger.header(f"BH Findings Extractor v{__version__} - DIFF")
        Logger.info(f"Alt: {old_dir}")
        Logger.info(f"Neu: {new_dir}")
        
        try:
            differ = DiffAnalyzer(old_dir, new_dir)
            result = differ.run()
            
            diff_path = new_dir / "DIFF_REPORT.txt"
            differ.write_diff_report(diff_path, result)
            
            new_count = len(result["new"])
            fixed_count = len(result["fixed"])
            
            if new_count > 0:
                Logger.warn(f"Neue Findings: {new_count}")
            if fixed_count > 0:
                Logger.success(f"Behobene Findings: {fixed_count}")
            if new_count == 0 and fixed_count == 0:
                Logger.info("Keine Änderungen")
            
            Logger.info(f"Report: {diff_path}")
        except Exception as e:
            Logger.error(f"Diff fehlgeschlagen: {e}")
            sys.exit(1)
        return
    
    # === NORMAL MODE ===
    if not args.input:
        ap.print_help()
        sys.exit(1)
    
    Logger.header(f"BH Findings Extractor v{__version__}")
    
    # Sammle JSON-Dateien
    all_json_files = []
    for input_path in args.input:
        inp = Path(input_path)
        if not inp.exists():
            Logger.error(f"'{input_path}' nicht gefunden")
            sys.exit(1)
        
        json_files = list(inp.glob("*.json"))
        if json_files:
            all_json_files.extend(json_files)
            Logger.info(f"Input: {inp.absolute()} ({len(json_files)} Dateien)")
    
    if not all_json_files:
        Logger.error("Keine JSON-Dateien gefunden")
        sys.exit(1)
    
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    writer = OutputWriter(out)
    
    Logger.info(f"Output: {out.absolute()}")
    Logger.info(f"Total: {len(all_json_files)} JSON-Dateien")
    if args.append:
        Logger.info("Mode: --append")
    if args.force:
        Logger.info("Mode: --force (Cache ignoriert)")
    
    # === LOAD ===
    Logger.section(1, "Lade Daten")
    
    existing_store = None
    if args.append and not args.force:
        existing_store = IdentityStore.load_cache(out)
        if existing_store:
            Logger.info(f"Cache geladen: {len(existing_store.loaded_files)} Dateien")
        else:
            Logger.debug("Kein Cache gefunden")
    
    loader = BloodHoundLoader(json_files=all_json_files, existing_store=existing_store)
    store, schema = loader.load_all()
    store.save_cache(out)
    loader.write_reports(out)
    
    Logger.info(f"Users: {store.stats['users']}, Computers: {store.stats['computers']}, Edges: {store.stats['edges']}")
    if store.stats.get("duplicates_merged", 0) > 0:
        Logger.debug(f"Duplikate gemerged: {store.stats['duplicates_merged']}")
    if loader.load_stats.get("files_skipped", 0) > 0:
        Logger.info(f"Übersprungen (Cache): {loader.load_stats['files_skipped']}")
    if loader.errors:
        Logger.warn(f"Fehler: {len(loader.errors)}")
    
    # === GRAPH ===
    Logger.section(2, "Graph")
    graph = GraphAnalyzer(store)
    gstats = {}
    if graph.build_graph():
        gstats = graph.get_stats()
        Logger.info(f"Nodes: {gstats['nodes']}, HV-Targets: {gstats['high_value_targets']}")
    else:
        Logger.debug("NetworkX nicht verfügbar")
    
    # === ANALYZE ===
    # Task-Filter
    task_filter = None
    if args.tasks:
        task_filter = set(t.strip().lower() for t in args.tasks.split(","))
        Logger.info(f"Task-Filter: {', '.join(task_filter)}")
    
    tasks_to_run = ALL_TASKS
    if task_filter:
        tasks_to_run = [tc for tc in ALL_TASKS if tc().name.lower() in task_filter]
    
    Logger.section(3, f"Analyse ({len(tasks_to_run)} Tasks)")
    results: Dict[str, FindingCollection] = {}
    start = time()
    
    for tc in tasks_to_run:
        t = tc()
        try:
            fc = t.run(store, graph)
            results[t.output_filename] = fc
            if len(fc) > 0:
                truncated_note = "Ausgabe auf 200 Einträge gekürzt" if getattr(fc, '_truncated', False) else None
                writer.write_findings(t.output_filename, fc, truncated_note, t.priority)
                Logger.success(f"{t.description}: {len(fc)}")
            else:
                Logger.skip(t.description)
        except Exception as e:
            Logger.error(f"{t.description}: {e}")
            Logger.debug(f"Traceback: {e.__class__.__name__}")
            results[t.output_filename] = FindingCollection()
    
    elapsed = time() - start
    
    # === OUTPUT ===
    Logger.section(4, "Reports")
    writer.write_index(results, schema, store.stats, gstats, elapsed)
    writer.write_csv(results)
    writer.write_json(results)
    writer.write_summary(results, schema, store.stats, loader.load_stats)
    
    scorer = RiskScorer()
    score, level, _ = scorer.calculate(results)
    
    # HTML Report
    if args.html:
        html_gen = HTMLReportGenerator()
        html_path = html_gen.generate(out, results, schema, store.stats, score, level)
        Logger.success(f"HTML Report: {html_path}")
    
    Logger.result(score, level)
    Logger.info(f"Fertig in {elapsed:.1f}s")
    Logger.info(f"Output: {out.absolute()}")


if __name__ == "__main__":
    main()
