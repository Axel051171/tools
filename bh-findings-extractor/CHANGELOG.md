# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.0] - 2026-01-31

### Added
- **Diff Mode** (`--diff OLD NEW`) - Compare two reports to track remediation progress
- **HTML Reports** (`--html`) - Professional Bootstrap 5 reports for management
- **Task Filter** (`--tasks`) - Run only specific security checks
- **Quiet Mode** (`-q`) - Minimal output for scripting
- **Verbose Mode** (`-v`) - Debug output
- **Force Reload** (`--force`) - Ignore cache
- **Colored Output** - ANSI colors for better terminal readability
- **6 New Security Findings:**
  - RBCD (Resource-Based Constrained Delegation)
  - Shadow Admins (GenericAll on DA without membership)
  - GPO Abuse (Write permissions on GPOs)
  - Nested Groups (Indirect DA membership chains)
  - Stale Computers (Inactive >90 days)
  - Pre-Windows 2000 Compatible Access Group

### Changed
- Total security checks increased from 21 to 27
- Improved CLI with examples in `--help`
- Better error messages and progress indication

## [4.0.0] - 2026-01-31

### Added
- **Severity Folders** - Output organized by CRITICAL/HIGH/MEDIUM/LOW/INFO
- **Truncation Notices** - Clear indication when output is limited

### Fixed
- Version consistency across all outputs
- Deterministic output (reproducible for diffing)
- `unknown_enabled` now only counts users (not computers/groups)
- Domain Admins detection from MemberOf edges (CE format)
- DCSync detection with pattern-matching fallback

## [3.9.0] - 2026-01-31

### Added
- **Append Mode** (`--append`) - Incremental scanning with cache
- **Cache System** - `_cache.json` persists loaded data

## [3.8.0] - 2026-01-31

### Added
- **Multiple Inputs** (`-i dir1 -i dir2`) - Combine data from multiple scans
- **Smart Merge** - SID-based object merging

## [3.7.0] - 2026-01-31

### Added
- **Item-Level Error Handling** - Bad items skip, don't crash
- **Error Categories** - Separate errors vs warnings
- **Load Statistics** - Detailed reporting

## [3.6.0] - 2026-01-31

### Added
- GPO and OU loading for Legacy format
- Extended DCSync edge types
- Schema warnings for incomplete data

## [3.5.0] - 2026-01-31

### Added
- Initial public release
- 21 security checks
- SID-based deduplication
- CSV/JSON export
- Attack path analysis with NetworkX
