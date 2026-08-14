# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Hardened the isolated stress-test harness: every run now uses an owned leaf
  under Python's system temporary directory, validates cleanup targets without
  following links, and verifies both the test root and a controlled sibling
  canary after every test. Fuzz cleanup retries briefly on transient Windows
  locks and reports the seed, iteration, trace, residuals, and original error
  instead of silently ignoring a failed teardown.
- Bounded CI stress verification with deterministic L1/L2/L4 profiles and a
  540-second internal deadline. Long-run rounds now emit timing/resource
  metrics and clean their own artifacts immediately, preventing accumulation
  from masking a timeout or leak.

### Testing

- Windows CI now requires an actual junction or symbolic-link cycle scan and
  records a structured coverage status; local hosts without link privileges
  still skip that one scenario explicitly. The stress workflow remains
  separate from the 3-platform functional matrix, but is a merge gate for
  this repository.

## [v2.1.2] - 2026-08-04

Patch release fixing an empty-dirs classification defect found by the CD-drive
validation (2026-08-04): the empty-directories scanner now skips reserved/system
directories that must never be reported as junk candidates.

### Fixed

- Empty-dirs reserved/system-directory exclusion: `_scan_empty_dirs`
  (`scripts/scanner.py`) now skips `Program Files`, `Program Files (x86)`,
  `inetpub`, `XboxGames`, and `Windows` (case-insensitive), in addition to the
  existing `$Recycle.Bin`, `System Volume Information`, and `.claude`
  exclusions. Flagging a user install-root or an OS-reserved directory as junk
  was a wrong signal — even though `remove_if_empty` + `os.rmdir` remain
  fail-safe (SKIP_LOCKED). Genuinely empty user directories (e.g. a root-level
  `junk` folder) are still flagged.

### Testing

- Added FM16 (empty-dirs skips reserved/system directories) regression coverage
  in [`tests/test_safety_fm.py`](tests/test_safety_fm.py) (60 assertions total across all suites).

## [v2.1.1] - 2026-08-04

Patch release fixing two classification defects found by the C-drive real-scan
validation (run C-20260804-190536-482080).

### Fixed

- Root-logs system-owner exclusion: root-level `.log`/`*_install.log` files owned by the
  OS (SYSTEM on Windows via the `FILE_ATTRIBUTE_SYSTEM` flag or an unreadable owner ACL,
  uid 0 on POSIX) are no longer candidates — an elevated run must never delete
  `C:\DumpStack.log`-style system files. Two-tier Windows check
  (`scripts/scanner.py` `_is_system_owned`); a Hidden-only user file is still flagged.
- User-temp installer/uninstaller exemption: installer artifacts are exempt from the
  user-temp category even past the 7-day gate — exact suffix (`.exe`/`.msi`/`.msu`/`.msp`/`.cab`)
  or a whole-word installer keyword (`setup`/`install`/`unins`/`uninstall`/`updater`) in the
  casefolded filename. Protects `英雄联盟卸载.exe`, `antigravity-ide-download.exe`, and
  `vscode-inno-updater-*.log`; `install.log` is exempted by design. Generic temp junk
  (`.tmp`/`.dll`/`.node`/`.bat`/`.json`) stays eligible.

### Testing

- Added FM14 (root-logs system-owner exclusion, incl. the Hidden-only no-over-exclusion
  edge) and FM15 (user-temp installer exemption) regression coverage in
  [`tests/test_safety_fm.py`](tests/test_safety_fm.py) (59 assertions total across all suites).

## [v2.1.0] - 2026-08-03

Safety hardening release. A post-mortem of a cross-volume quarantine incident
identified nine failure modes (FM1–FM9, full analysis in
[references/incident-rca.md](references/incident-rca.md)); all are fixed and
covered by regression tests.

### Added

- Conservative default posture (FM0): without `-Categories`, scan/clean processes only age-gated temp files,
  logs, and verified-empty directories; app-owned caches and crash dumps are opt-in.
- `--dry-run` preview on both [`scripts/scanner.py`](scripts/scanner.py) and [`scripts/cleaner.py`](scripts/cleaner.py):
  prints a per-file preview of every deletion without touching any file.
- Process-awareness gate (FM4): categories whose owner application is running (Chrome, Steam, WeChat, ...)
  are skipped with a clear message and never auto-killed; `--close-apps` prompts the user to close them instead.
- Fixed-drive filter (FM8): only fixed local drives are eligible — removable, CD/DVD, and network drives are excluded.

### Changed

- POSIX unlink is default-skip (FM1): files that cannot be safely unlinked are recorded as `SKIP_POSIX_UNSAFE`
  without probing; opt in explicitly with `--allow-posix-unlink`.
- Quarantine runs the same lock probe as delete (FM2): a locked file is never moved.
- The elevated system batch is generated from approved candidate rows only, applies a `forfiles` age gate,
  and restarts the `wuauserv` service afterwards (FM3).
- Dual-action execution (FM5): cache categories use `clean_contents` (files inside deleted, directory kept);
  `empty-dirs` uses `remove_if_empty` (only verified-empty directories).
- Taxonomy mutual exclusion (FM6): categories no longer overlap on the same paths.
- Data-signature validation (FM7): a static-map cache directory whose sampled content does not match the
  expected signature is escalated to `CAUTION` and quarantined, never `clean_contents`'d in place.
- Same-volume quarantine default (FM9): quarantined files move under `X:\.rubbish-quarantine\run-<timestamp>\`
  on the source volume — cross-volume `EXDEV` `MOVE_FAILED` failures are eliminated. [`scripts/report.py`](scripts/report.py)
  consumes the same resolution instead of assuming a Desktop quarantine.

### Fixed

- FM1–FM9 safety findings from the [incident RCA](references/incident-rca.md): POSIX flock gap, quarantine lock
  bypass, elevated batch force-delete, missing process awareness, directory-vs-file mismatch, category overlap,
  stale path map, removable drives, and cross-volume quarantine `EXDEV`.

### Testing

- Added FM0–FM9 plus FM13 regression coverage in [`tests/test_safety_fm.py`](tests/test_safety_fm.py)
  (57 assertions total across all suites).

## [v2.0.0] - 2026-08-01

### Changed

- Ported the scan → approve → clean → verify → report workflow from PowerShell to Python 3.10+.
- Added the cross-platform `psutil` runtime dependency; `pywin32` is gated to Windows for UAC and Task Scheduler integration.
- Replaced the PowerShell test harness with six pytest suites plus a dependency-free compileall/fallback runner.
- Unified Windows, Ubuntu, and macOS CI with Python 3.10–3.12 compatibility checks and read-only scanner smoke tests.
- Preserved quarantine-first cleanup, junction/symlink safety, seven-day freshness gates, checkpoint/resume, and native Windows/POSIX lock semantics.

## [v1.1.0] - 2026-08-01

### Added

- Added multi-drive batch execution with `-Drives` for [`scripts/scanner.py`](scripts/scanner.py), [`scripts/cleaner.py`](scripts/cleaner.py), and [`scripts/report.py`](scripts/report.py). The optional `scanner.py -Parallel` path scans multiple drives concurrently, and scan and cleanup deliver category-level progress; cleanup remains sequential and approval-gated.
- Added scan and cleanup checkpoints with `-Resume`, plus policy-based scheduling through [`scripts/schedule.py`](scripts/schedule.py) and the [`references/policies/`](references/policies/) profiles.

### Changed

- Added fixed-drive resolution and platform-specific default paths through [`scripts/lib/platform.py`](scripts/lib/platform.py), so supported Windows, Linux, and macOS hosts use the appropriate drive and runtime semantics.
- Updated [`scripts/lib/core.py`](scripts/lib/core.py) for POSIX link handling and locked-item behavior.

### Fixed

- Prevented duplicate root-temp evaluation and normalized system temp roots while preserving repeated path separators.
- Kept the production scripts parseable in Windows PowerShell 5.1.

### Testing

- Made pytest/fallback pass/fail results explicit in [`tests/test_runner.py`](tests/test_runner.py) and [`.github/workflows/test.yml`](.github/workflows/test.yml).
- Expanded CI to a Windows, Ubuntu, and macOS matrix, including the Windows PowerShell 5.1 test entry point.

## [v1.0.0] - 2026-07-31

### Added

- Repository scaffolded as the `rubbish-cleaner` skill and created on GitHub via the CLI (`gh`); development follows a feature-branch git workflow.
- [SKILL.md](SKILL.md): skill core with progressive disclosure.
- `scripts/lib/core.py`: safety function library (classification, quarantine, reporting helpers).
- Core scripts:
  - `scripts/scanner.py`: read-only drive scan + junk classification.
  - `scripts/cleaner.py`: approval-gated safe cleanup with quarantine.
  - `scripts/report.py`: post-clean verification + summary report.
- References: [junk-taxonomy.md](references/junk-taxonomy.md), [safety-rules.md](references/safety-rules.md), [per-app-path-map.md](references/per-app-path-map.md).
- Dual-mode test suite: dependency-free fallback runner (`tests/test_runner.py`) and six pytest files.
- [install.py](scripts/install.py): one-command installer; the skill is installed into the Claude Code, Codex and opencode skill directories.

### Changed

- [README.md](README.md) rewritten agent-first: quick start via agents, slash-command usage, manual install de-emphasized.
- English-only README cleanup: mixed-language headings and comments fixed.
- Bilingual README: added [README_zh.md](README_zh.md) mirror with a language switcher.
- Added a "Limitations & Roadmap" section to the README.
- Repository renamed to `rubbish_cleaning_skill`.

Key files: [SKILL.md](SKILL.md), [README.md](README.md), [install.py](scripts/install.py), [CHANGELOG](CHANGELOG.md).
