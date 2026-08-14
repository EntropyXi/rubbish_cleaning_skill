"""L1 — unit stress suite (todo 2 of the rubbish-cleaner-stress-test plan).

Six adversarial-load tests that prove the v2.1.0 safety model holds up at the
edges:

(a) 100k-file scan baseline + generation-time guard;
(b) maximum-depth nesting (OS-capped) — no RecursionError / hang;
(c) maximum-length paths (OS-capped) — scanner finds the correct candidates;
(d) two "drives" cleaned concurrently — no races, no cross-talk;
(e) broken symlink / junction cycle — the junction-aware walk terminates;
(f) disk-full simulation — the free-space probe fails gracefully.

Every test runs STRICTLY inside ``stress_root/unit`` (the shared
``assert_no_escape`` fixture asserts the whole stress-root subtree is
byte-identical afterwards, so each test removes everything it creates before
returning).  All scanner/cleaner calls go through the REAL entry points
(``scanner.scan`` / ``cleaner.clean``); only the disk-full test monkeypatches
the free-space probe (``psutil.disk_usage``).

Path-limit notes: this suite adapts to the OS.  Windows hosts without the
``LongPathsEnabled`` policy are hard-capped at ~260 chars, so deep chains and
long filenames are created to the maximum depth/length the OS accepts; POSIX
hosts get the full ~1000-level chain / ~1050-char path.  Either way the test
asserts the scanner stays robust (completes, correct candidates, no crash,
no infinite loop).
"""

from __future__ import annotations

import concurrent.futures
import errno
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

# Defensive import: repo root must be importable no matter how pytest wires
# sys.path.  The scanner/cleaner modules are imported as a package.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import cleaner, scanner  # noqa: E402
from scripts.lib import platform  # noqa: E402

IS_WINDOWS = platform.IS_WINDOWS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default number of files for the scan baseline; override with
# STRESS_100K_COUNT (e.g. 100000 for a one-off full benchmark, or a smaller
# value for a fast local/CI run).
_DEFAULT_FILE_COUNT = 50000
_CI_FILE_COUNT = 5000
_FILE_SIZE = 2048  # 2 KiB per file via os.write
_GEN_BUDGET_SECONDS = 240.0  # abort generation if the machine is too slow
_SCAN_GATE_SECONDS = 600.0  # scan must finish within 10 minutes
_DEEP_SCAN_GATE_SECONDS = 360.0  # deep-nesting scan must not hang (Windows CI
                                 # long-paths runners legitimately take ~134s to
                                 # scan a 1000-level chain — that is slow I/O,
                                 # not a hang)
_CYCLE_SCAN_GATE_SECONDS = 30.0  # symlink-cycle scan must terminate promptly

# The CI L1 envelope is 240 seconds including its own cleanup.  These tighter
# gates prevent a single test from consuming the 15-minute Actions timeout.
_CI_GEN_BUDGET_SECONDS = 120.0
_CI_SCAN_GATE_SECONDS = 90.0
_CI_DEEP_SCAN_GATE_SECONDS = 90.0
_CI_DEEP_LEVELS = 250

_OLD_MTIME_DELTA = 8 * 24 * 3600  # 8 days: safely older than the 7-day gate
_PAD = b"\0" * _FILE_SIZE


def _ci_profile_enabled() -> bool:
    return os.environ.get("STRESS_L2_PROFILE", "").strip().lower() == "ci"


def _scan_file_count() -> int:
    """Use a fixed L1 input in CI; local one-off benchmarks stay configurable."""
    configured = os.environ.get("STRESS_100K_COUNT")
    if _ci_profile_enabled():
        if configured is not None and configured != str(_CI_FILE_COUNT):
            raise ValueError(
                f"CI requires STRESS_100K_COUNT={_CI_FILE_COUNT}, got {configured!r}"
            )
        return _CI_FILE_COUNT
    return int(configured or _DEFAULT_FILE_COUNT)


def _link_status_path() -> Optional[Path]:
    raw = os.environ.get("RUBBISH_STRESS_STATUS_FILE")
    if not raw:
        return None
    path = Path(raw)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise AssertionError(f"link-status path is not a normal file: {path}")
    if path.parent.is_symlink():
        raise AssertionError(f"link-status parent is a link: {path.parent}")
    return path


def _write_link_status(status: str, kind: Optional[str], reason: Optional[str]) -> None:
    """Atomically persist the single CI coverage status schema, when requested."""
    path = _link_status_path()
    if path is None:
        return
    payload = {
        "status": status,
        "kind": kind,
        "reason": reason,
        "platform": sys.platform,
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _write_file(path: Path, size: int = _FILE_SIZE, backdate: bool = True) -> None:
    """Write ``size`` bytes via ``os.write``; optionally backdate mtime."""
    fd = os.open(os.fspath(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        os.write(fd, _PAD[:size])
    finally:
        os.close(fd)
    if backdate:
        old = time.time() - _OLD_MTIME_DELTA
        os.utime(os.fspath(path), (old, old))


def _remove_tree(path: Path) -> None:
    """Delete a tree with an EXPLICIT stack — never recursion, never os.walk.

    ``os.walk`` delegates per-directory-level via C-level ``yield from``
    recursion (``_walk`` -> ``yield from _walk(...)``), so a ~1000-level chain
    raises ``RecursionError`` — the same stack blowup as ``pathlib.rglob``.
    An explicit ``os.scandir`` stack stays flat at any depth.
    """
    target = os.fspath(path)
    if _is_link_or_reparse(path):
        # os.rmdir removes a directory junction itself; os.unlink removes a
        # POSIX/directory symlink itself.  Never descend through either.
        try:
            os.rmdir(target)
        except OSError:
            os.unlink(target)
        return
    if not os.path.exists(target):
        return
    pending: list[str] = [target]
    directories: list[str] = []
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            continue
        directories.append(current)
        for entry in entries:
            full = os.path.join(current, entry.name)
            try:
                if _is_link_or_reparse(Path(full)):
                    try:
                        os.rmdir(full)
                    except OSError:
                        os.unlink(full)
                elif entry.is_dir(follow_symlinks=False):
                    pending.append(full)
                else:
                    os.unlink(full)
            except OSError:
                continue
    # Children were discovered after their parents, so reversed() is post-order.
    for directory in reversed(directories):
        try:
            os.rmdir(directory)
        except OSError:
            continue


def _scan(root: Path, categories: list[str], run_dir: Path, **extra) -> dict:
    """Run the REAL scanner against ``root`` with a private run dir."""
    kwargs: dict = {
        "root_path": os.fspath(root),
        "categories": categories,
        "run_dir": os.fspath(run_dir),
        "is_user_drive": False,
    }
    kwargs.update(extra)
    return scanner.scan("X:", **kwargs)


def _recycle_root(workdir: Path) -> Path:
    """The platform-specific recycle-bin root used to force a deep walk."""
    if IS_WINDOWS:
        return workdir / "$RECYCLE.BIN"
    return workdir / ".local" / "share" / "Trash"


def _build_deepest_chain(recycle: Path, levels: int) -> tuple[Path, int]:
    """Create a chain of ``levels`` single-char dirs; stop at the OS limit.

    Returns ``(deepest_dir, achieved_depth)``.  Single-level ``mkdir`` is used
    (``Path.mkdir(parents=True)`` recurses and blows the stack on Windows).
    """
    current = recycle
    achieved = 0
    for _ in range(levels):
        nxt = current / "d"
        try:
            nxt.mkdir()
        except OSError:
            break  # OS path-length / depth limit reached — that IS the cap
        current = nxt
        achieved += 1
    return current, achieved


# ---------------------------------------------------------------------------
# (a) 100k-file scan baseline
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_scan_100k_files(stress_root: Path) -> None:
    """Generate a large tree, scan it with the real scanner, record the baseline."""
    count = _scan_file_count()
    ci = _ci_profile_enabled()
    generation_budget = _CI_GEN_BUDGET_SECONDS if ci else _GEN_BUDGET_SECONDS
    scan_budget = _CI_SCAN_GATE_SECONDS if ci else _SCAN_GATE_SECONDS
    workdir = stress_root / "unit" / "scan-100k"
    try:
        temp_dir = workdir / "Temp"
        temp_dir.mkdir(parents=True, exist_ok=False)

        start = time.monotonic()
        for index in range(count):
            if index % 5000 == 0:
                elapsed = time.monotonic() - start
                if elapsed > generation_budget:
                    raise RuntimeError(
                        "generation too slow on this machine: "
                        f"{elapsed:.0f}s elapsed for {index}/{count} files — "
                        "run with STRESS_100K_COUNT=50000 or a faster disk"
                    )
            _write_file(temp_dir / f"f_{index:06d}.tmp")
        gen_elapsed = time.monotonic() - start
        if gen_elapsed > generation_budget:
            raise RuntimeError(
                "generation too slow on this machine: "
                f"{gen_elapsed:.0f}s for {count} files — "
                "run with STRESS_100K_COUNT=50000 or a faster disk"
            )
        print(f"GEN_100K_SECONDS={gen_elapsed:.1f} files={count}")

        scan_start = time.monotonic()
        extra = {} if IS_WINDOWS else {"system_temp_dir": os.fspath(temp_dir)}
        result = _scan(workdir, ["root-temps"], workdir / "out", **extra)
        scan_wall = time.monotonic() - scan_start
        print(f"BASELINE_100K_SCAN_SECONDS={scan_wall:.1f} files={count}")

        assert scan_wall < scan_budget, (
            f"100k scan took {scan_wall:.0f}s (gate {scan_budget}s)"
        )
        # Every backdated file in Temp must be a root-temps candidate.
        assert len(result["rows"]) == count, (
            f"expected {count} root-temps candidates, got {len(result['rows'])}"
        )
        assert {row["Category"] for row in result["rows"]} == {"root-temps"}
    finally:
        _remove_tree(workdir)


# ---------------------------------------------------------------------------
# (b) deep nesting — no RecursionError / hang
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_scan_deep_nesting(stress_root: Path) -> None:
    """Walk the deepest chain the OS allows; the scanner must not blow up.

    Robustness-only assertions: the PLAN's intent is "no RecursionError / no
    hang on a ~1000-level chain", NOT a specific candidate-row count.  The
    scanner's deep walks (``_dir_stats`` / ``_find_dirs_named``) are iterative
    (explicit ``os.scandir`` stack), so a depth-1000 chain must scan cleanly.
    ``is_user_drive=True`` is required so the ``recycle-bin`` category is
    actually evaluated on POSIX (it is a user category — with
    ``is_user_drive=False`` the scanner filters it out and never walks the
    deep tree, which would make this a vacuous no-op test).
    """
    workdir = stress_root / "unit" / "deep-nesting"
    try:
        recycle = _recycle_root(workdir)
        recycle.mkdir(parents=True, exist_ok=True)

        requested_levels = _CI_DEEP_LEVELS if _ci_profile_enabled() else 1000
        deepest, achieved = _build_deepest_chain(recycle, requested_levels)
        print(f"DEEP_ACHIEVED_DEPTH={achieved} requested={requested_levels}")
        assert achieved >= 40, (
            f"deep chain only reached depth {achieved} — the OS limit is far "
            "too low on this host for the test to be meaningful"
        )
        _write_file(deepest / "marker.tmp", size=64)

        start = time.monotonic()
        extra = {"is_user_drive": True}
        if not IS_WINDOWS:
            extra["home_dir"] = os.fspath(workdir)
        result = _scan(workdir, ["recycle-bin"], workdir / "out", **extra)
        elapsed = time.monotonic() - start
        deep_budget = _CI_DEEP_SCAN_GATE_SECONDS if _ci_profile_enabled() else _DEEP_SCAN_GATE_SECONDS
        assert elapsed < deep_budget, (
            f"deep-nesting scan took {elapsed:.0f}s — looks like a hang"
        )
        # Robustness: the scan terminated without exception and returned a
        # well-formed row list.  We deliberately do NOT assert a row count —
        # the recycle-bin directory is an O(1) clean_contents candidate whose
        # single row does not depend on the depth of the chain.
        assert isinstance(result["rows"], list), result["rows"]
    finally:
        _remove_tree(workdir)


# ---------------------------------------------------------------------------
# (c) long paths — scanner handles them and finds the right candidates
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_scan_long_paths(stress_root: Path) -> None:
    """Craft paths at the OS length limit; scan finds the correct candidates."""
    workdir = stress_root / "unit" / "long-paths"
    try:
        if IS_WINDOWS:
            # Windows without LongPathsEnabled caps the total at ~260 chars.
            # Pick the longest single filename the OS accepts.
            temp_dir = workdir / "Temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            long_file: Optional[Path] = None
            for name_len in (250, 240, 230, 220, 210, 200, 180, 160, 140, 120, 100):
                candidate = temp_dir / ("f" * name_len + ".tmp")
                try:
                    _write_file(candidate)
                except OSError:
                    continue
                long_file = candidate
                break
            assert long_file is not None, "OS rejected even a 100-char filename"
            # A long-named directory entry also exercises os.scandir.  The
            # fail-closed session root intentionally adds path components, so
            # adapt this *separate* directory component to the legacy Win32
            # path budget just as we do for the file component above.
            long_dir_created = False
            for name_len in (150, 130, 110, 90, 70, 50, 30, 20):
                try:
                    (temp_dir / ("d" * name_len)).mkdir(exist_ok=True)
                except OSError:
                    continue
                long_dir_created = True
                break
            assert long_dir_created, "OS rejected every long directory component"
            extra: dict = {}
        else:
            # POSIX: nested 200-char dirs push the TOTAL path to ~1050 chars
            # while each component stays under NAME_MAX (255).
            nested = workdir
            for _ in range(4):
                nested = nested / ("d" * 200)
            temp_dir = nested / "Temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            long_file = temp_dir / ("f" * 200 + ".tmp")
            _write_file(long_file)
            extra = {"system_temp_dir": os.fspath(temp_dir)}

        assert long_file is not None
        total_len = len(os.path.abspath(os.fspath(long_file)))
        print(f"LONG_PATH_TOTAL_LEN={total_len}")
        assert total_len >= 200, (
            f"long path only {total_len} chars — too short to be a stress case"
        )

        result = _scan(workdir, ["root-temps"], workdir / "out", **extra)
        assert any(Path(row["Path"]) == long_file for row in result["rows"]), (
            "the long-path file was not found as a root-temps candidate"
        )
        for row in result["rows"]:
            if Path(row["Path"]) == long_file:
                assert row["Category"] == "root-temps"
                assert row["Risk"] == "SAFE"
                assert int(row["SizeBytes"]) == _FILE_SIZE
    finally:
        _remove_tree(workdir)


# ---------------------------------------------------------------------------
# (d) concurrent cleaning of two fake drives — no cross-talk
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_clean_concurrent_drives(stress_root: Path) -> None:
    """Clean two identical fake drives concurrently via a thread pool."""
    workdir = stress_root / "unit" / "concurrent-drives"
    drives = ("A", "B")
    try:
        specs: list[tuple[str, str, str]] = []
        for letter in drives:
            drive_dir = workdir / f"drive{letter}"
            temp_dir = drive_dir / "Temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            for name in ("a.tmp", "b.tmp"):
                _write_file(temp_dir / name)
            extra = {} if IS_WINDOWS else {"system_temp_dir": os.fspath(temp_dir)}
            scan_result = _scan(drive_dir, ["root-temps"], drive_dir / "scan", **extra)
            csv_path = scan_result["run_dir"] + os.sep + "candidates.csv"
            specs.append((letter, csv_path, os.fspath(drive_dir / "quarantine")))

        def clean_one(spec: tuple[str, str, str]) -> tuple[str, dict]:
            letter, csv_path, quarantine_dir = spec
            result = cleaner.clean(
                f"{letter}:",
                candidates_csv=csv_path,
                out_dir=os.fspath(workdir / "clean-out"),
                volume={},
                yes=True,
                quarantine_dir=quarantine_dir,
                allow_posix_unlink=True,
            )
            return letter, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(clean_one, spec) for spec in specs]
            results = [future.result() for future in futures]

        for letter, result in results:
            assert "root-temps" in result["completed_categories"], (
                f"drive {letter} did not complete root-temps"
            )
            assert len(result["dispositions"]) == 2, result["dispositions"]
            # Correct dispositions: both temp files deleted.
            for item in result["dispositions"]:
                assert item["Disposition"] == "OK", item
                # No cross-talk: each drive only touches its OWN tree.
                assert item["Path"].startswith(os.fspath(workdir / f"drive{letter}"))

        # Both drives' junk is gone; nothing spilled into the sibling drive.
        for letter in drives:
            assert not list((workdir / f"drive{letter}" / "Temp").iterdir()), (
                f"drive {letter} temp files not cleaned"
            )
    finally:
        _remove_tree(workdir)


# ---------------------------------------------------------------------------
# (e) broken symlink / junction cycle — walk must terminate
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_broken_symlink_cycle(stress_root: Path) -> None:
    """A symlink cycle (a->b->a) must not make the scanner loop forever."""
    workdir = stress_root / "unit" / "symlink-cycle"
    require_windows = os.environ.get("REQUIRE_WINDOWS_LINK_CYCLE") == "1"
    require_posix = os.environ.get("REQUIRE_POSIX_LINK_CYCLE") == "1"
    required = require_windows if IS_WINDOWS else require_posix
    status = "failed"
    kind: Optional[str] = None
    reason: Optional[str] = None
    try:
        recycle = _recycle_root(workdir)
        recycle.mkdir(parents=True, exist_ok=True)
        loop = recycle / "loop"
        loop.mkdir(exist_ok=True)
        try:
            if IS_WINDOWS:
                # Prefer a true junction on Windows.  It requires no developer
                # mode on hosted runners and points back into this owned leaf.
                created = subprocess.run(
                    ["cmd", "/d", "/c", "mklink", "/J", os.fspath(loop / "a"), os.fspath(loop)],
                    capture_output=True, text=True, check=False,
                )
                if created.returncode == 0 and _is_link_or_reparse(loop / "a"):
                    kind = "junction"
                else:
                    # Some Windows filesystems reject junctions; directory
                    # symlink is the documented fallback when developer mode
                    # or elevated privilege is available.
                    (loop / "a").symlink_to(".", target_is_directory=True)
                    kind = "symlink"
            else:
                (loop / "a").symlink_to(".", target_is_directory=True)
                kind = "symlink"
        except (OSError, NotImplementedError) as error:
            reason = f"cannot create a symlink/junction cycle: {type(error).__name__}: {error}"
            status = "skipped"
            _write_link_status(status, kind, reason)
            if required:
                pytest.fail(reason)
            pytest.skip(reason)

        # A real file at the top level so the walk has a genuine candidate.
        _write_file(recycle / "real.tmp", size=128)
        print(f"SYMLINK_CYCLE_CREATED=True kind={kind}")

        start = time.monotonic()
        # is_user_drive=True: recycle-bin is a POSIX user category, so with
        # is_user_drive=False the scanner filters it out and the walk would
        # never touch the symlink cycle (making the test vacuous on POSIX).
        extra = {"is_user_drive": True}
        if not IS_WINDOWS:
            extra["home_dir"] = os.fspath(workdir)
        result = _scan(workdir, ["recycle-bin"], workdir / "out", **extra)
        elapsed = time.monotonic() - start
        assert elapsed < _CYCLE_SCAN_GATE_SECONDS, (
            f"symlink-cycle scan took {elapsed:.0f}s — the walk did not terminate"
        )
        # The cycle was not followed: the only candidate is the recycle root
        # itself; the loop's symlinks contributed nothing.
        assert len(result["rows"]) == 1, result["rows"]
        assert result["rows"][0]["Category"] == "recycle-bin"
        status = "executed"
    finally:
        _write_link_status(status, kind, reason)
        _remove_tree(workdir)


# ---------------------------------------------------------------------------
# (f) disk full — graceful failure, no crash, no partial output
# ---------------------------------------------------------------------------


@pytest.mark.stress
def test_disk_full_graceful(stress_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing free-space probe must fail the scan gracefully.

    The scanner's free-space check is ``psutil.disk_usage`` (scanner.py, in the
    ``root_path`` branch, before any output is written).  A real disk-full
    condition surfaces there as ``OSError(ENOSPC)`` — the scan must raise a
    clean, message-carrying error and must NOT have produced any partial or
    corrupt output.
    """
    workdir = stress_root / "unit" / "disk-full"
    try:
        temp_dir = workdir / "Temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        _write_file(temp_dir / "a.tmp")

        out_dir = workdir / "out"

        def disk_full_probe(_path: object) -> object:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(scanner.psutil, "disk_usage", disk_full_probe)

        with pytest.raises(OSError) as excinfo:
            _scan(workdir, ["root-temps"], out_dir)
        assert "No space left on device" in str(excinfo.value), excinfo.value
        # The probe runs BEFORE run-dir creation, so no partial output exists.
        assert not out_dir.exists(), "scan wrote partial output before failing"
    finally:
        _remove_tree(workdir)
