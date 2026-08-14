"""L2 — integration long-run resource-leak stress tests.

Both tests run STRICTLY under the stress root's ``integration`` subdir
(``D:\\_rubbish_cleaner_stress\\integration\\`` locally) and exercise the REAL
``scanner.scan`` / ``cleaner.clean`` entry points — never mocks of the product
core.  The ``assert_no_escape`` autouse fixture snapshots the stress-root
subtree before/after each test, so every tree, output dir and quarantine dir a
test creates MUST be removed before the test function returns.

``test_ten_rounds_no_leak``
    A growing fake browser-cache tree (5,000 files, +500 per round) is scanned
    and cleaned through 12 sequential rounds: the first 2 are WARM-UP (no
    measurement — lets Python GC / import caches settle), the remaining 10 are
    measured.  After every round we snapshot RSS + the open-handle count via
    psutil (``num_fds`` on POSIX, ``num_handles`` on Windows — never
    ``/proc/self/fd``) and assert the process does not leak: RSS growth over
    the 10 measured rounds stays within 15% of the post-warm-up baseline and
    the handle count stays within a 50 delta.

    The tree is built as a real ``browser-caches`` layout and the scan/clean
    use the ``browser-caches`` category — a directory-level candidate
    (clean_contents), so the retained candidate/disposition rows are O(1)
    regardless of how many junk files a round holds.  This keeps the RSS gate
    measuring the product's own leak behaviour rather than the Python
    allocator water-mark that a monotonic workload of *file-level* candidates
    (e.g. root-temps) inherently ratchets up — which we verified empirically
    grows ~2 KB/file and exceeds the 15% budget with no product leak at all.
    ``psutil.process_iter`` is stubbed to report no running processes so a
    Chrome/Edge on the host cannot gate the browser-caches category away (the
    plan explicitly allows mocking only ``psutil.process_iter``; every other
    part of scanner/cleaner is real).

``test_rounds_with_running_app``
    Repeats the FM4 process-awareness gate: every round mocks
    ``psutil.process_iter`` to report a running chrome-like process and runs
    the cleaner against a browser-caches candidate.  The gate must hold under
    repetition — 0 files deleted, the category listed as skipped, and the
    skip message naming Chrome + the browser-caches category printed every
    round.
"""

from __future__ import annotations

import contextlib
import csv
import gc
import io
import os
import shutil
import time
from pathlib import Path
from typing import Optional
from unittest import mock

import psutil
import pytest

from scripts import cleaner, scanner

# L2 has two deliberately fixed profiles.  CI is intentionally small enough
# to leave headroom inside its 150-second in-process budget; ``local`` keeps
# the original deep soak workload.  Do not add numeric environment overrides:
# reproducible profiles are the point of this regression test.
_L2_PROFILES = {
    "ci": {"warm_up": 2, "measured": 5, "start_files": 100, "file_increment": 25},
    "local": {"warm_up": 2, "measured": 10, "start_files": 5000, "file_increment": 500},
}
_L2_TOTAL_BUDGET_SECONDS = 150.0
_L2_CI_PER_ROUND_BUDGET_SECONDS = 15.0

# Junk files are aged 10 days so they pass the scanner's 7-day cutoff and the
# cleaner's delete-time temp-age recheck (a fresh file would be skipped).
_AGED_DAYS = 10

# Leak limits (Oracle Finding 3: psutil RSS sampling noise + GC timing make
# tighter bounds flaky in CI; Metis Finding 7: handle count must stay flat).
_RSS_GROWTH_LIMIT = 0.15
_FD_DELTA_LIMIT = 50

_GATE_ROUNDS = 5

_CANDIDATE_COLUMNS = ("Category", "Risk", "Path", "SizeBytes", "FileCount", "Action")


def _open_handle_count() -> int:
    """Cross-platform open-handle count via psutil, never /proc/self/fd.

    ``num_fds`` exists on POSIX; Windows psutil has no ``num_fds`` attribute,
    so we fall back to ``num_handles`` there.  Any failure degrades to 0.
    """
    process = psutil.Process()
    for name in ("num_fds", "num_handles"):
        getter = getattr(process, name, None)
        if getter is None:
            continue
        try:
            return int(getter())
        except (NotImplementedError, psutil.Error, OSError):
            continue
    return 0


def _snapshot() -> tuple[int, int]:
    """Return (rss_bytes, open_handles) for the current process."""
    rss = int(psutil.Process().memory_info().rss)
    return rss, _open_handle_count()


def _l2_profile() -> tuple[str, dict[str, int]]:
    """Return the fixed L2 profile, rejecting ambiguous CI configuration."""
    name = os.environ.get("STRESS_L2_PROFILE", "local").strip().lower()
    if name not in _L2_PROFILES:
        raise ValueError(
            "STRESS_L2_PROFILE must be exactly 'ci' or 'local', "
            f"not {name!r}"
        )
    return name, _L2_PROFILES[name]


def _remove_round_audited(round_dir: Path) -> None:
    """Remove one owned round and fail loudly if any entry remains.

    ``round_dir`` is always an immediate child created by this test beneath
    ``rounds_dir``.  ``shutil.rmtree(ignore_errors=True)`` used to hide a
    failed teardown and leave the next round to inherit stale artefacts.
    """
    if not round_dir.exists():
        return
    errors: list[str] = []

    def onerror(operation, path, excinfo) -> None:
        error = excinfo[1]
        errors.append(
            f"{getattr(operation, '__name__', operation)}({path}): "
            f"{type(error).__name__}: {error}"
        )

    shutil.rmtree(round_dir, onerror=onerror)
    if round_dir.exists():
        residuals = sorted(str(path.relative_to(round_dir)) for path in round_dir.rglob("*"))
        errors.append("residuals=" + repr(residuals))
    if errors:
        raise AssertionError("round teardown failed: " + "; ".join(errors))


def _aged_file(path: Path, days_old: int) -> Path:
    path.write_bytes(b"junk-" + path.name.encode("utf-8"))
    stamp = time.time() - days_old * 86400
    os.utime(path, (stamp, stamp))
    return path


def _browser_cache_dir(tree: Path) -> Path:
    """Return the browser-cache dir that ``_scan_browser_caches`` looks for."""
    if os.name == "nt":
        return tree / "Google" / "Chrome" / "User Data" / "Default" / "Cache"
    return tree / "google-chrome" / "Default" / "Cache"


def _build_tree(tree: Path, file_count: int) -> Path:
    """Build a fake browser-cache tree with *file_count* aged junk files.

    ``.tmp`` is deliberately used (not a ``_DATA_SUFFIXES`` member) so the
    directory stays SAFE — an FM7 data-like signature would escalate the
    candidate to CAUTION/quarantine and defeat the clean_contents flow.
    """
    cache = _browser_cache_dir(tree)
    cache.mkdir(parents=True, exist_ok=True)
    for index in range(file_count):
        _aged_file(cache / f"junk-{index:06d}.tmp", _AGED_DAYS)
    return cache


def _volume(root: Path) -> dict[str, object]:
    return {
        "Root": str(root),
        "FreeBytes": 4 * 1024 * 1024 * 1024,
        "TotalBytes": 8 * 1024 * 1024 * 1024,
    }


def _write_candidates(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=_CANDIDATE_COLUMNS, delimiter="|", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class _FakeProc:
    def __init__(self, name: str) -> None:
        self._info = {"name": name}

    @property
    def info(self) -> dict[str, str]:
        return self._info


def _mock_running(module: object, names: list[str]) -> mock._patch:
    return mock.patch.object(module.psutil, "process_iter", return_value=[_FakeProc(name) for name in names])


@contextlib.contextmanager
def _no_running_processes():
    """Stub ``psutil.process_iter`` in BOTH scanner and cleaner to empty."""
    with _mock_running(scanner, []), _mock_running(cleaner, []):
        yield


@pytest.mark.stress
def test_ten_rounds_no_leak(stress_root):
    """Fixed-profile scan+clean rounds: resources stable and teardown audited."""
    profile_name, profile = _l2_profile()
    integration = stress_root / "integration"
    rounds_dir = integration / "leak-rounds"
    rounds_dir.mkdir(parents=True, exist_ok=True)
    total_rounds = profile["warm_up"] + profile["measured"]
    baseline_rss: Optional[int] = None
    baseline_handles: Optional[int] = None
    rss_peaks: list[int] = []
    handle_peaks: list[int] = []
    suite_start = time.monotonic()
    try:
        for round_no in range(1, total_rounds + 1):
            round_start = time.monotonic()
            measured = round_no > profile["warm_up"]
            file_count = profile["start_files"] + (round_no - 1) * profile["file_increment"]
            round_dir = rounds_dir / f"round-{round_no:03d}"
            build_seconds = scan_seconds = clean_seconds = verify_seconds = 0.0
            rss_before = handles_before = rss_after = handles_after = 0
            try:
                build_start = time.monotonic()
                tree = round_dir / "tree"
                cache = _build_tree(tree, file_count)
                build_seconds = time.monotonic() - build_start

                gc.collect()
                rss_before, handles_before = _snapshot()
                scan_start = time.monotonic()
                with _no_running_processes():
                    run_dir = round_dir / "out"
                    scan_result = scanner.scan(
                        "X:", root_path=tree, out_dir=run_dir,
                        categories=["browser-caches"], local_app_data=tree,
                        user_cache_dir=tree, is_user_drive=True,
                    )
                    scan_seconds = time.monotonic() - scan_start
                    clean_start = time.monotonic()
                    candidates_csv = Path(scan_result["run_dir"]) / "candidates.csv"
                    clean_result = cleaner.clean(
                        "X:", volume=_volume(round_dir), candidates_csv=candidates_csv,
                        yes=True, quarantine_dir=round_dir / "quarantine",
                        allow_posix_unlink=True, is_user_drive=True,
                        is_system_drive=False,
                    )
                    clean_seconds = time.monotonic() - clean_start
                verify_start = time.monotonic()
                gc.collect()
                rss_after, handles_after = _snapshot()

                # Real work sanity: a no-op round is not leak coverage.
                assert scan_result["rows"], f"round {round_no}: scanner found no browser-caches candidate"
                assert cache.is_dir(), f"round {round_no}: clean_contents must keep the cache dir"
                survivors = [Path(root) / name for root, _dirs, names in os.walk(cache) for name in names]
                assert not survivors, f"round {round_no}: {len(survivors)} junk files survived cleanup"
                assert clean_result["dispositions"], f"round {round_no}: cleaner recorded no dispositions"
                verify_seconds = time.monotonic() - verify_start

                if not measured:
                    baseline_rss, baseline_handles = rss_after, handles_after
                else:
                    assert baseline_rss is not None and baseline_handles is not None
                    rss_peaks.append(rss_after)
                    handle_peaks.append(handles_after)
                    assert rss_after <= baseline_rss * (1 + _RSS_GROWTH_LIMIT), (
                        f"round {round_no}: RSS grew to {rss_after} bytes vs baseline "
                        f"{baseline_rss} (> {_RSS_GROWTH_LIMIT:.0%})"
                    )
                    for label, value in (("before", handles_before), ("after", handles_after)):
                        assert abs(value - baseline_handles) <= _FD_DELTA_LIMIT, (
                            f"round {round_no}: handle count {label}={value} drifted from "
                            f"baseline {baseline_handles} by more than {_FD_DELTA_LIMIT}"
                        )
            finally:
                teardown_start = time.monotonic()
                _remove_round_audited(round_dir)
                teardown_seconds = time.monotonic() - teardown_start
                round_total = time.monotonic() - round_start
                print(
                    "L2_ROUND_METRICS "
                    f"profile={profile_name} round={round_no} files={file_count} "
                    f"build={build_seconds:.3f}s scan={scan_seconds:.3f}s "
                    f"clean={clean_seconds:.3f}s verify={verify_seconds:.3f}s "
                    f"teardown={teardown_seconds:.3f}s total={round_total:.3f}s "
                    f"rss_before={rss_before} rss_after={rss_after} "
                    f"handles_before={handles_before} handles_after={handles_after}"
                )
                if profile_name == "ci":
                    assert round_total <= _L2_CI_PER_ROUND_BUDGET_SECONDS, (
                        f"round {round_no}: {round_total:.3f}s exceeds fixed CI "
                        f"per-round budget {_L2_CI_PER_ROUND_BUDGET_SECONDS:.0f}s"
                    )
                assert time.monotonic() - suite_start <= _L2_TOTAL_BUDGET_SECONDS, (
                    f"L2 profile {profile_name} exceeded its fixed "
                    f"{_L2_TOTAL_BUDGET_SECONDS:.0f}s budget"
                )

        assert baseline_rss is not None
        assert max(rss_peaks) <= baseline_rss * (1 + _RSS_GROWTH_LIMIT), (
            f"RSS leaked over {profile['measured']} rounds: peak {max(rss_peaks)} "
            f"vs baseline {baseline_rss}"
        )
        assert max(abs(value - baseline_handles) for value in handle_peaks) <= _FD_DELTA_LIMIT, (
            f"open-handle count leaked over {profile['measured']} rounds"
        )
    finally:
        if rounds_dir.exists():
            _remove_round_audited(rounds_dir)


@pytest.mark.stress
def test_rounds_with_running_app(stress_root):
    """FM4 process gate holds under repetition: running app -> 0 deletions."""
    integration = stress_root / "integration"
    rounds_dir = integration / "gate-rounds"
    rounds_dir.mkdir(parents=True, exist_ok=True)
    profile_name, profile = _l2_profile()
    gate_rounds = 3 if profile_name == "ci" else _GATE_ROUNDS
    suite_start = time.monotonic()
    try:
        for round_no in range(1, gate_rounds + 1):
            round_dir = rounds_dir / f"gate-{round_no:03d}"
            round_start = time.monotonic()
            try:
                cache = round_dir / "cache"
                cache.mkdir(parents=True, exist_ok=True)
                files = [_aged_file(cache / f"blob-{index}.tmp", _AGED_DAYS) for index in range(3)]
                candidates = round_dir / "candidates.csv"
                _write_candidates(candidates, [{"Category": "browser-caches", "Risk": "SAFE", "Path": str(cache), "SizeBytes": sum(path.stat().st_size for path in files), "FileCount": len(files), "Action": "delete"}])
                buffer = io.StringIO()
                with _mock_running(cleaner, ["chrome.exe"]):
                    with contextlib.redirect_stdout(buffer):
                        result = cleaner.clean("X:", volume=_volume(round_dir), candidates_csv=candidates, yes=True, quarantine_dir=round_dir / "quarantine", is_user_drive=True, is_system_drive=False)
                out = buffer.getvalue()
                assert all(path.exists() for path in files), f"round {round_no}: FM4 gate must preserve running-app cache files"
                assert cache.exists(), f"round {round_no}: gated cache dir must survive"
                assert result["dispositions"] == [], f"round {round_no}: gated category must not delete anything"
                assert "browser-caches" in result["skipped_categories"], f"round {round_no}: browser-caches must be listed as skipped"
                assert "检测到 Chrome 运行中" in out, f"round {round_no}: FM4 skip message must name the running app"
                assert "浏览器缓存清理已跳过" in out, f"round {round_no}: FM4 skip message must name the category"
            finally:
                _remove_round_audited(round_dir)
                elapsed = time.monotonic() - round_start
                print(f"L2_GATE_METRICS profile={profile_name} round={round_no} total={elapsed:.3f}s")
                assert time.monotonic() - suite_start <= _L2_TOTAL_BUDGET_SECONDS, "L2 running-app gate exceeded 150s budget"
    finally:
        if rounds_dir.exists():
            _remove_round_audited(rounds_dir)
