"""L4 — safety-fuzz harness for the rubbish-cleaner skill (THE CORE stress proof).

Deterministic PRNG (seed via ``FUZZ_SEED``, default 42) generates N random
"worlds" (``FUZZ_ITERS``, default 500; CI runs 20) under the stress root
``<RUBBISH_STRESS_ROOT>/fuzz/``.  Each world is a bounded random file tree
(50-300 files/dirs, names with unicode/spaces/dots/long components <= 200
chars, depth <= 20, deterministic content) with scanner-recognizable
candidates planted at the real scanner's fixed path-map locations (browser /
app / dev / IDE caches, root temp / log / suspicious / duplicate-archive /
empty-dirs, recycle bin, user-temp, thumbnail cache) plus random filler that
must never be touched.

Design (per the plan):

* **Scanner-first ownership mapping (Oracle Finding 1):** the REAL scanner runs
  on each world FIRST (before any clean).  The candidate rows are read from
  ``scan()['rows']`` (each row: ``Category``/``Risk``/``Path``/``Action``).
  Candidates whose ``Category`` has entries in
  ``scanner.CATEGORY_OWNER_PROCESSES`` are eligible for process-ownership; a
  random subset of THOSE is marked "process-owned" and a mocked
  ``psutil.process_iter`` returns the corresponding REAL owner stems (e.g.
  browser-caches -> chrome/msedge, dev-caches -> pip/npm/python/node).  A
  directory is NEVER marked process-owned by its generated name alone — only
  via the scanner's real category mapping (so the FM4 gate is genuinely
  exercised and not vacuously satisfied).
* **Operation tracking (Oracle Finding 5):** every op records its type
  (scan/clean/quarantine) and target, so post-condition (e) is asserted only
  when a ``clean_contents`` execution actually ran.
* **FM7 risk-field access (Oracle Finding 6):** post-condition (f) reads the
  scanner's returned ``rows`` ``Risk`` field and asserts any candidate whose
  directory content is data-like (contains .db/.sqlite/.index/.dat) has
  ``Risk == "CAUTION"``, never ``"SAFE"``.
* **Wall-clock budgets (Metis F4):** per-iteration budget (default 30 s) and a
  total run budget (default 25 min); exceeding either aborts with the seed +
  iteration + op trace so the run is reproducible.

Six post-conditions are asserted after EVERY world:
(a) every non-candidate file is byte-identical to its pre-run snapshot;
(b) every quarantined item exists intact under the quarantine dir;
(c) files under a process-owned dir are NEVER deleted;
(d) nothing outside the fuzz root changed (autouse ``assert_no_escape`` sentinel
    over the whole stress-root subtree enforces this);
(e) ``clean_contents`` never removed its target directory;
(f) any data-like candidate has ``Risk == "CAUTION"`` (FM7).

On any violation the failure is raised with seed + iteration + the operation
trace so it can be reproduced with ``FUZZ_SEED`` / ``FUZZ_ITERS``.

Bounds: total files per world <= 300, total bytes per world <= 5 MB,
depth <= 20, filename <= 200 chars.  Every world is removed in ``finally`` so
the stress-root sentinel stays pristine.
"""

from __future__ import annotations

import hashlib
import os
import random
import time
from pathlib import Path
from typing import Any, Optional

import pytest

from . import conftest as stress_conftest
from scripts import cleaner, scanner
from scripts.lib import platform as lib_platform

IS_WINDOWS = lib_platform.IS_WINDOWS

_DRIVE = "FUZZ"

# --------------------------------------------------------------------------- #
# Configuration (env-overridable) and hard bounds
# --------------------------------------------------------------------------- #

DEFAULT_SEED = 42
DEFAULT_ITERS = 500
PER_ITER_BUDGET_S = 30.0
TOTAL_BUDGET_S = 25 * 60.0

MAX_FILES = 300
MAX_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 20
MAX_NAME_LEN = 200
_MAX_PATH = 240 if IS_WINDOWS else 1024
_CLEANUP_ATTEMPTS = 3
_CLEANUP_RETRY_DELAY_S = 0.1

# Mirrors the scanner's FM7 data-suffix set exactly (Oracle Finding 6).
_DATA_SUFFIXES = scanner._DATA_SUFFIXES
_FM7_SUFFIX_CHOICES = [".db", ".sqlite", ".index", ".dat"]

# Categories the generator actually plants, per platform.  Only categories the
# real scanner evaluates on the current platform are planted (POSIX never scans
# app-caches / root-logs / root-suspicious / duplicate-archives).
if IS_WINDOWS:
    _PLANTED_CATEGORIES = [
        "root-temps",
        "root-logs",
        "root-suspicious",
        "duplicate-archives",
        "empty-dirs",
        "recycle-bin",
        "app-caches",
        "browser-caches",
        "dev-caches",
        "ide-caches",
        "crash-dumps",
        "user-temp",
        "thumbnail-cache",
    ]
else:
    _PLANTED_CATEGORIES = [
        "root-temps",
        "recycle-bin",
        "browser-caches",
        "dev-caches",
        "ide-caches",
        "crash-dumps",
        "thumbnail-cache",
        "user-temp",
    ]

# Unique-basename cache dirs eligible to carry the FM7 data-signature.  The
# basename matters: quarantined targets are moved to ``quarantine/<basename>``
# and an EEXIST collision would turn the move into MOVE_FAILED.
if IS_WINDOWS:
    _DATA_LIKE_SITES = [
        ("appdata_local/pip/cache", "dev-caches"),
        ("appdata_local/Google/Chrome/User Data/Default/GPUCache", "browser-caches"),
        ("appdata_local/JetBrains/PyCharm/caches", "ide-caches"),
    ]
else:
    _DATA_LIKE_SITES = [
        ("user-cache/pip", "dev-caches"),
        ("user-cache/google-chrome/Default/GPUCache", "browser-caches"),
        ("user-cache/JetBrains/PyCharm/caches", "ide-caches"),
    ]

_RESERVED = {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)} | {
    "con", "prn", "aux", "nul",
}

# Filler name tokens: unicode, spaces, dots, emoji, multi-script.
_NAME_TOKENS = [
    "data", "user", "tmp", "session", "run", "item", "cache", "Cache", "temp",
    "Temp", "缓存", "临时", "数据", "测试", "图片", "资料", "ü", "π", "日本語",
    "한국어", "русский", "🗑", "🧹", "☃", "·", "a", "b", "c",
]


def _fail(seed: int, iteration: int, op_trace: list[str], message: str) -> None:
    """Raise a reproducible failure carrying seed + iteration + op trace."""
    trace = "\n".join(f"  op[{i}] {op}" for i, op in enumerate(op_trace))
    raise AssertionError(
        "L4 fuzz safety invariant violated\n"
        f"seed={seed} iteration={iteration}\n"
        f"op_trace:\n{trace}\n"
        f"violation: {message}"
    )


class FixtureCleanupError(RuntimeError):
    """Deterministic, reproducible failure from the fuzz fixture teardown."""

    def __init__(
        self,
        seed: int,
        iteration: int,
        op_trace: list[str],
        attempts: list[str],
        residuals: list[str],
        *,
        body_error: Optional[BaseException] = None,
    ) -> None:
        self.seed = seed
        self.iteration = iteration
        self.op_trace = list(op_trace)
        self.attempts = list(attempts)
        self.residuals = list(residuals)
        self.body_error = body_error
        trace = "\n".join(f"  op[{index}] {entry}" for index, entry in enumerate(op_trace))
        attempt_text = "\n".join(f"  {entry}" for entry in attempts) or "  <none>"
        residual_text = "\n".join(f"  {entry}" for entry in residuals) or "  <none>"
        context = " while preserving a test-body failure" if body_error is not None else ""
        super().__init__(
            f"test-fixture residual{context}\n"
            f"seed={seed} iteration={iteration}\n"
            f"op_trace:\n{trace or '  <none>'}\n"
            f"cleanup_attempts:\n{attempt_text}\n"
            f"no_follow_residuals:\n{residual_text}"
        )


def _check_budget(
    seed: int,
    iteration: int,
    op_trace: list[str],
    iter_start: float,
    total_start: float,
) -> None:
    now = time.monotonic()
    if now - iter_start > PER_ITER_BUDGET_S:
        _fail(
            seed, iteration, op_trace,
            f"per-iteration wall-clock budget exceeded "
            f"({now - iter_start:.1f}s > {PER_ITER_BUDGET_S:.0f}s)",
        )
    if now - total_start > TOTAL_BUDGET_S:
        _fail(
            seed, iteration, op_trace,
            f"total run wall-clock budget exceeded "
            f"({now - total_start:.1f}s > {TOTAL_BUDGET_S:.0f}s)",
        )


def _volume(world: Path) -> dict[str, Any]:
    return {"Root": str(world), "FreeBytes": 1 << 40, "TotalBytes": 1 << 42}


def _content(seed: int, iteration: int, rel: str, size: int) -> bytes:
    """Deterministic content bytes derived from (seed, iteration, rel path)."""
    digest = hashlib.sha256(f"{seed}:{iteration}:{rel}".encode("utf-8")).digest()
    return (digest * ((size // len(digest)) + 1))[:size]


def _sanitize_name(name: str) -> str:
    name = "".join(ch for ch in name if ch not in '<>:"/\\|?*' and ord(ch) >= 32)
    name = name.rstrip(" .")
    if not name or name in {".", ".."}:
        return ""
    if name.casefold() in _RESERVED:
        name += "x"
    return name


def _random_name(rng: random.Random, max_len: int) -> str:
    for _ in range(16):
        name = "".join(rng.choice(_NAME_TOKENS) for _ in range(rng.randint(1, 3)))
        if rng.random() < 0.15 and max_len >= 80:
            pad = rng.randint(20, min(140, max_len - len(name) - 1))
            if pad >= 10:
                name += "x" * pad
        if rng.random() < 0.25:
            name = rng.choice(["", " ", "."]) + name + rng.choice(["", " ", "."])
        name = _sanitize_name(name)
        if name and len(name) <= max_len:
            return name
    return "item"


def _file_name(rng: random.Random) -> str:
    base = _random_name(rng, 60)
    ext = rng.choice(["bin", "txt", "log", "tmp", "dat", "db", "dll", "exe",
                      "zip", "png", "json", "xml", "index", "dat", "cache"])
    return f"{base}.{ext}"


def _dir_name(rng: random.Random, depth: int) -> str:
    # Oracle Finding 1: random cache-like names deep in the tree MUST NOT be
    # candidates by name alone — only scanner path-map locations count.
    if rng.random() < 0.3:
        return rng.choice(["Cache", "cache", "temp", "Temp", "tmp", "TMP"])
    return _random_name(rng, 200 if depth <= 1 else 60)


def _short(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                   for _ in range(rng.randint(4, 10)))


def _path_ok(path: Path) -> bool:
    return len(os.fspath(path)) <= _MAX_PATH


def _make_process_iter(stems: list[str]):
    """Return a mock psutil.process_iter whose processes carry ``stems``."""

    class _FakeProc:
        def __init__(self, name: str):
            self._info = {"name": name}

        @property
        def info(self) -> dict[str, str]:
            return self._info

    def _iter(_attrs=None):
        return [_FakeProc(stem) for stem in stems]

    return _iter


def _try_write_file(
    rng: random.Random,
    seed: int,
    iteration: int,
    world: Path,
    parent: Path,
    files: dict[str, dict[str, Any]],
) -> Optional[Path]:
    for _ in range(8):
        name = _file_name(rng)
        path = parent / name
        if not _path_ok(path) or path.exists():
            continue
        rel = path.relative_to(world).as_posix()
        size = rng.randint(64, 4096)
        content = _content(seed, iteration, rel, size)
        try:
            path.write_bytes(content)
        except OSError:
            continue
        files[str(path)] = {
            "rel": rel,
            "digest": hashlib.sha256(content).hexdigest(),
            "size": size,
        }
        return path
    return None


def _plant_filler(
    rng: random.Random,
    seed: int,
    iteration: int,
    world: Path,
    files: dict[str, dict[str, Any]],
    filler_target: int,
) -> None:
    """Random filler tree (non-candidate) under a single root-level dir."""
    root_dir = world / _random_name(rng, 40)
    for _ in range(16):  # guard against colliding with a planted root-level dir
        try:
            root_dir.mkdir()
            break
        except FileExistsError:
            root_dir = world / _random_name(rng, 40)
    if not root_dir.is_dir():
        root_dir = world / f"filler-{_short(rng)}"
        root_dir.mkdir()
    created = 0
    stack = [(root_dir, 1)]
    while stack and created < filler_target and len(files) < MAX_FILES:
        parent, depth = stack.pop(rng.randrange(len(stack)))
        if depth >= MAX_DEPTH:
            for _ in range(rng.randint(1, 3)):
                if created >= filler_target or len(files) >= MAX_FILES:
                    break
                if _try_write_file(rng, seed, iteration, world, parent, files):
                    created += 1
            continue
        if rng.random() < 0.55:
            child = parent / _dir_name(rng, depth)
            if not _path_ok(child):
                continue
            try:
                child.mkdir()
            except OSError:
                continue
            stack.append((child, depth + 1))
        else:
            if _try_write_file(rng, seed, iteration, world, parent, files):
                created += 1
    if created == 0:
        _try_write_file(rng, seed, iteration, world, root_dir, files)


def _generate_world(
    rng: random.Random,
    seed: int,
    iteration: int,
    world: Path,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build one deterministic world: planted candidates + random filler.

    Returns ``(files, planted_categories)`` where ``files`` maps absolute path
    -> ``{"rel", "digest", "size"}`` for every file in the world.
    """
    files: dict[str, dict[str, Any]] = {}
    planted: set[str] = set()
    old = time.time() - 30 * 86400  # aged > 7-day window for temp age gates

    def add(rel_dir: str, n_range: tuple[int, int], *, aged: bool = False,
            data_suffix: Optional[str] = None,
            fname: Optional[str] = None) -> Path:
        directory = world.joinpath(*rel_dir.split("/"))
        directory.mkdir(parents=True, exist_ok=True)
        count = rng.randint(*n_range)
        for i in range(count):
            if data_suffix is not None and i == 0:
                name = f"d0{data_suffix}"
            elif fname is not None:
                name = fname.format(i=i)
            else:
                name = f"f{i}.bin"
            path = directory / name
            rel = path.relative_to(world).as_posix()
            size = rng.randint(64, 2048)
            content = _content(seed, iteration, rel, size)
            path.write_bytes(content)
            if aged:
                os.utime(path, (old, old))
            files[str(path)] = {
                "rel": rel,
                "digest": hashlib.sha256(content).hexdigest(),
                "size": size,
            }
        return directory

    # --- FM7 data-like site (unique basename, direct data child, < 20 entries)
    data_site_rel, data_cat = rng.choice(_DATA_LIKE_SITES)
    data_suffix = rng.choice(_FM7_SUFFIX_CHOICES)
    add(data_site_rel, (2, 4), data_suffix=data_suffix)
    planted.add(data_cat)

    # --- cache categories
    cache_sites: list[tuple[str, str]] = []
    if IS_WINDOWS:
        cache_sites = [
            ("appdata_local/Google/Chrome/User Data/Default/Cache", "browser-caches"),
            ("appdata_local/Google/Chrome/User Data/Default/Code Cache", "browser-caches"),
            ("appdata_local/Microsoft/Edge/User Data/Default/Cache", "browser-caches"),
            ("appdata_local/pip/cache", "dev-caches"),
            ("appdata_local/npm-cache", "dev-caches"),
            ("home/.cache/torch", "dev-caches"),
            ("home/.cache/opencode", "dev-caches"),
            ("appdata_local/JetBrains/PyCharm/caches", "ide-caches"),
            ("appdata_roaming/Zotero/Zotero/Profiles/%s/cache2" % _short(rng), "ide-caches"),
            ("appdata_local/CrashDumps", "crash-dumps"),
        ]
    else:
        cache_sites = [
            ("user-cache/google-chrome/Default/Cache", "browser-caches"),
            ("user-cache/google-chrome/Default/Code Cache", "browser-caches"),
            ("user-cache/microsoft-edge/Default/Cache", "browser-caches"),
            ("user-cache/pip", "dev-caches"),
            ("user-cache/npm", "dev-caches"),
            ("user-cache/torch", "dev-caches"),
            ("user-cache/opencode", "dev-caches"),
            ("user-cache/JetBrains/PyCharm/caches", "ide-caches"),
            ("home/.config/Code/Cache", "ide-caches"),
        ]
    for rel_dir, category in cache_sites:
        if rel_dir == data_site_rel:
            continue  # already planted with the data signature
        add(rel_dir, (2, 4))
        planted.add(category)

    if IS_WINDOWS:
        # user-temp: aged files directly in local-app-data Temp
        add("appdata_local/Temp", (2, 5), aged=True)
        planted.add("user-temp")
    else:
        # POSIX user-temp scans direct files of the user-cache dir.
        add("user-cache", (1, 3), aged=True)
        planted.add("user-temp")

    # --- root-relative categories (Windows-only for the POSIX-absent ones)
    if IS_WINDOWS:
        # NOTE: NTFS is case-insensitive — "temp" would collide with "Temp",
        # so only distinct names are planted here.
        for name in ("Temp", "tmp"):
            add(name, (1, 4), aged=True)
        planted.add("root-temps")
    else:
        add("Temp", (2, 5), aged=True)  # scanned via system_temp_dir
        planted.add("root-temps")

    if IS_WINDOWS:
        add("anaconda3/pkgs/cache", (2, 4))
        add("Ubisoft Game Launcher/cache", (2, 4))
        add(f"Wegame/{_short(rng)}/cache", (2, 4))
        add(f"WeiXin/xwechat_files/{_short(rng)}/cache", (2, 4))
        planted.add("app-caches")
        # app-caches empty-dir candidates under a Steam library
        (world / "SteamLibrary/steamapps/common" / _short(rng)).mkdir(parents=True)
        # root-logs
        for i in range(rng.randint(2, 4)):
            path = world / f"rootlog{i}.log"
            rel = path.relative_to(world).as_posix()
            content = _content(seed, iteration, rel, rng.randint(64, 1024))
            path.write_bytes(content)
            files[str(path)] = {"rel": rel, "digest": hashlib.sha256(content).hexdigest(), "size": len(content)}
        planted.add("root-logs")
        # root-suspicious (CAUTION -> quarantine)
        for i in range(rng.randint(1, 2)):
            path = world / f"suspicious{i}.dll"
            rel = path.relative_to(world).as_posix()
            content = _content(seed, iteration, rel, rng.randint(64, 512))
            path.write_bytes(content)
            files[str(path)] = {"rel": rel, "digest": hashlib.sha256(content).hexdigest(), "size": len(content)}
        planted.add("root-suspicious")
        # duplicate-archives: zip + sibling directory
        for i in range(rng.randint(1, 2)):
            base = _short(rng)
            (world / base).mkdir()
            inner = world / base / "payload.txt"
            rel = inner.relative_to(world).as_posix()
            content = _content(seed, iteration, rel, 256)
            inner.write_bytes(content)
            files[str(inner)] = {"rel": rel, "digest": hashlib.sha256(content).hexdigest(), "size": len(content)}
            archive = world / f"{base}.zip"
            rel_a = archive.relative_to(world).as_posix()
            content_a = _content(seed, iteration, rel_a, 512)
            archive.write_bytes(content_a)
            files[str(archive)] = {"rel": rel_a, "digest": hashlib.sha256(content_a).hexdigest(), "size": len(content_a)}
        planted.add("duplicate-archives")
        # empty-dirs
        for i in range(rng.randint(1, 2)):
            (world / f"empty{i}").mkdir()
        planted.add("empty-dirs")
        # recycle bin
        add("$RECYCLE.BIN", (1, 3))
        planted.add("recycle-bin")
        # thumbnail cache files (SAFE .db file rows by design)
        add("appdata_local/Microsoft/Windows/Explorer", (1, 3), fname="thumbcache_{i:016d}.db")
        planted.add("thumbnail-cache")
    else:
        # POSIX recycle bin under the fake home
        add("home/.local/share/Trash", (1, 3))
        planted.add("recycle-bin")
        # POSIX thumbnail cache
        add("user-cache/thumbnails", (1, 3), fname="thumbcache_{i:016d}.db")
        planted.add("thumbnail-cache")
        # POSIX crash-dumps under posix_crash_dir
        add("crash", (1, 3))
        planted.add("crash-dumps")

    # --- filler: 50-300 total entries, bounded
    # Iterative directory count (explicit os.scandir stack).  pathlib.rglob
    # delegates per-level via C-level recursive yield-from and would raise
    # RecursionError on the deep-nesting worlds; symlinks are not followed.
    dir_count = 0
    stack = [os.fspath(world)]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    dir_count += 1
                    stack.append(os.path.join(directory, entry.name))
            except OSError:
                continue
    entries_now = len(files) + dir_count
    target_entries = rng.randint(50, 300)
    filler_target = max(10, min(target_entries - entries_now, MAX_FILES - len(files)))
    _plant_filler(rng, seed, iteration, world, files, filler_target)

    return files, sorted(planted)


def _assert_bounds(world: Path, files: dict[str, dict[str, Any]], seed: int,
                   iteration: int, op_trace: list[str]) -> None:
    total_bytes = sum(meta["size"] for meta in files.values())
    if len(files) > MAX_FILES:
        _fail(seed, iteration, op_trace,
              f"bounds: {len(files)} files > {MAX_FILES} per world")
    if total_bytes > MAX_BYTES:
        _fail(seed, iteration, op_trace,
              f"bounds: {total_bytes} bytes > {MAX_BYTES} per world")
    for meta in files.values():
        parts = Path(meta["rel"]).parts
        depth = len(parts) - 1
        if depth > MAX_DEPTH:
            _fail(seed, iteration, op_trace,
                  f"bounds: {meta['rel']} depth {depth} > {MAX_DEPTH}")
        if len(parts[-1]) > MAX_NAME_LEN:
            _fail(seed, iteration, op_trace,
                  f"bounds: filename {len(parts[-1])} chars > {MAX_NAME_LEN}")


def _scan_world(rng: random.Random, world: Path, run_dir: Path,
                categories: list[str], process_iter) -> dict[str, Any]:
    return scanner.scan(
        _DRIVE,
        root_path=world,
        volume=_volume(world),
        run_dir=run_dir,
        categories=categories,
        is_user_drive=True,
        home_dir=world / "home",
        local_app_data=world / "appdata_local",
        app_data=world / "appdata_roaming",
        user_cache_dir=world / "user-cache",
        system_temp_dir=world / "Temp",
        posix_crash_dir=world / "crash",
        process_iter=process_iter,
    )


def _dir_has_data_file(path: str, sample_cap: int = 20) -> bool:
    """Mirror the scanner's FM7 content-signature check (single level)."""
    if not os.path.isdir(path):
        return False
    try:
        with os.scandir(path) as iterator:
            for index, entry in enumerate(iterator):
                if index >= sample_cap:
                    break
                if os.path.splitext(entry.name)[1].casefold() in _DATA_SUFFIXES:
                    return True
    except OSError:
        return False
    return False


def _check_fm7(rows: list[dict[str, Any]], seed: int, iteration: int,
               op_trace: list[str]) -> None:
    """Post-condition (f): data-like candidates are CAUTION, never SAFE."""
    for row in rows:
        path = row["Path"]
        if os.path.isdir(path) and _dir_has_data_file(path):
            if row["Risk"] != "CAUTION":
                _fail(
                    seed, iteration, op_trace,
                    f"(f) FM7 risk-field: data-like candidate {path} has "
                    f"Risk={row['Risk']!r} (expected CAUTION, never SAFE)",
                )


def _select_owned(rng: random.Random, rows: list[dict[str, Any]]):
    """Scanner-first ownership: pick candidates whose category owns processes."""
    owner_map = scanner.CATEGORY_OWNER_PROCESSES
    eligible = [row for row in rows if owner_map.get(row["Category"])]
    count = rng.randint(0, min(3, len(eligible)))
    chosen = rng.sample(eligible, count) if count else []
    stems = sorted({spec for row in chosen for spec in owner_map[row["Category"]]})
    # A non-watched stem makes the mock realistic without gating extra categories.
    if stems and rng.random() < 0.5:
        stems.append("explorer.exe" if IS_WINDOWS else "dock")
    return chosen, stems


def _random_subset(rng: random.Random, items: list[str], force_full_prob: float = 0.2) -> list[str]:
    items = list(items)
    if not items:
        return []
    if rng.random() < force_full_prob:
        return items
    return rng.sample(items, rng.randint(1, len(items)))


def _execute_op(
    kind: str,
    rng: random.Random,
    seed: int,
    iteration: int,
    op_trace: list[str],
    world: Path,
    run_dir: Path,
    quarantine_dir: Path,
    planted_categories: list[str],
    process_iter,
    all_rows: list[dict[str, Any]],
    quarantined: list[tuple[str, bool, str]],
    clean_contents_ran: list[str],
) -> None:
    """Run one randomized op through the REAL scanner/cleaner entry points."""
    if kind == "scan":
        cats = _random_subset(rng, planted_categories)
        result = _scan_world(rng, world, run_dir, cats, process_iter)
        all_rows.extend(result["rows"])
        _check_fm7(result["rows"], seed, iteration, op_trace)
        op_trace.append(
            f"scan(categories=[{','.join(cats)}], rows={len(result['rows'])})"
        )
        return

    consumed = scanner._load_existing_rows(run_dir / "candidates.csv")
    if kind == "quarantine":
        caution = sorted({row["Category"] for row in consumed if row["Risk"] == "CAUTION"})
        cats = _random_subset(rng, caution) if caution else []
    else:
        present = sorted({row["Category"] for row in consumed})
        cats = _random_subset(rng, present) if present else []

    if not cats:
        op_trace.append(f"{kind}(categories=[], no-op)")
        return

    # POSIX deletion coverage must be explicit: a randomized false value would
    # only exercise the product's intentional SKIP_POSIX_UNSAFE default.
    allow_unlink = True
    result = cleaner.clean(
        _DRIVE,
        volume=_volume(world),
        candidates_csv=run_dir / "candidates.csv",
        quarantine_dir=quarantine_dir,
        yes=True,
        categories=cats,
        allow_posix_unlink=allow_unlink,
        process_iter=process_iter,
        is_user_drive=True,
        is_system_drive=False,
    )

    row_by_path = {row["Path"]: row for row in consumed}
    execution_map = cleaner._CATEGORY_EXECUTION_MAP
    ok_count = 0
    quarantine_count = 0
    for disp in result["dispositions"]:
        target = disp["Path"]
        disposition = disp["Disposition"]
        if disposition == "QUARANTINED":
            quarantine_count += 1
            base = os.path.basename(target)
            was_dir = (quarantine_dir / base).is_dir()
            quarantined.append((target, was_dir, base))
        elif disposition == "OK":
            ok_count += 1
            row = row_by_path.get(target)
            if row and (
                row["Action"] == "clean_contents"
                or (
                    row["Action"] == "delete"
                    and execution_map.get(row["Category"]) == "clean_contents"
                    and os.path.isdir(target)
                )
            ):
                clean_contents_ran.append(target)
    op_trace.append(
        f"{kind}(categories=[{','.join(cats)}], allow_posix_unlink={allow_unlink}, "
        f"ok={ok_count}, quarantined={quarantine_count})"
    )


def _check_postconditions(
    pre_files: dict[str, dict[str, Any]],
    all_rows: list[dict[str, Any]],
    owned_rows: list[dict[str, Any]],
    quarantined: list[tuple[str, bool, str]],
    clean_contents_ran: list[str],
    quarantine_dir: Path,
    seed: int,
    iteration: int,
    op_trace: list[str],
) -> None:
    # Files that may legitimately disappear: candidate file rows + every file
    # under any candidate directory row (clean_contents / quarantine / delete).
    removable: set[str] = set()
    for row in all_rows:
        base = row["Path"].rstrip(os.sep) + os.sep
        for abs_path in pre_files:
            if abs_path == row["Path"] or abs_path.startswith(base):
                removable.add(abs_path)

    # (a) every non-candidate file is byte-identical to its pre-run snapshot.
    for abs_path, meta in pre_files.items():
        if abs_path in removable:
            continue
        path = Path(abs_path)
        if not path.is_file():
            _fail(seed, iteration, op_trace,
                  f"(a) non-candidate file disappeared: {abs_path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta["digest"]:
            _fail(seed, iteration, op_trace,
                  f"(a) non-candidate file mutated: {abs_path}")

    # (c) files under a process-owned dir are NEVER deleted.
    for row in owned_rows:
        base = row["Path"].rstrip(os.sep) + os.sep
        for abs_path, meta in pre_files.items():
            if abs_path.startswith(base):
                path = Path(abs_path)
                if not path.is_file():
                    _fail(seed, iteration, op_trace,
                          f"(c) process-owned file deleted: {abs_path} "
                          f"(owner-category {row['Category']})")
                if hashlib.sha256(path.read_bytes()).hexdigest() != meta["digest"]:
                    _fail(seed, iteration, op_trace,
                          f"(c) process-owned file mutated: {abs_path} "
                          f"(owner-category {row['Category']})")

    # (b) every quarantined item exists intact under the quarantine dir.
    for target, was_dir, base in quarantined:
        dest = quarantine_dir / base
        if was_dir:
            if not dest.is_dir():
                _fail(seed, iteration, op_trace,
                      f"(b) quarantined directory missing: {dest}")
            prefix = target.rstrip(os.sep) + os.sep
            for abs_path, meta in pre_files.items():
                if abs_path.startswith(prefix):
                    moved = dest / Path(abs_path).relative_to(target)
                    if not moved.is_file():
                        _fail(seed, iteration, op_trace,
                              f"(b) quarantined file missing: {moved}")
                    if hashlib.sha256(moved.read_bytes()).hexdigest() != meta["digest"]:
                        _fail(seed, iteration, op_trace,
                              f"(b) quarantined file corrupted: {moved}")
        else:
            if not dest.is_file():
                _fail(seed, iteration, op_trace,
                      f"(b) quarantined file missing: {dest}")
            meta = pre_files.get(target)
            if meta and hashlib.sha256(dest.read_bytes()).hexdigest() != meta["digest"]:
                _fail(seed, iteration, op_trace,
                      f"(b) quarantined file corrupted: {dest}")

    # (e) clean_contents never removed its target directory.
    for target in clean_contents_ran:
        if not os.path.isdir(target):
            _fail(seed, iteration, op_trace,
                  f"(e) clean_contents removed its target dir: {target}")


def _no_follow_residual(path: Path) -> str:
    """Describe a residual without walking through a link or junction."""
    if not os.path.lexists(os.fspath(path)):
        return f"{path}|MISSING"
    try:
        info = os.lstat(os.fspath(path))
    except OSError as error:
        return f"{path}|LSTAT_ERROR|{type(error).__name__}|errno={error.errno}|winerror={getattr(error, 'winerror', None)}"
    if os.path.islink(os.fspath(path)) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stress_conftest, "_REPARSE_POINT", 0x400)
    ):
        try:
            return f"{path}|LINK|target={os.readlink(os.fspath(path))!r}"
        except OSError as error:
            return f"{path}|LINK_ERROR|{type(error).__name__}|errno={error.errno}|winerror={getattr(error, 'winerror', None)}"
    if path.is_dir():
        return f"{path}|DIR\n{stress_conftest._snapshot_no_follow(path)}"
    return f"{path}|FILE|size={info.st_size}"


def _cleanup_iteration(
    fuzz_root: Path,
    world: Path,
    run_dir: Path,
    quarantine_dir: Path,
    seed: int,
    iteration: int,
    op_trace: list[str],
) -> None:
    """Delete the three owned iteration children with bounded diagnostics.

    Every attempt re-validates lexical direct-child ownership and no-follow
    ancestors in ``cleanup_owned_direct_child``.  It intentionally never
    deletes ``fuzz_root`` or a parent and never suppresses a residual.
    """
    targets = (
        (world, f"{iteration:04d}"),
        (run_dir, f"run-{iteration:04d}"),
        (quarantine_dir, f"quarantine-{iteration:04d}"),
    )
    attempts: list[str] = []
    residuals: list[str] = []
    for target, expected_name in targets:
        for attempt in range(1, _CLEANUP_ATTEMPTS + 1):
            try:
                stress_conftest.cleanup_owned_direct_child(
                    fuzz_root, target, expected_name
                )
                attempts.append(f"target={target} attempt={attempt} result=ok")
            except Exception as error:
                attempts.append(
                    f"target={target} attempt={attempt} error={type(error).__name__} "
                    f"errno={getattr(error, 'errno', None)} "
                    f"winerror={getattr(error, 'winerror', None)} detail={error}"
                )
            if not os.path.lexists(os.fspath(target)):
                break
            residuals.append(_no_follow_residual(target))
            if attempt < _CLEANUP_ATTEMPTS:
                time.sleep(_CLEANUP_RETRY_DELAY_S)
        if os.path.lexists(os.fspath(target)):
            residuals.append(f"FINAL|{_no_follow_residual(target)}")
    if residuals and any(entry.startswith("FINAL|") for entry in residuals):
        raise FixtureCleanupError(seed, iteration, op_trace, attempts, residuals)


@pytest.mark.stress
def test_fuzz_safety_invariants_hold(stress_root):
    """Deterministic safety fuzz: N random worlds x random ops, 6 invariants."""
    seed = int(os.environ.get("FUZZ_SEED", str(DEFAULT_SEED)))
    iters = int(os.environ.get("FUZZ_ITERS", str(DEFAULT_ITERS)))
    global PER_ITER_BUDGET_S, TOTAL_BUDGET_S
    PER_ITER_BUDGET_S = float(os.environ.get("FUZZ_PER_ITER_BUDGET_S", str(PER_ITER_BUDGET_S)))
    TOTAL_BUDGET_S = float(os.environ.get("FUZZ_TOTAL_BUDGET_S", str(TOTAL_BUDGET_S)))

    fuzz_root = Path(stress_root) / "fuzz"
    fuzz_root.mkdir(parents=True, exist_ok=True)
    total_start = time.monotonic()

    for iteration in range(iters):
        iter_start = time.monotonic()
        op_trace: list[str] = []
        rng = random.Random(f"{seed}:{iteration}")
        world = fuzz_root / f"{iteration:04d}"
        run_dir = fuzz_root / f"run-{iteration:04d}"
        quarantine_dir = fuzz_root / f"quarantine-{iteration:04d}"
        try:
            world.mkdir(parents=True, exist_ok=False)
            pre_files, planted_categories = _generate_world(rng, seed, iteration, world)
            _assert_bounds(world, pre_files, seed, iteration, op_trace)

            # Mapping scan FIRST (scanner-first): read rows, never guess.
            mapping = _scan_world(rng, world, run_dir, planted_categories,
                                  _make_process_iter([]))
            rows = mapping["rows"]
            _check_fm7(rows, seed, iteration, op_trace)

            # Ownership mapping from the REAL rows + REAL owner stems.
            owned_rows, owned_stems = _select_owned(rng, rows)
            process_iter = _make_process_iter(owned_stems)

            all_rows = list(rows)
            quarantined: list[tuple[str, bool, str]] = []
            clean_contents_ran: list[str] = []

            n_ops = rng.randint(10, 30)
            for op_index in range(n_ops):
                _check_budget(seed, iteration, op_trace, iter_start, total_start)
                if op_index == 0:
                    kind = "scan"
                else:
                    roll = rng.random()
                    kind = "scan" if roll < 0.35 else ("clean" if roll < 0.75 else "quarantine")
                _execute_op(
                    kind, rng, seed, iteration, op_trace, world, run_dir,
                    quarantine_dir, planted_categories, process_iter, all_rows,
                    quarantined, clean_contents_ran,
                )

            _check_postconditions(
                pre_files, all_rows, owned_rows, quarantined,
                clean_contents_ran, quarantine_dir, seed, iteration, op_trace,
            )
            print(f"[fuzz] world {iteration:04d}/{iters} ok "
                  f"({n_ops} ops, {len(owned_stems)} owned-stem(s), "
                  f"{len(quarantined)} quarantine(s))")
        except BaseException as body_error:
            # Keep the original product/assertion failure as the causal chain,
            # but never hide an independently failed fixture cleanup.
            try:
                _cleanup_iteration(
                    fuzz_root, world, run_dir, quarantine_dir,
                    seed, iteration, op_trace,
                )
            except FixtureCleanupError as cleanup_error:
                raise FixtureCleanupError(
                    seed, iteration, op_trace,
                    cleanup_error.attempts, cleanup_error.residuals,
                    body_error=body_error,
                ) from body_error
            raise
        else:
            _cleanup_iteration(
                fuzz_root, world, run_dir, quarantine_dir,
                seed, iteration, op_trace,
            )


def _regression_iteration_paths(stress_root: Path, iteration: int) -> tuple[Path, Path, Path, Path]:
    fuzz_root = stress_root / "fuzz"
    return (
        fuzz_root,
        fuzz_root / f"{iteration:04d}",
        fuzz_root / f"run-{iteration:04d}",
        fuzz_root / f"quarantine-{iteration:04d}",
    )


@pytest.mark.stress
def test_fuzz_cleanup_removes_only_iteration_children(stress_root: Path) -> None:
    """Regression: a normal iteration tree is removed with no root residual."""
    fuzz_root, world, run_dir, quarantine_dir = _regression_iteration_paths(stress_root, 9101)
    for target in (world, run_dir, quarantine_dir):
        (target / "nested").mkdir(parents=True)
        (target / "nested" / "payload.bin").write_bytes(b"payload")
    _cleanup_iteration(fuzz_root, world, run_dir, quarantine_dir, 42, 9101, ["regression-normal"])
    assert all(not os.path.lexists(os.fspath(path)) for path in (world, run_dir, quarantine_dir))


@pytest.mark.stress
def test_fuzz_cleanup_does_not_follow_link_target(stress_root: Path) -> None:
    """Regression: a link iteration target is unlinked, never recursively walked."""
    fuzz_root, world, run_dir, quarantine_dir = _regression_iteration_paths(stress_root, 9102)
    outside_parent = stress_root / "unit"
    outside = outside_parent / "fuzz-link-target"
    outside.mkdir()
    payload = outside / "must-survive.txt"
    payload.write_text("outside", encoding="utf-8")
    try:
        try:
            world.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"cannot create stress link regression fixture: {error}")
        run_dir.mkdir()
        quarantine_dir.mkdir()
        _cleanup_iteration(fuzz_root, world, run_dir, quarantine_dir, 42, 9102, ["regression-link"])
        assert not os.path.lexists(os.fspath(world))
        assert payload.read_text(encoding="utf-8") == "outside"
    finally:
        stress_conftest.cleanup_owned_direct_child(
            outside_parent, outside, "fuzz-link-target"
        )


@pytest.mark.stress
def test_fuzz_cleanup_reports_retries_and_residuals(
    stress_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a failing delete is never silently swallowed."""
    fuzz_root, world, run_dir, quarantine_dir = _regression_iteration_paths(stress_root, 9103)
    for target in (world, run_dir, quarantine_dir):
        target.mkdir()
    original_cleanup = stress_conftest.cleanup_owned_direct_child

    def deny_cleanup(*_args, **_kwargs) -> None:
        raise PermissionError(13, "simulated cleanup denial")

    monkeypatch.setattr(stress_conftest, "cleanup_owned_direct_child", deny_cleanup)
    with pytest.raises(FixtureCleanupError) as excinfo:
        _cleanup_iteration(fuzz_root, world, run_dir, quarantine_dir, 42, 9103, ["regression-denied"])
    error = excinfo.value
    assert len(error.attempts) == 9
    assert any("PermissionError" in attempt for attempt in error.attempts)
    assert any(residual.startswith("FINAL|") for residual in error.residuals)
    monkeypatch.setattr(stress_conftest, "cleanup_owned_direct_child", original_cleanup)
    _cleanup_iteration(fuzz_root, world, run_dir, quarantine_dir, 42, 9103, ["regression-cleanup"])


@pytest.mark.stress
def test_fuzz_cleanup_rejects_root_parent_escape_and_link_ancestor(stress_root: Path) -> None:
    """Regression: validation fails closed before unsafe cleanup is attempted."""
    fuzz_root, world, _run_dir, _quarantine_dir = _regression_iteration_paths(stress_root, 9104)
    outside_parent = stress_root / "unit"
    outside = outside_parent / "fuzz-cleanup-outside"
    outside.mkdir()
    link_parent = fuzz_root / "link-parent"
    try:
        with pytest.raises(stress_conftest.StressIsolationError):
            stress_conftest.cleanup_owned_direct_child(fuzz_root, stress_root, stress_root.name)
        with pytest.raises(stress_conftest.StressIsolationError):
            stress_conftest.cleanup_owned_direct_child(fuzz_root, outside, outside.name)
        try:
            link_parent.symlink_to(outside_parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            # The root/parent/escape checks above remain meaningful on Windows
            # hosts that cannot create developer-mode links.
            pass
        else:
            with pytest.raises(stress_conftest.StressIsolationError):
                stress_conftest.cleanup_owned_direct_child(
                    link_parent, link_parent / "child", "child"
                )
    finally:
        if os.path.lexists(os.fspath(link_parent)):
            stress_conftest.cleanup_owned_direct_child(fuzz_root, link_parent, "link-parent")
        stress_conftest.cleanup_owned_direct_child(
            outside_parent, outside, "fuzz-cleanup-outside"
        )
