"""Fail-closed isolation for the explicit stress-test suite.

The default suite continues to ignore ``tests/stress`` through
``tests/conftest.py``.  When this suite is selected explicitly, every product
path is derived from a session-owned leaf directly below Python's resolved
system temporary directory.  A caller may supply an *empty* direct child of
that directory as ``RUBBISH_STRESS_ROOT``; it remains caller-owned and the
fixture creates and later removes only a unique session child inside it.

Snapshots deliberately cover the session root and a controlled sibling
canary.  They do not claim to monitor an entire disk or temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

import pytest


GUARD_CONTENT = "rubbish-cleaner-stress-sentinel-do-not-delete\n"
_SUBDIRS = ("unit", "integration", "fuzz", "__sentinel")
_OWNER_NAME = ".rubbish-stress-owner.json"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class StressIsolationError(RuntimeError):
    """Refuse an unsafe stress-root or cleanup request without deleting it."""


@dataclass(frozen=True)
class _StressSession:
    root: Path
    cleanup_parent: Path
    canary: Path
    temp_parent: Path
    session_id: str
    token: str


_ACTIVE_SESSION: Optional[_StressSession] = None


def _absolute(path: Union[os.PathLike[str], str]) -> Path:
    """Return an absolute lexical path without silently accepting relatives."""
    value = os.fspath(path)
    if not value or not os.path.isabs(value):
        raise StressIsolationError(f"stress path must be non-empty and absolute: {value!r}")
    return Path(os.path.abspath(value))


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = os.lstat(os.fspath(path))
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_or_child(parent: Path, child: Path) -> bool:
    """Use both ``relative_to`` and ``commonpath`` for containment checks."""
    try:
        child.relative_to(parent)
        return os.path.commonpath((os.fspath(parent), os.fspath(child))) == os.fspath(parent)
    except (ValueError, OSError):
        return False


def _temp_parent() -> Path:
    raw = _absolute(tempfile.gettempdir())
    resolved = raw.resolve(strict=True)
    if not resolved.is_dir() or _is_link_or_reparse(resolved):
        raise StressIsolationError(f"Python system temp is not a safe directory: {resolved}")
    return resolved


def _assert_no_link_ancestors(parent: Path, child: Path, *, include_leaf: bool) -> None:
    """Reject symlink/junction/reparse components from ``parent`` to ``child``."""
    parent = _absolute(parent)
    child = _absolute(child)
    if not _same_or_child(parent, child):
        raise StressIsolationError(f"path escapes validated parent: {child} not below {parent}")
    relative = child.relative_to(parent)
    current = parent
    for index, part in enumerate(relative.parts):
        current = current / part
        if index == len(relative.parts) - 1 and not include_leaf:
            break
        if not os.path.lexists(os.fspath(current)):
            break
        if _is_link_or_reparse(current):
            raise StressIsolationError(f"link/reparse ancestor is forbidden: {current}")
        if current != child and not current.is_dir():
            raise StressIsolationError(f"non-directory ancestor is forbidden: {current}")


def _validate_stress_root(configured_root: Union[os.PathLike[str], str]) -> Tuple[Path, Path]:
    """Validate one direct-child stress container/leaf below Python temp.

    Returns ``(temp_parent, lexical_candidate)``.  The candidate may be absent
    (the CI case), but it can never be the temp root, a filesystem root, a
    relative path, or a path reached through a link/reparse ancestor.
    """
    temp_parent = _temp_parent()
    candidate = _absolute(configured_root)
    if candidate == temp_parent or candidate.parent != temp_parent:
        raise StressIsolationError(
            "RUBBISH_STRESS_ROOT must be a non-root direct child of Python "
            f"system temp ({temp_parent}), got {candidate}"
        )
    resolved_candidate = candidate.resolve(strict=False)
    if not _same_or_child(temp_parent, resolved_candidate) or resolved_candidate == temp_parent:
        raise StressIsolationError(f"stress root resolves outside system temp: {candidate}")
    _assert_no_link_ancestors(temp_parent, candidate, include_leaf=True)
    if candidate.exists() and not candidate.is_dir():
        raise StressIsolationError(f"stress root is not a directory: {candidate}")
    return temp_parent, candidate


def _write_owner_marker(root: Path, session_id: str, token: str) -> None:
    marker = root / _OWNER_NAME
    payload = {
        "schema": 1,
        "session_id": session_id,
        "token": token,
        "pid": os.getpid(),
        "created_at": time.time(),
    }
    fd = os.open(os.fspath(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")


def _owner_matches(root: Path, session: _StressSession) -> bool:
    marker = root / _OWNER_NAME
    if _is_link_or_reparse(marker):
        return False
    try:
        with marker.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == 1
        and payload.get("session_id") == session.session_id
        and payload.get("token") == session.token
    )


def _create_canary(temp_parent: Path, session_id: str, token: str) -> Path:
    """Create an owned sibling canary that is never passed to product code."""
    canary = temp_parent / f"external-canary-{uuid.uuid4().hex}"
    canary.mkdir(mode=0o700)
    _assert_no_link_ancestors(temp_parent, canary, include_leaf=True)
    _write_owner_marker(canary, session_id, token)
    (canary / "ordinary.txt").write_text(GUARD_CONTENT, encoding="utf-8")
    (canary / "empty-directory").mkdir()
    try:
        (canary / "link-entry").symlink_to("ordinary.txt")
    except (OSError, NotImplementedError):
        # Some Windows developer sessions cannot create links.  The canary
        # still protects files and empty directories on those hosts.
        pass
    return canary


def _create_owned_session_root() -> _StressSession:
    """Create a fail-closed owned leaf or owned child of an empty override."""
    override = os.environ.get("RUBBISH_STRESS_ROOT")
    if override:
        temp_parent, candidate = _validate_stress_root(override)
        if candidate.exists():
            entries = list(os.scandir(os.fspath(candidate)))
            if entries:
                raise StressIsolationError(
                    "refusing non-empty RUBBISH_STRESS_ROOT without taking ownership: "
                    f"{candidate}"
                )
            session_root = candidate / f"session-{uuid.uuid4().hex}"
            session_root.mkdir(mode=0o700)
            cleanup_parent = candidate
        else:
            candidate.mkdir(mode=0o700)
            session_root = candidate
            cleanup_parent = temp_parent
    else:
        temp_parent = _temp_parent()
        session_root = temp_parent / f"rubbish-stress-{uuid.uuid4().hex}"
        session_root.mkdir(mode=0o700)
        cleanup_parent = temp_parent

    _assert_no_link_ancestors(temp_parent, session_root, include_leaf=True)
    session_id = uuid.uuid4().hex
    token = uuid.uuid4().hex
    _write_owner_marker(session_root, session_id, token)
    session = _StressSession(
        root=session_root,
        cleanup_parent=cleanup_parent,
        canary=_create_canary(temp_parent, session_id, token),
        temp_parent=temp_parent,
        session_id=session_id,
        token=token,
    )
    return session


def _validate_owned_parent(parent: Union[os.PathLike[str], str]) -> Path:
    """Ensure a cleanup parent is an ordinary directory inside this session."""
    if _ACTIVE_SESSION is None:
        raise StressIsolationError("no active stress session owns this cleanup request")
    raw = _absolute(parent)
    root = _ACTIVE_SESSION.root
    resolved = raw.resolve(strict=False)
    if raw == root or not _same_or_child(root, raw) or not _same_or_child(root, resolved):
        raise StressIsolationError(f"cleanup parent is outside the owned session: {raw}")
    _assert_no_link_ancestors(root, raw, include_leaf=True)
    if not raw.is_dir():
        raise StressIsolationError(f"cleanup parent is not an ordinary directory: {raw}")
    return raw


def _validate_direct_child(
    parent: Path, target: Union[os.PathLike[str], str], expected_name: str
) -> Path:
    """Validate a named direct child before every destructive filesystem call."""
    parent = _validate_owned_parent(parent)
    candidate = _absolute(target)
    if not expected_name or candidate.name != expected_name or candidate.parent != parent:
        raise StressIsolationError(
            f"cleanup target must be direct child {expected_name!r} of {parent}, got {candidate}"
        )
    _assert_no_link_ancestors(parent, candidate, include_leaf=False)
    return candidate


def cleanup_owned_direct_child(
    parent: Union[os.PathLike[str], str],
    target: Union[os.PathLike[str], str],
    expected_name: str,
) -> None:
    """Remove one owned direct child without following a link/junction target."""
    candidate = _validate_direct_child(Path(parent), target, expected_name)
    if not os.path.lexists(os.fspath(candidate)):
        return
    info = os.lstat(os.fspath(candidate))
    if stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT):
        try:
            os.unlink(os.fspath(candidate))
        except IsADirectoryError:
            os.rmdir(os.fspath(candidate))
        return
    if stat.S_ISDIR(info.st_mode):
        # ``rmtree`` is invoked only after the target itself was lstat-checked
        # as a normal directory; modern Python uses fd-based no-follow cleanup
        # where available.
        shutil.rmtree(os.fspath(candidate))
        return
    os.unlink(os.fspath(candidate))


def _snapshot_no_follow(root: Path) -> str:
    """Snapshot files, empty directories, and links without traversing links."""
    root = _absolute(root)
    lines: list[str] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(os.fspath(directory)) as iterator:
                entries = list(iterator)
        except OSError as error:
            lines.append(f"{directory.relative_to(root).as_posix()}|DIR_ERROR|{type(error).__name__}:{error.errno}")
            continue
        for entry in entries:
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            try:
                info = os.lstat(entry.path)
            except OSError as error:
                lines.append(f"{rel}|LSTAT_ERROR|{type(error).__name__}:{error.errno}")
                continue
            is_link = stat.S_ISLNK(info.st_mode) or bool(
                getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
            )
            if is_link:
                try:
                    target = os.readlink(entry.path)
                    lines.append(f"{rel}|LINK|{target}")
                except OSError as error:
                    lines.append(f"{rel}|LINK_ERROR|{type(error).__name__}:{error.errno}")
                continue
            if stat.S_ISDIR(info.st_mode):
                lines.append(f"{rel}|DIR")
                stack.append(path)
                continue
            if stat.S_ISREG(info.st_mode):
                try:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    lines.append(f"{rel}|FILE|{digest}|{info.st_size}")
                except OSError as error:
                    lines.append(f"{rel}|FILE_ERROR|{type(error).__name__}:{error.errno}")
                continue
            lines.append(f"{rel}|SPECIAL|{info.st_mode}")
    return "\n".join(sorted(lines))


def _cleanup_session_artifact(session: _StressSession, parent: Path, target: Path) -> None:
    """Remove only an owner-marked root/canary after no-follow validation."""
    parent = _absolute(parent)
    target = _absolute(target)
    if target.parent != parent or not _same_or_child(session.temp_parent, parent):
        raise StressIsolationError(f"session cleanup target escaped validated parent: {target}")
    _assert_no_link_ancestors(session.temp_parent, parent, include_leaf=True)
    _assert_no_link_ancestors(parent, target, include_leaf=True)
    if not _owner_matches(target, session):
        raise StressIsolationError(f"refusing to delete unowned stress artifact: {target}")
    if _is_link_or_reparse(target) or not target.is_dir():
        raise StressIsolationError(f"owned artifact became a link/non-directory: {target}")
    shutil.rmtree(os.fspath(target))


@pytest.fixture(scope="session")
def stress_root():
    """Yield the session-owned stress root and remove only owned artifacts."""
    global _ACTIVE_SESSION
    session = _create_owned_session_root()
    _ACTIVE_SESSION = session
    canary_before: Optional[str] = None
    try:
        for subdir in _SUBDIRS:
            (session.root / subdir).mkdir(exist_ok=False)
        (session.root / "__sentinel" / "guard.txt").write_text(GUARD_CONTENT, encoding="utf-8")
        canary_before = _snapshot_no_follow(session.canary)
        yield session.root
    finally:
        # ``yield`` may be resumed with a test-body exception, so this check
        # belongs in finally rather than after yield.  It is still performed
        # before any owned artifact is removed.
        canary_after = _snapshot_no_follow(session.canary)
        canary_error: Optional[AssertionError] = None
        if canary_before is not None and canary_after != canary_before:
            canary_error = AssertionError(
                "controlled-external-canary mutation detected during stress session\n"
                f"canary={session.canary}\n--- before ---\n{canary_before}\n--- after ---\n{canary_after}"
            )
        cleanup_errors = []
        for parent, target in ((session.temp_parent, session.canary), (session.cleanup_parent, session.root)):
            try:
                _cleanup_session_artifact(session, parent, target)
            except BaseException as error:
                cleanup_errors.append(f"{target}: {type(error).__name__}: {error}")
        _ACTIVE_SESSION = None
        if cleanup_errors:
            raise StressIsolationError(
                "stress fixture refused or failed session teardown; evidence was retained:\n"
                + "\n".join(cleanup_errors)
            )
        if canary_error is not None:
            raise canary_error


@pytest.fixture(autouse=True)
def assert_no_escape(stress_root: Path):
    """Require each test to restore both owned root and controlled canary."""
    if _ACTIVE_SESSION is None:
        raise StressIsolationError("stress session unexpectedly inactive")
    before_root = _snapshot_no_follow(stress_root)
    before_canary = _snapshot_no_follow(_ACTIVE_SESSION.canary)
    yield
    after_root = _snapshot_no_follow(stress_root)
    after_canary = _snapshot_no_follow(_ACTIVE_SESSION.canary)
    failures = []
    if after_root != before_root:
        failures.append(
            "stress-root mutation/residual\n"
            f"root={stress_root}\n--- before ---\n{before_root}\n--- after ---\n{after_root}"
        )
    if after_canary != before_canary:
        failures.append(
            "controlled-external-canary mutation\n"
            f"canary={_ACTIVE_SESSION.canary}\n--- before ---\n{before_canary}\n--- after ---\n{after_canary}"
        )
    assert not failures, "\n\n".join(failures)
