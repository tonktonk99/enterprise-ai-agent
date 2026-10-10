import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath

from .security import BLOCKED_NAMES, BLOCKED_PARTS, find_secrets, validate_relative_path

MAX_FILE_BYTES = 256 * 1024
MAX_CONTEXT_FILES = 5
MAX_CONTEXT_CHARS = 12_000
MAX_PROPOSAL_FILES = 8
TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".css",
    ".go",
    ".h",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {
    ".editorconfig",
    ".gitignore",
    "dockerfile",
    "license",
    "makefile",
}
IGNORE_DIRS = BLOCKED_PARTS | {
    ".next",
    ".turbo",
    "build",
    "dist",
    "coverage",
    "target",
}
IMPORTANT_NAMES = {
    "readme.md",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "cargo.toml",
}


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def gather_context(root: Path, task: str) -> dict[str, object]:
    safe_root = root.resolve(strict=True)
    terms = {
        term.lower()
        for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", task)
        if len(term) > 2
    }
    candidates: list[tuple[int, str, str, str]] = []
    skipped_secrets = 0
    scanned = 0
    for current, dirs, names in os.walk(safe_root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            name
            for name in dirs
            if name.lower() not in IGNORE_DIRS
            and not (current_path / name).is_symlink()
        )
        for name in sorted(names):
            if scanned >= 200:
                break
            path = current_path / name
            relative = path.relative_to(safe_root).as_posix()
            try:
                validate_relative_path(relative)
            except ValueError:
                continue
            if (
                path.suffix.lower() not in TEXT_SUFFIXES
                and name.lower() not in TEXT_FILENAMES
            ) or path.is_symlink():
                continue
            try:
                if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                    continue
                raw = path.read_bytes()
                content = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            scanned += 1
            if find_secrets(content):
                skipped_secrets += 1
                continue
            lowered_path = relative.lower()
            lowered_content = content.lower()
            score = sum(term in lowered_path for term in terms) * 4
            score += sum(term in lowered_content for term in terms)
            if name.lower() in IMPORTANT_NAMES:
                score += 2
            candidates.append((score, relative, content, _digest(raw)))
        if scanned >= 200:
            break

    candidates.sort(key=lambda item: (-item[0], item[1]))
    selected: list[dict[str, str]] = []
    used_chars = 0
    for _, relative, content, digest in candidates:
        remaining = MAX_CONTEXT_CHARS - used_chars
        if remaining <= 0 or len(selected) >= MAX_CONTEXT_FILES:
            break
        excerpt = content[:remaining]
        selected.append({"path": relative, "content": excerpt, "sha256": digest})
        used_chars += len(excerpt)

    return {
        "files": selected,
        "files_scanned": scanned,
        "files_skipped_for_secrets": skipped_secrets,
        "context_chars": used_chars,
    }


def validate_proposal(root: Path, files: list[dict[str, object]]) -> list[dict[str, object]]:
    if len(files) > MAX_PROPOSAL_FILES:
        raise ValueError(f"A proposal can change at most {MAX_PROPOSAL_FILES} files.")
    safe_root = root.resolve(strict=True)
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Each proposed file must have a string path.")
        path = validate_relative_path(item["path"])
        if (
            PurePosixPath(path).suffix.lower() not in TEXT_SUFFIXES
            and PurePosixPath(path).name.lower() not in TEXT_FILENAMES
        ):
            raise ValueError(f"Only recognized text files can be edited: {path}")
        if path in seen:
            raise ValueError(f"Duplicate proposed file path: {path}")
        seen.add(path)
        content = item.get("content")
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError(f"Proposed file {path} must be text smaller than 256 KiB.")
        target = safe_root / path
        if not _is_within(safe_root, target.parent.resolve()):
            raise ValueError(f"Proposed file {path} escapes the workspace.")
        if target.parent.exists() and not target.parent.is_dir():
            raise ValueError(f"Parent of {path} is not a directory.")
        if target.is_symlink():
            raise ValueError(f"Symbolic links cannot be edited: {path}")
        if target.exists() and not target.is_file():
            raise ValueError(f"Only regular files can be edited: {path}")
        if target.exists() and target.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"Existing file {path} is too large to safely replace.")
        before_hash = item.get("before_hash")
        if target.exists():
            current = target.read_bytes()
            if before_hash != _digest(current):
                raise ValueError(f"Workspace file changed after proposal: {path}")
        elif before_hash is not None:
            raise ValueError(f"Workspace file disappeared after proposal: {path}")
        normalized.append(
            {
                "path": path,
                "content": content,
                "before_hash": before_hash,
                "reason": str(item.get("reason", ""))[:500],
            }
        )
    return normalized


def apply_proposal(root: Path, files: list[dict[str, object]]) -> list[str]:
    normalized = validate_proposal(root, files)
    safe_root = root.resolve(strict=True)
    staged: dict[str, Path] = {}
    originals: dict[str, tuple[bool, bytes, int]] = {}
    applied: list[str] = []
    try:
        for item in normalized:
            relative = str(item["path"])
            target = safe_root / relative
            missing: list[Path] = []
            parent = target.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir()
            if target.is_symlink() or not _is_within(safe_root, target.parent.resolve()):
                raise ValueError(f"Workspace path changed during approval: {relative}")
            exists = target.exists()
            original = target.read_bytes() if exists else b""
            mode = stat.S_IMODE(target.stat().st_mode) if exists else 0o644
            originals[relative] = (exists, original, mode)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=".agent-stage-", delete=False
            ) as handle:
                handle.write(str(item["content"]).encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
                staged[relative] = Path(handle.name)
            staged[relative].chmod(mode)

        for item in normalized:
            relative = str(item["path"])
            target = safe_root / relative
            if target.is_symlink() or not _is_within(safe_root, target.parent.resolve()):
                raise ValueError(f"Workspace path changed during approval: {relative}")
            existed, _, _ = originals[relative]
            if existed != target.exists():
                raise ValueError(f"Workspace file changed after validation: {relative}")
            if existed and _digest(target.read_bytes()) != item["before_hash"]:
                raise ValueError(f"Workspace file changed after validation: {relative}")
            os.replace(staged[relative], target)
            applied.append(relative)
        return applied
    except Exception as original_error:
        rollback_errors: list[str] = []
        for relative in reversed(applied):
            target = safe_root / relative
            existed, original, mode = originals[relative]
            try:
                if existed:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", dir=target.parent, prefix=".agent-rollback-", delete=False
                    ) as handle:
                        handle.write(original)
                        handle.flush()
                        os.fsync(handle.fileno())
                        restore = Path(handle.name)
                    restore.chmod(mode)
                    os.replace(restore, target)
                else:
                    target.unlink(missing_ok=True)
            except OSError as error:
                rollback_errors.append(f"{relative}: {error}")
        if rollback_errors:
            raise RuntimeError(
                f"Apply failed ({original_error}); rollback also failed: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
