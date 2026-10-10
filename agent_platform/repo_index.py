"""Token-efficient repository index.

Instead of sending whole files to the model, Forge builds a compact map of the
repository (paths + top-level symbols) and ranks files with BM25. The Planner
only sees the map; the Coder only sees the files the Planner selected, and
everything else is reduced to signature outlines.
"""

from __future__ import annotations

import ast
import hashlib
import math
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .security import find_secrets, validate_relative_path
from .workspace import IGNORE_DIRS, MAX_FILE_BYTES, TEXT_FILENAMES, TEXT_SUFFIXES

MAX_INDEXED_FILES = 2_000
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_SYMBOL_PATTERNS: dict[str, re.Pattern[str]] = {
    "js": re.compile(
        r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
        r"(?:function\s*\*?\s*([A-Za-z_$][\w$]*)|class\s+([A-Za-z_$][\w$]*)|"
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)",
        re.MULTILINE,
    ),
    "go": re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)|^type\s+([A-Za-z_]\w*)", re.MULTILINE),
    "rs": re.compile(r"^\s*(?:pub\s+)?(?:fn|struct|enum|trait)\s+([A-Za-z_]\w*)", re.MULTILINE),
    "java": re.compile(
        r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:class|interface|enum|[\w<>\[\]]+)\s+([A-Za-z_]\w*)\s*[({]",
        re.MULTILINE,
    ),
    "rb": re.compile(r"^\s*(?:def|class|module)\s+([A-Za-z_][\w.?!]*)", re.MULTILINE),
    "php": re.compile(r"^\s*(?:public\s+|private\s+|protected\s+)?(?:function|class)\s+([A-Za-z_]\w*)", re.MULTILINE),
}
_LANG_BY_SUFFIX = {
    ".js": "js", ".jsx": "js", ".mjs": "js", ".ts": "js", ".tsx": "js", ".vue": "js",
    ".go": "go", ".rs": "rs", ".java": "java", ".rb": "rb", ".php": "php",
}


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in TOKEN_RE.findall(text):
        for part in CAMEL_RE.sub(" ", raw).replace("_", " ").split():
            if len(part) > 1:
                tokens.append(part.lower())
    return tokens


@dataclass
class IndexedFile:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    symbols: list[str]
    outline: str
    term_freq: dict[str, int] = field(repr=False)
    length: int = 0


def _python_outline(content: str) -> tuple[list[str], str]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return [], ""
    symbols: list[str] = []
    lines: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(node.name)
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            lines.append(f"{prefix} {node.name}({ast.unparse(node.args)}) ...")
        elif isinstance(node, ast.ClassDef):
            symbols.append(node.name)
            lines.append(f"class {node.name}:")
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbols.append(f"{node.name}.{child.name}")
                    lines.append(f"    def {child.name}({ast.unparse(child.args)}) ...")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    symbols.append(target.id)
                    lines.append(f"{target.id} = ...")
    return symbols, "\n".join(lines)


def _generic_outline(content: str, suffix: str) -> tuple[list[str], str]:
    pattern = _SYMBOL_PATTERNS.get(_LANG_BY_SUFFIX.get(suffix, ""))
    if pattern is None:
        return [], ""
    symbols: list[str] = []
    lines: list[str] = []
    for match in pattern.finditer(content):
        name = next((group for group in match.groups() if group), None)
        if name:
            symbols.append(name)
            lines.append(match.group(0).strip()[:160])
    return symbols, "\n".join(lines)


def outline_for(path: str, content: str) -> tuple[list[str], str]:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return _python_outline(content)
    return _generic_outline(content, suffix)


class RepoIndex:
    """Incremental, thread-safe index keyed by file mtime/size."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self._files: dict[str, IndexedFile] = {}
        self._lock = threading.Lock()
        self.skipped_for_secrets = 0

    def refresh(self) -> None:
        seen: set[str] = set()
        skipped = 0
        count = 0
        for current, dirs, names in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(
                name
                for name in dirs
                if name.lower() not in IGNORE_DIRS
                and not name.startswith(".forge")
                and not (current_path / name).is_symlink()
            )
            for name in sorted(names):
                if count >= MAX_INDEXED_FILES:
                    break
                path = current_path / name
                relative = path.relative_to(self.root).as_posix()
                if (
                    path.suffix.lower() not in TEXT_SUFFIXES
                    and name.lower() not in TEXT_FILENAMES
                ) or path.is_symlink():
                    continue
                try:
                    validate_relative_path(relative)
                    stat_result = path.stat()
                except (ValueError, OSError):
                    continue
                if not path.is_file() or stat_result.st_size > MAX_FILE_BYTES:
                    continue
                count += 1
                cached = self._files.get(relative)
                if (
                    cached
                    and cached.mtime_ns == stat_result.st_mtime_ns
                    and cached.size == stat_result.st_size
                ):
                    seen.add(relative)
                    continue
                try:
                    raw = path.read_bytes()
                    content = raw.decode("utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                if find_secrets(content):
                    skipped += 1
                    continue
                symbols, outline = outline_for(relative, content)
                terms = tokenize(relative) * 3 + tokenize(" ".join(symbols)) * 2 + tokenize(content)
                freq: dict[str, int] = {}
                for term in terms:
                    freq[term] = freq.get(term, 0) + 1
                with self._lock:
                    self._files[relative] = IndexedFile(
                        path=relative,
                        sha256=hashlib.sha256(raw).hexdigest(),
                        size=stat_result.st_size,
                        mtime_ns=stat_result.st_mtime_ns,
                        symbols=symbols[:40],
                        outline=outline[:1_500],
                        term_freq=freq,
                        length=len(terms),
                    )
                seen.add(relative)
        with self._lock:
            for stale in set(self._files) - seen:
                del self._files[stale]
            self.skipped_for_secrets = skipped

    @property
    def files(self) -> dict[str, IndexedFile]:
        with self._lock:
            return dict(self._files)

    def total_chars(self) -> int:
        return sum(item.size for item in self.files.values())

    def rank(self, query: str, limit: int = 20) -> list[tuple[str, float]]:
        files = self.files
        if not files:
            return []
        terms = set(tokenize(query))
        n_docs = len(files)
        avg_len = sum(item.length for item in files.values()) / n_docs or 1.0
        doc_freq: dict[str, int] = {}
        for item in files.values():
            for term in terms:
                if term in item.term_freq:
                    doc_freq[term] = doc_freq.get(term, 0) + 1
        k1, b = 1.4, 0.75
        scores: list[tuple[str, float]] = []
        for path, item in files.items():
            score = 0.0
            for term in terms:
                tf = item.term_freq.get(term, 0)
                if not tf:
                    continue
                idf = math.log(1 + (n_docs - doc_freq[term] + 0.5) / (doc_freq[term] + 0.5))
                score += idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * item.length / avg_len))
            if Path(path).name.lower() in {"readme.md", "package.json", "pyproject.toml"}:
                score += 0.2
            scores.append((path, score))
        scores.sort(key=lambda pair: (-pair[1], pair[0]))
        return scores[:limit]

    def repo_map(self, query: str, max_chars: int = 3_000) -> str:
        """Compact, ranked map: `path: sym1, sym2` lines, most relevant first."""
        files = self.files
        lines: list[str] = []
        used = 0
        ranked = self.rank(query, limit=len(files))
        for path, _ in ranked:
            symbols = ", ".join(files[path].symbols[:8])
            line = f"{path}: {symbols}" if symbols else path
            if used + len(line) + 1 > max_chars:
                lines.append(f"... (+{len(ranked) - len(lines)} more files)")
                break
            lines.append(line)
            used += len(line) + 1
        return "\n".join(lines)

    def read(self, relative: str) -> tuple[str, str] | None:
        """Return (content, sha256) if the file is indexed and unchanged."""
        item = self.files.get(relative)
        if item is None:
            return None
        try:
            raw = (self.root / relative).read_bytes()
        except OSError:
            return None
        digest = hashlib.sha256(raw).hexdigest()
        if digest != item.sha256:
            return None
        return raw.decode("utf-8"), digest


_INDEXES: dict[Path, RepoIndex] = {}
_INDEXES_LOCK = threading.Lock()


def get_index(root: Path) -> RepoIndex:
    resolved = root.resolve(strict=True)
    with _INDEXES_LOCK:
        index = _INDEXES.get(resolved)
        if index is None:
            index = RepoIndex(resolved)
            _INDEXES[resolved] = index
    index.refresh()
    return index

