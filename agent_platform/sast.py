"""Deterministic static analysis (no model tokens).

Python files are analysed with the `ast` module (precise, low false positives);
other languages use conservative line-based rules. Every finding carries a CWE
identifier so results can be mapped to secure-coding controls.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import PurePosixPath
from typing import Any

from .security import find_secrets

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding(
    severity: str, rule: str, cwe: str | None, path: str, line: int | None, message: str, source: str = "sast"
) -> dict[str, Any]:
    return {
        "severity": severity,
        "rule": rule,
        "cwe": cwe,
        "path": path,
        "line": line,
        "message": message,
        "source": source,
    }


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_dynamic_string(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[dict[str, Any]] = []

    def add(self, node: ast.AST, severity: str, rule: str, cwe: str, message: str) -> None:
        self.findings.append(_finding(severity, rule, cwe, self.path, getattr(node, "lineno", None), message))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901 - flat rule table
        name = _call_name(node.func)
        short = name.rsplit(".", 1)[-1]
        if name in {"eval", "exec"}:
            self.add(node, "high", "py-eval-exec", "CWE-95", f"`{name}()` executes dynamic code.")
        elif name in {"os.system", "os.popen"}:
            self.add(node, "high", "py-os-command", "CWE-78", f"`{name}()` runs a shell command.")
        elif name.startswith("subprocess.") and _is_true(_kw(node, "shell")):
            self.add(node, "high", "py-subprocess-shell", "CWE-78", "subprocess call with shell=True.")
        elif name in {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "shelve.open"}:
            self.add(node, "high", "py-unsafe-deserialization", "CWE-502", f"`{name}()` can execute code from untrusted data.")
        elif name in {"yaml.load", "yaml.load_all"} and _kw(node, "Loader") is None:
            self.add(node, "high", "py-yaml-load", "CWE-502", "yaml.load without a safe Loader.")
        elif name in {"yaml.unsafe_load"}:
            self.add(node, "high", "py-yaml-load", "CWE-502", "yaml.unsafe_load deserializes arbitrary objects.")
        elif name in {"hashlib.md5", "hashlib.sha1"} and not _is_false(_kw(node, "usedforsecurity")):
            self.add(node, "medium", "py-weak-hash", "CWE-328", f"`{name}` is not collision resistant.")
        elif short in {"get", "post", "put", "delete", "patch", "request"} and _is_false(_kw(node, "verify")):
            self.add(node, "high", "py-tls-verify-disabled", "CWE-295", "TLS certificate verification disabled.")
        elif short == "run" and _is_true(_kw(node, "debug")):
            self.add(node, "medium", "py-debug-enabled", "CWE-489", "Application started with debug=True.")
        elif short in {"execute", "executemany", "executescript"} and node.args and _is_dynamic_string(node.args[0]):
            self.add(node, "high", "py-sql-injection", "CWE-89", "SQL built from string formatting; use parameters.")
        elif name in {"tempfile.mktemp"}:
            self.add(node, "medium", "py-insecure-tempfile", "CWE-377", "tempfile.mktemp is race-prone; use mkstemp.")
        elif name in {"random.random", "random.randint", "random.choice"} and self._in_security_context(node):
            self.add(node, "medium", "py-insecure-random", "CWE-338", "Use `secrets` for security-sensitive randomness.")
        elif short == "chmod" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and mode.value & 0o002:
                self.add(node, "medium", "py-world-writable", "CWE-732", "File made world-writable.")
        elif short == "bind" and node.args and isinstance(node.args[0], ast.Tuple):
            host = node.args[0].elts[0] if node.args[0].elts else None
            if isinstance(host, ast.Constant) and host.value in {"0.0.0.0", "::", ""}:
                self.add(node, "medium", "py-bind-all-interfaces", "CWE-1327", "Socket binds to all interfaces.")
        self.generic_visit(node)

    def _in_security_context(self, node: ast.AST) -> bool:
        return False  # refined by assignment check below

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            target_name = _call_name(target).lower()
            if re.search(r"token|secret|password|nonce|salt|otp", target_name) and isinstance(node.value, ast.Call):
                if _call_name(node.value.func).startswith("random."):
                    self.add(node, "medium", "py-insecure-random", "CWE-338", "Use `secrets` for security-sensitive randomness.")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node, "low", "py-bare-except-pass", "CWE-390", "Bare `except: pass` hides errors.")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        test = ast.unparse(node.test).lower()
        if re.search(r"auth|admin|permission|is_staff|role", test):
            self.add(node, "medium", "py-assert-authz", "CWE-617", "assert used for authorization is stripped with -O.")
        self.generic_visit(node)


_LINE_RULES: list[tuple[set[str], re.Pattern[str], str, str, str, str]] = [
    ({".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".html"}, re.compile(r"\beval\s*\(|new\s+Function\s*\("), "high", "js-eval", "CWE-95", "Dynamic code execution."),
    ({".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue"}, re.compile(r"\.(?:innerHTML|outerHTML)\s*=(?!=)|insertAdjacentHTML\s*\(|document\.write\s*\("), "medium", "js-dom-xss", "CWE-79", "HTML sink; prefer textContent or sanitize."),
    ({".jsx", ".tsx"}, re.compile(r"dangerouslySetInnerHTML"), "medium", "react-dangerous-html", "CWE-79", "dangerouslySetInnerHTML bypasses React escaping."),
    ({".js", ".ts", ".mjs"}, re.compile(r"child_process['\"]?\)?\.exec\s*\(|\bexecSync\s*\("), "high", "node-command-exec", "CWE-78", "Shell command execution."),
    ({".js", ".ts", ".mjs"}, re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"), "high", "node-tls-disabled", "CWE-295", "TLS verification disabled."),
    ({".js", ".ts", ".mjs", ".jsx", ".tsx"}, re.compile(r"Math\.random\(\).*(?:token|secret|password|key)", re.I), "medium", "js-insecure-random", "CWE-338", "Math.random is not cryptographically secure."),
    ({".go"}, re.compile(r"InsecureSkipVerify\s*:\s*true"), "high", "go-tls-skip-verify", "CWE-295", "TLS verification disabled."),
    ({".go"}, re.compile(r"exec\.Command\(\s*\"(?:sh|bash)\"\s*,\s*\"-c\""), "high", "go-shell-exec", "CWE-78", "Shell command execution."),
    ({".go", ".java", ".php", ".rb", ".js", ".ts"}, re.compile(r"(?i)[\"'](?:SELECT|INSERT|UPDATE|DELETE)\s[^\"']*[\"']\s*\+"), "high", "sql-concatenation", "CWE-89", "SQL built by string concatenation."),
    ({".php"}, re.compile(r"\b(?:eval|system|shell_exec|passthru)\s*\(|\bunserialize\s*\(\s*\$_"), "high", "php-dangerous-call", "CWE-94", "Dangerous PHP call."),
    ({".java"}, re.compile(r"new\s+ObjectInputStream\s*\("), "medium", "java-deserialization", "CWE-502", "Java native deserialization."),
    ({".sh"}, re.compile(r"curl[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"), "high", "sh-curl-pipe", "CWE-494", "Piping a download into a shell."),
    ({".yml", ".yaml"}, re.compile(r"privileged:\s*true"), "high", "k8s-privileged", "CWE-250", "Privileged container."),
    ({".yml", ".yaml"}, re.compile(r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.[^}]*(?:title|body)"), "high", "gha-script-injection", "CWE-94", "Untrusted GitHub event data in a workflow expression."),
]
_DOCKERFILE_RULES = [
    (re.compile(r"^\s*FROM\s+\S+:latest\b", re.I | re.M), "low", "docker-latest-tag", "CWE-1357", "Pin base images instead of :latest."),
    (re.compile(r"^\s*USER\s+root\b", re.I | re.M), "medium", "docker-root-user", "CWE-250", "Container runs as root."),
    (re.compile(r"^\s*ADD\s+https?://", re.I | re.M), "medium", "docker-remote-add", "CWE-494", "ADD from URL skips integrity checks."),
]


def analyze_file(path: str, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    suffix = PurePosixPath(path).suffix.lower()
    name = PurePosixPath(path).name.lower()
    for label in find_secrets(content):
        findings.append(_finding("high", f"secret-{label}", "CWE-798", path, None, "Possible hard-coded credential.", "secrets"))
    if suffix == ".py":
        try:
            tree = ast.parse(content)
        except SyntaxError as error:
            findings.append(_finding("high", "syntax-error", None, path, error.lineno, f"Python syntax error: {error.msg}", "syntax"))
            return findings
        visitor = _PythonVisitor(path)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings
    if suffix == ".json":
        try:
            json.loads(content)
        except json.JSONDecodeError as error:
            findings.append(_finding("high", "syntax-error", None, path, error.lineno, f"Invalid JSON: {error.msg}", "syntax"))
    if name == "dockerfile":
        for pattern, severity, rule, cwe, message in _DOCKERFILE_RULES:
            match = pattern.search(content)
            if match:
                findings.append(_finding(severity, rule, cwe, path, content.count("\n", 0, match.start()) + 1, message))
        if not re.search(r"^\s*USER\s+", content, re.I | re.M):
            findings.append(_finding("low", "docker-no-user", "CWE-250", path, None, "No USER instruction; container defaults to root."))
    for suffixes, pattern, severity, rule, cwe, message in _LINE_RULES:
        if suffix not in suffixes:
            continue
        for number, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                findings.append(_finding(severity, rule, cwe, path, number, message))
                break
    return findings


def analyze_changes(files: list[dict[str, Any]], before: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Analyse proposed files, reporting only findings that are new vs. `before`."""
    before = before or {}
    results: list[dict[str, Any]] = []
    for item in files:
        path = str(item["path"])
        current = analyze_file(path, str(item["content"]))
        if path in before:
            existing = {(f["rule"], f["message"]) for f in analyze_file(path, before[path])}
            current = [f for f in current if (f["rule"], f["message"]) not in existing]
        results.extend(current)
    results.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["path"], f["line"] or 0))
    return results


def max_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "info"
    return max((f["severity"] for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0))

