import re
from pathlib import PurePosixPath


SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_key",
        re.compile(
            r"""(?i)aws_?secret_?access_?key\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b"""
        ),
    ),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("api_token", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
    ),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("azure_storage_key", re.compile(r"(?i)\bAccountKey=[A-Za-z0-9/+=]{40,}")),
    (
        "url_credential",
        re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"']{1,64}:[^\s@/\"']{3,128}@[\w.-]+"),
    ),
    (
        "credential",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|access[_-]?key)\b["']?\s*[:=]\s*["'][^"']{8,}["']"""
        ),
    ),
)
# Backwards-compatible view of the compiled patterns.
SECRET_PATTERNS = tuple(pattern for _, pattern in SECRET_RULES)

BLOCKED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".ssh",
    ".aws",
    ".azure",
}
BLOCKED_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets.json",
}


def find_secrets(text: str) -> list[str]:
    """Return names of matched secret classes, never the matched values."""
    return [label for label, pattern in SECRET_RULES if pattern.search(text)]


def validate_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("File paths must be non-empty relative POSIX paths.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("File path escapes or is not relative to the workspace.")
    if any(part.lower() in BLOCKED_PARTS for part in path.parts):
        raise ValueError("The requested path is in a protected directory.")
    if path.name.lower() in BLOCKED_NAMES or path.name.lower().startswith(".env."):
        raise ValueError("Secret and environment files cannot be edited.")
    return path.as_posix()


def scan_proposed_files(files: list[dict[str, object]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for item in files:
        path = str(item["path"])
        content = str(item["content"])
        for label in find_secrets(content):
            findings.append(
                {
                    "severity": "high",
                    "path": path,
                    "rule": label,
                    "message": "A possible credential was detected; review and rotate it if real.",
                }
            )
        if re.search(r"(?i)\b(?:eval\s*\(|exec\s*\(|shell\s*=\s*True)", content):
            findings.append(
                {
                    "severity": "medium",
                    "path": path,
                    "rule": "dynamic_or_shell_execution",
                    "message": "Review dynamic or shell execution in this proposed change.",
                }
            )
    return findings
