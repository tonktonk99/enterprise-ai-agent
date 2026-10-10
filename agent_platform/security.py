import re
from pathlib import PurePosixPath


SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"']{8,}["']"""
    ),
)

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
    labels = ("private_key", "aws_access_key", "github_token", "api_token", "credential")
    return [
        label
        for label, pattern in zip(labels, SECRET_PATTERNS)
        if pattern.search(text)
    ]


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
