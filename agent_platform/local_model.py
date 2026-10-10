import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen2.5:3b"
MAX_RESPONSE_BYTES = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            request.full_url, code, "Model redirects are disabled", headers, response
        )


def model_name() -> str:
    configured = os.environ.get("AI_MODEL", DEFAULT_MODEL).strip()
    if (
        not configured
        or len(configured) > 128
        or "\n" in configured
        or re.search(r"cloud|remote", configured, re.IGNORECASE)
    ):
        raise ValueError("Cloud/remote or invalid model names are not allowed.")
    return configured


def completion(
    messages: list[dict[str, str]],
    *,
    max_tokens: int,
    json_mode: bool = False,
) -> str:
    base_url = os.environ.get("AI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "AI_BASE_URL must point directly to a local model on localhost; "
            "external model services are blocked."
        )
    if parsed.port is None and parsed.scheme == "http":
        raise ValueError("AI_BASE_URL must include a port for local HTTP models.")

    body: dict[str, Any] = {
        "model": model_name(),
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": max(128, min(max_tokens, 4096)),
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    headers = {"Content-Type": "application/json"}
    local_key = os.environ.get("AI_API_KEY", "")
    if local_key:
        headers["Authorization"] = f"Bearer {local_key}"
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=120) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        detail = error.read(2_000).decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Local model returned HTTP {error.code}: {detail}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            "Could not reach the local model. Start Ollama and download the configured "
            f"model ({model_name()}). Details: {error.reason}"
        ) from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("The local model response exceeded the 256 KiB safety limit.")
    try:
        payload = json.loads(raw.decode("utf-8"))
        choices = payload.get("choices")
        content = choices[0].get("message", {}).get("content") if choices else None
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, IndexError) as error:
        raise ValueError("The local model returned an invalid chat-completions response.") from error
    if not isinstance(content, str) or not content.strip():
        raise ValueError("The local model returned no answer.")
    return content.strip()


def model_ready() -> bool:
    try:
        expected_model = model_name()
    except ValueError:
        return False
    base_url = os.environ.get("AI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
    ):
        return False
    origin = f"{parsed.scheme}://{parsed.netloc}"
    request = urllib.request.Request(
        f"{origin}/api/tags",
        headers={"Accept": "application/json"},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=1) as response:
            if response.status != 200:
                return False
            payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    models = payload.get("models", [])
    return isinstance(models, list) and any(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item["name"] == expected_model
        for item in models
    )
