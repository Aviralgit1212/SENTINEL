
#!/usr/bin/env python3
"""Bounded, static JSON inspection for Sentinel. Never executes uploaded data."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_STRINGS = 20_000
MAX_EXAMPLES = 20
MAX_OUTPUT_BYTES = 1_000_000

URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>\\]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

PROMPT_PATTERNS = {
    "ignore-previous-instructions": re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\b.{0,70}"
        r"\b(previous|prior|above|all)\b.{0,35}"
        r"\b(instructions?|rules?|prompts?)\b"
    ),
    "system-prompt-extraction": re.compile(
        r"(?i)\b(reveal|print|show|expose|dump|repeat)\b.{0,60}"
        r"\b(system prompt|hidden prompt|developer message|secret instructions?)\b"
    ),
    "role-override": re.compile(
        r"(?i)\b(you are now|act as|pretend to be)\b.{0,50}"
        r"\b(system|developer|unrestricted|jailbreak|admin)\b"
    ),
    "tool-or-command-coercion": re.compile(
        r"(?i)\b(run|execute|invoke)\b.{0,45}"
        r"\b(shell|terminal|powershell|command|tool|function)\b"
    ),
    "exfiltration-language": re.compile(
        r"(?i)\b(send|upload|exfiltrate|forward)\b.{0,50}"
        r"\b(credentials?|passwords?|tokens?|secrets?|private keys?)\b"
    ),
}

SECRET_PATTERNS = {
    "private-key-material": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "aws-access-key-like": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token-like": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "jwt-like-token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
        r"[A-Za-z0-9_-]{8,}\b"
    ),
}

DANGEROUS_KEY_RE = re.compile(
    r"(?i)(^|[_-])(eval|exec|shell|powershell|command|script|"
    r"preinstall|postinstall|installcommand)([_-]|$)"
)

SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?(?:key|token)|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key|"
    r"client[_-]?secret|authorization)"
)

EXEC_PATTERNS = {
    "shell-command-pattern": re.compile(
        r"(?i)(?:\b(?:powershell|cmd\.exe|/bin/(?:sh|bash)|"
        r"bash\s+-c|curl\s+[^\n]{0,100}\|\s*(?:sh|bash)|"
        r"wget\s+[^\n]{0,100}\|\s*(?:sh|bash))\b)"
    ),
    "dynamic-code-pattern": re.compile(
        r"(?i)(?:javascript\s*:|\beval\s*\(|"
        r"\bnew Function\s*\(|\bexec\s*\()"
    ),
    "encoded-payload-marker": re.compile(
        r"(?i)(?:base64_decode\s*\(|frombase64string\s*\(|"
        r"data:text/html;base64,|\\u0000)"
    ),
}


class ObjectPairs(list):
    """Preserve object pairs so duplicate keys remain detectable."""


def emit(payload: dict[str, Any]) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    )

    if len(encoded.encode("utf-8")) > MAX_OUTPUT_BYTES:
        payload = {
            "ok": False,
            "supported": False,
            "error": "JSON analyzer output exceeded the safety limit.",
            "fileSize": payload.get("fileSize", 0),
        }
        encoded = json.dumps(payload, separators=(",", ":"))

    print(encoded)


def analyze(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError:
        return {
            "ok": False,
            "supported": False,
            "error": "JSON file could not be accessed.",
            "fileSize": 0,
        }

    if size > MAX_FILE_BYTES:
        return {
            "ok": False,
            "supported": False,
            "error": "JSON file exceeds the 10 MiB analysis limit.",
            "fileSize": size,
        }

    try:
        raw = path.read_bytes()
    except OSError:
        return {
            "ok": False,
            "supported": False,
            "error": "JSON file could not be read.",
            "fileSize": size,
        }

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return {
            "ok": False,
            "supported": False,
            "error": "JSON is not valid UTF-8 text.",
            "fileSize": size,
        }

    duplicate_keys: list[str] = []
    duplicate_count = 0

    def pairs_hook(pairs: list[tuple[str, Any]]) -> ObjectPairs:
        nonlocal duplicate_count

        seen: set[str] = set()

        for key, _ in pairs:
            if key in seen:
                duplicate_count += 1

                if (
                    len(duplicate_keys) < MAX_EXAMPLES
                    and key not in duplicate_keys
                ):
                    duplicate_keys.append(key[:120])

            seen.add(key)

        return ObjectPairs(pairs)

    def reject_nonstandard_constant(value: str) -> None:
        raise ValueError(f"Invalid JSON constant: {value}")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_nonstandard_constant,
        )
    except (
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        message = "Malformed JSON syntax."

        if isinstance(exc, json.JSONDecodeError):
            message = (
                f"Malformed JSON syntax at line {exc.lineno}, "
                f"column {exc.colno}."
            )
        elif str(exc).startswith("Invalid JSON constant"):
            message = "JSON contains a non-standard numeric constant."

        return {
            "ok": True,
            "supported": False,
            "error": message,
            "fileSize": size,
            "parseError": True,
            "duplicateKeyCount": 0,
            "duplicateKeyExamples": [],
            "urls": [],
            "suspiciousIndicators": ["malformed-json"],
        }

    indicators: set[str] = set()
    prompt_types: set[str] = set()
    secret_types: set[str] = set()
    dangerous_keys: set[str] = set()
    sensitive_keys: set[str] = set()

    urls: list[str] = []
    ip_addresses: list[str] = []

    nodes = 0
    string_count = 0
    max_depth_seen = 0
    html_script_count = 0
    total_string_chars = 0

    # Iterative traversal avoids recursive traversal of nested objects.
    stack: list[tuple[Any, int, str]] = [(parsed, 0, "$")]
    truncated = False

    while stack:
        value, depth, key_context = stack.pop()

        nodes += 1

        if nodes > MAX_NODES:
            indicators.add("node-limit-exceeded")
            truncated = True
            break

        max_depth_seen = max(max_depth_seen, depth)

        if depth > MAX_DEPTH:
            indicators.add("nesting-depth-limit-exceeded")
            truncated = True
            continue

        if isinstance(value, ObjectPairs):
            for key, child in value:
                if nodes + len(stack) >= MAX_NODES:
                    indicators.add("node-limit-exceeded")
                    truncated = True
                    break

                key_str = str(key)

                if SENSITIVE_KEY_RE.search(key_str):
                    sensitive_keys.add(key_str[:100])

                if DANGEROUS_KEY_RE.search(key_str):
                    dangerous_keys.add(key_str[:100])
                    indicators.add("executable-or-command-like-key")

                stack.append((child, depth + 1, key_str[:120]))

        elif isinstance(value, list):
            for child in value:
                if nodes + len(stack) >= MAX_NODES:
                    indicators.add("node-limit-exceeded")
                    truncated = True
                    break

                stack.append((child, depth + 1, key_context))

        elif isinstance(value, str):
            string_count += 1
            total_string_chars += len(value)

            if string_count > MAX_STRINGS:
                indicators.add("string-count-limit-exceeded")
                truncated = True
                break

            for kind, pattern in PROMPT_PATTERNS.items():
                if pattern.search(value):
                    prompt_types.add(kind)

            for kind, pattern in SECRET_PATTERNS.items():
                if pattern.search(value):
                    secret_types.add(kind)

            for kind, pattern in EXEC_PATTERNS.items():
                if pattern.search(value):
                    indicators.add(kind)

            if re.search(
                r"(?is)<\s*(?:script|iframe|object|embed)\b|javascript\s*:",
                value,
            ):
                html_script_count += 1

            for match in URL_RE.findall(value):
                safe_url = match[:300].rstrip(".,);]")

                if (
                    safe_url
                    and len(urls) < MAX_EXAMPLES
                    and safe_url not in urls
                ):
                    # Redact URL credentials and query/fragment data.
                    safe_url = re.sub(
                        r"(?i)(https?://)[^/@\s]+@",
                        r"\1[redacted]@",
                        safe_url,
                    )

                    safe_url = re.sub(
                        r"[?#].*$",
                        "?[redacted]" if "?" in safe_url else "#[redacted]",
                        safe_url,
                    )

                    urls.append(safe_url)

            for match in IP_RE.findall(value):
                octets = match.split(".")

                if (
                    all(0 <= int(octet) <= 255 for octet in octets)
                    and match not in ip_addresses
                    and len(ip_addresses) < MAX_EXAMPLES
                ):
                    ip_addresses.append(match)

            if (
                SENSITIVE_KEY_RE.search(key_context)
                and value.strip()
                and value.strip().lower()
                not in {"null", "none", "changeme", "example", "your-secret-here"}
            ):
                # Never return the sensitive value itself.
                sensitive_keys.add(key_context[:100])

    if duplicate_count:
        indicators.add("duplicate-object-keys")

    if prompt_types:
        indicators.add("prompt-injection-like-instruction")

    if secret_types:
        indicators.add("possible-credential-or-secret-material")

    if html_script_count:
        indicators.add("html-or-script-like-content")

    if total_string_chars > 5_000_000:
        indicators.add("large-text-content")

    if truncated:
        indicators.add("analysis-truncated")

    if isinstance(parsed, ObjectPairs):
        top_level_type = "object"
    elif isinstance(parsed, list):
        top_level_type = "array"
    elif parsed is None:
        top_level_type = "null"
    elif isinstance(parsed, str):
        top_level_type = "string"
    elif isinstance(parsed, bool):
        top_level_type = "boolean"
    else:
        top_level_type = "number"

    return {
        "ok": True,
        "supported": not truncated,
        "error": (
            "Analysis was truncated by a safety limit."
            if truncated
            else None
        ),
        "fileSize": size,
        "topLevelType": top_level_type,
        "nodeCount": min(nodes, MAX_NODES),
        "stringCount": min(string_count, MAX_STRINGS),
        "maxDepth": max_depth_seen,
        "duplicateKeyCount": duplicate_count,
        "duplicateKeyExamples": duplicate_keys,
        "urls": urls,
        "ipAddresses": ip_addresses,
        "promptInjectionCount": len(prompt_types),
        "promptInjectionTypes": sorted(prompt_types),
        "secretIndicators": sorted(secret_types),
        "sensitiveKeyCount": len(sensitive_keys),
        "sensitiveKeyExamples": sorted(sensitive_keys)[:MAX_EXAMPLES],
        "dangerousKeyCount": len(dangerous_keys),
        "dangerousKeyExamples": sorted(dangerous_keys)[:MAX_EXAMPLES],
        "htmlScriptLikeCount": html_script_count,
        "suspiciousIndicators": sorted(indicators),
        "analysisTruncated": truncated,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        emit({
            "ok": False,
            "supported": False,
            "error": "Expected exactly one file path.",
            "fileSize": 0,
        })
        sys.exit(0)

    try:
        emit(analyze(Path(sys.argv[1])))
    except Exception:
        # Avoid exposing stack traces or filesystem details.
        emit({
            "ok": False,
            "supported": False,
            "error": "Unexpected JSON analysis error.",
            "fileSize": 0,
        })