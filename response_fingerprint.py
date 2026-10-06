"""Sanitized structural fingerprints for authenticated HTTP responses.

B3.5 intentionally analyzes response structure without persisting response
bodies, credential material, cookies, or authorization headers.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from bs4 import BeautifulSoup
import httpx


MAX_ANALYSIS_BYTES = 256 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_KEYS = 256
MAX_HTML_NODES = 512


@dataclass(frozen=True)
class ResponseFingerprint:
    """Metadata and sanitized structural information about an HTTP response."""

    content_type: str
    content_length: int
    representation: str
    structure: tuple[str, ...]
    shape: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _content_type(response: httpx.Response) -> str:
    """Return the normalized media type without parameters."""
    value = response.headers.get("content-type", "")
    return value.split(";", 1)[0].strip().lower()


def _json_structure(
    value: Any,
    *,
    depth: int = 0,
    path: str = "$",
    seen_keys: int = 0,
) -> tuple[list[str], int]:
    """Return sanitized JSON key/type paths and the number of keys observed."""
    if depth > MAX_JSON_DEPTH or seen_keys >= MAX_JSON_KEYS:
        return [f"{path}:<truncated>"], seen_keys

    if isinstance(value, dict):
        structure: list[str] = [f"{path}:object"]

        sorted_items = sorted(
            value.items(),
            key=lambda item: str(item[0]),
        )

        for index, (_, child_value) in enumerate(sorted_items, start=1):
            if seen_keys >= MAX_JSON_KEYS:
                structure.append(f"{path}:<keys-truncated>")
                break

            child_path = f"{path}.field_{index}"
            child_structure, seen_keys = _json_structure(
                child_value,
                depth=depth + 1,
                path=child_path,
                seen_keys=seen_keys + 1,
            )
            structure.extend(child_structure)

        return structure, seen_keys

    if isinstance(value, list):
        structure = [f"{path}:array[{len(value)}]"]
        if value:
            child_structure, seen_keys = _json_structure(
                value[0],
                depth=depth + 1,
                path=f"{path}[]",
                seen_keys=seen_keys,
            )
            structure.extend(child_structure)
        return structure, seen_keys

    if value is None:
        value_type = "null"
    elif isinstance(value, bool):
        value_type = "boolean"
    elif isinstance(value, (int, float)):
        value_type = "number"
    elif isinstance(value, str):
        value_type = "string"
    else:
        value_type = type(value).__name__

    return [f"{path}:{value_type}"], seen_keys


def _html_structure(text: str) -> tuple[list[str], str]:
    """Return sanitized HTML tag counts and coarse document shape."""
    soup = BeautifulSoup(text, "html.parser")
    tags = [tag.name for tag in soup.find_all(limit=MAX_HTML_NODES)]
    counts = Counter(tags)

    structure = [
        f"tag:{name}={counts[name]}"
        for name in sorted(counts)
    ]

    title_present = bool(soup.title)
    forms = len(soup.find_all("form"))
    links = len(soup.find_all("a"))
    headings = len(soup.find_all(re.compile(r"^h[1-6]$")))

    shape = (
        f"title={int(title_present)};"
        f"forms={forms};"
        f"links={links};"
        f"headings={headings}"
    )

    return structure, shape


def _text_structure(text: str) -> tuple[list[str], str]:
    """Return content-neutral statistics for plain text."""
    stripped = text.strip()
    lines = stripped.splitlines() if stripped else []
    words = stripped.split()

    structure = [
        f"lines={len(lines)}",
        f"words={len(words)}",
    ]

    shape = (
        f"chars={len(stripped)};"
        f"lines={len(lines)};"
        f"words={len(words)}"
    )

    return structure, shape


def fingerprint_response(response: httpx.Response) -> ResponseFingerprint:
    """Create a sanitized structural fingerprint from an HTTP response.

    Only a bounded prefix of the response body is analyzed. The raw body is
    never returned or stored by this function.
    """
    content_type = _content_type(response)
    body = response.content[:MAX_ANALYSIS_BYTES]
    content_length = len(response.content)

    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            structure, shape = _text_structure(body.decode("utf-8", errors="replace"))
            return ResponseFingerprint(
                content_type=content_type,
                content_length=content_length,
                representation="invalid-json",
                structure=tuple(structure),
                shape=shape,
            )

        structure, _ = _json_structure(value)
        shape = f"json-root={type(value).__name__}"
        return ResponseFingerprint(
            content_type=content_type,
            content_length=content_length,
            representation="json",
            structure=tuple(structure),
            shape=shape,
        )

    text = body.decode("utf-8", errors="replace")

    if content_type in {"text/html", "application/xhtml+xml"}:
        structure, shape = _html_structure(text)
        return ResponseFingerprint(
            content_type=content_type,
            content_length=content_length,
            representation="html",
            structure=tuple(structure),
            shape=shape,
        )

    structure, shape = _text_structure(text)
    return ResponseFingerprint(
        content_type=content_type,
        content_length=content_length,
        representation="text",
        structure=tuple(structure),
        shape=shape,
    )
