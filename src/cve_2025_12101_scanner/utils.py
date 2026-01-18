from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    port: int
    scheme: str


def parse_target(url: str) -> Target:
    """
    Accepts:
      - https://example.com
      - http://example.com
      - example.com
      - example.com:8443

    Returns parsed Target.
    """
    url = url.strip()
    if not url:
        raise ValueError("Empty target")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid target URL: {url}")

    scheme = parsed.scheme or "https"
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if scheme == "https" else 80

    return Target(raw=url, host=host, port=port, scheme=scheme)


def load_targets(lines: Iterable[str]) -> list[Target]:
    """
    Loads targets from a list of lines.
    Ignores empty lines and comments starting with '#'.
    """
    targets: list[Target] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            targets.append(parse_target(s))
        except ValueError:
            # Skip invalid lines quietly by design for bulk files
            continue
    return targets


def parse_headers(header_kv_list: list[str] | None) -> dict[str, str]:
    """
    Accepts ["Header: value", "Another: value"] and returns a dict.
    """
    headers: dict[str, str] = {}
    if not header_kv_list:
        return headers

    for item in header_kv_list:
        if ":" not in item:
            raise ValueError(f"Invalid header format: {item}. Expected 'Key: Value'")
        k, v = item.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise ValueError(f"Invalid header key: {item}")
        headers[k] = v
    return headers
