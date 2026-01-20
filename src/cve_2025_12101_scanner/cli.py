# src/cve_2025_12101_scanner/cli.py
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .scanner import DEFAULT_PATH, print_result_human, scan_target
from .utils import load_targets, parse_headers, parse_target


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SternSleuth Citrix NetScaler RXSS scanner. CVE-2025-12101 style reflection probe.",
        allow_abbrev=False,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single target URL, e.g. https://example.com")
    target_group.add_argument(
        "-f",
        "--file",
        help="Text file with targets. One per line. Supports # comments.",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help="Add custom header. Format: 'Key: Value'. Repeat for multiple headers.",
    )

    parser.add_argument("--timeout", type=int, default=15, help="Timeout seconds (default: 15)")
    parser.add_argument(
        "--path",
        default=DEFAULT_PATH,
        help=f"POST path to probe (default: {DEFAULT_PATH})",
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="Delay in seconds between targets to avoid flooding (default: 0.0)",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Allow self-signed TLS, disables certificate verification. Lab use only.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors, useful for CI logs and piping.",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print vulnerable findings (human output).",
    )

    parser.add_argument(
        "--out",
        help="Write vulnerable targets to a text file (one per line).",
    )

    parser.add_argument(
        "--json",
        dest="json_out",
        help="Write a report-ready JSON bundle (metadata + evidence + results) to a file.",
    )

    payload_group = parser.add_mutually_exclusive_group(required=False)
    payload_group.add_argument(
        "--payload",
        help="Single payload string to test. If omitted, defaults to <script>alert(1)</script>.",
    )
    payload_group.add_argument(
        "--payload-file",
        help="Text file containing payloads. One payload per line. Supports # comments.",
    )

    parser.add_argument(
        "--stop-on-first",
        action="store_true",
        help="Stop scanning a target after first vulnerable payload match. Enabled by default behavior per target.",
    )

    return parser.parse_args(argv)


def _load_payloads(args: argparse.Namespace) -> list[str]:
    if args.payload_file:
        p = Path(args.payload_file)
        if not p.exists():
            raise FileNotFoundError(f"Payload file not found: {p}")
        payloads: list[str] = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            payloads.append(s)
        if not payloads:
            raise ValueError("Payload file contained no valid payloads.")
        return payloads

    if args.payload:
        return [args.payload]

    # Default safe baseline
    return ["<script>alert(1)</script>"]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    extra_headers = parse_headers(args.header)
    payloads = _load_payloads(args)

    if args.url:
        targets = [parse_target(args.url)]
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] Targets file not found: {file_path}")
            return 2
        targets = load_targets(file_path.read_text(encoding="utf-8", errors="ignore").splitlines())

    if not targets:
        print("[!] No valid targets loaded.")
        return 2

    results: list[dict] = []
    vulnerable_targets: list[str] = []

    bundle_meta = {
        "tool": "Sternsleuth-Citrix-NetScaler-RXSS",
        "path": args.path,
        "timeout": args.timeout,
        "rate_seconds": args.rate,
        "insecure": bool(args.insecure),
        "no_color": bool(args.no_color),
        "quiet": bool(args.quiet),
        "headers": extra_headers,
        "payload_source": "payload-file" if args.payload_file else ("payload" if args.payload else "default"),
        "payload_count": len(payloads),
        "targets_count": len(targets),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    for i, t in enumerate(targets, start=1):
        # Rate limiting between targets to avoid accidental flooding
        if i > 1 and args.rate and args.rate > 0:
            time.sleep(args.rate)

        target_any_vuln = False

        for p_idx, payload in enumerate(payloads, start=1):
            r = scan_target(
                target_raw=t.raw,
                host=t.host,
                port=t.port,
                scheme=t.scheme,
                path=args.path,
                payload=payload,
                timeout=args.timeout,
                extra_headers=extra_headers,
                insecure=args.insecure,
                capture_evidence=True,
            )

            results.append(r.to_dict())

            if r.vulnerable:
                target_any_vuln = True
                if t.raw not in vulnerable_targets:
                    vulnerable_targets.append(t.raw)

                if args.quiet:
                    print(f"[VULNERABLE] {t.raw} payload={payload}")
                else:
                    print_result_human(r, no_color=args.no_color)

                # By default, stop at first vuln payload per target to keep traffic minimal.
                # If you want to keep testing all payloads, remove this break.
                break

            if not args.quiet:
                print_result_human(r, no_color=args.no_color)

            # Optional: tiny intra-target delay if you test many payloads.
            # Keep it minimal but polite. This is separate from --rate which is per target.
            if len(payloads) > 1 and args.rate and args.rate > 0:
                time.sleep(min(args.rate, 0.5))

            if args.stop_on_first and target_any_vuln:
                break

    if args.out:
        Path(args.out).write_text(
            "\n".join(vulnerable_targets) + ("\n" if vulnerable_targets else ""),
            encoding="utf-8",
        )

    if args.json_out:
        report_bundle = {
            "meta": bundle_meta,
            "vulnerable_targets": vulnerable_targets,
            "results": results,
            "how_to_reproduce": {
                "example_single_target": f'cve-2025-12101 -u https://target -H "X-HackerOne-Research: <username>" --json results.json',
                "notes": "This JSON includes request previews and response snippets for report-ready evidence.",
            },
        }
        Path(args.json_out).write_text(json.dumps(report_bundle, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
