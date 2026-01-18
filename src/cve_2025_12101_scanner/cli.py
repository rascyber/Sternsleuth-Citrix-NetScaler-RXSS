from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import print_result_human, scan_target
from .utils import load_targets, parse_headers, parse_target


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner for CVE-2025-12101. Citrix NetScaler RXSS reflection check.",
        allow_abbrev=False,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single target URL, e.g. https://example.com")
    target_group.add_argument(
        "-f",
        "--file",
        help="Text file with targets. One URL per line. Supports # comments.",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help="Add custom header, format: 'Key: Value'. Repeat for multiple headers.",
    )

    parser.add_argument("--timeout", type=int, default=15, help="Timeout seconds (default: 15)")
    parser.add_argument(
        "--show-raw",
        action="store_true",
        help="Print raw HTTP responses (noisy). Recommended only for single targets.",
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
        help="Write full scan results to a JSON file.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    extra_headers = parse_headers(args.header)

    if args.url:
        targets = [parse_target(args.url)]
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] Targets file not found: {file_path}")
            return 2
        targets = load_targets(file_path.read_text(encoding="utf-8").splitlines())

    if not targets:
        print("[!] No valid targets loaded.")
        return 2

    results = []
    vulnerable_targets: list[str] = []

    for t in targets:
        result, raw = scan_target(
            t,
            timeout=args.timeout,
            extra_headers=extra_headers,
            show_raw=args.show_raw,
        )

        results.append(result.to_dict())

        if result.vulnerable:
            vulnerable_targets.append(t.raw)

        if args.quiet:
            if result.vulnerable:
                print(f"[VULNERABLE] {t.raw}")
        else:
            print_result_human(result, raw_response=raw)

    if args.out:
        Path(args.out).write_text("\n".join(vulnerable_targets) + ("\n" if vulnerable_targets else ""), encoding="utf-8")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
