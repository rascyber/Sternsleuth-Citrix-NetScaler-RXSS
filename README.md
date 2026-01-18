# CVE-2025-12101 Scanner (Citrix NetScaler RXSS)

A small, public-friendly scanner for **CVE-2025-12101**. It sends a raw HTTP POST to `/cgi/logout` with the known SAMLResponse and RelayState payload and checks whether `"<script>alert(1)</script>"` is reflected in the response.

This project is based on public research. Use only on systems you are explicitly authorized to test.

## Features
- Single target scanning: `-u https://host`
- Bulk scanning from a file: `-f targets.txt`
- Ignores blank lines and `# comments` in targets files
- Optional custom header injection (example: HackerOne research header)
- Output to text file and optional JSON output
- Quiet mode for mass runs

## Install
Requires Python 3.10+.

```bash
git clone <your-repo-url>
cd cve-2025-12101-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
