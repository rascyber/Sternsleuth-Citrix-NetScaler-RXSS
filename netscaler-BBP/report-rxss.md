# Reflected XSS in NetScaler Gateway and AAA `/cgi/logout` via SAML RelayState

## Summary

A reflected cross-site scripting (RXSS) vulnerability exists in **NetScaler Gateway and NetScaler AAA** within the SAML logout handler at `/cgi/logout`.
By supplying a crafted `RelayState` parameter, attacker-controlled input is reflected into the HTML response and **executes arbitrary JavaScript in the victim’s browser context**.

This issue represents a **product-level vulnerability** affecting NetScaler Gateway and NetScaler AAA.
The behavior was reproduced on a customer-owned NetScaler AAA deployment used **solely as a safe reproduction environment**.

---

## Affected Products

- **NetScaler Gateway**
- **NetScaler AAA**
- Endpoint: `/cgi/logout`
- Feature: SAML logout / RelayState processing

The affected logic is shared across Gateway and AAA authentication and logout flows.

---

## Severity

**Medium**

### CVSS v3.1 (Proposed)

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

### CVSS Rationale

- **AV:N** – Exploitable remotely over the network
- **AC:L** – No special conditions or race requirements
- **PR:N** – No authentication required to inject payload
- **UI:R** – Victim interaction required to trigger logout flow
- **S:C** – Script executes in the NetScaler Gateway/AAA origin
- **C:L / I:L** – Ability to read or manipulate browser-accessible content
- **A:N** – No availability impact observed

This aligns with Citrix’s typical classification for exploitable reflected XSS with confirmed browser execution.

---

## Scope Clarification

The proof-of-execution was demonstrated on `https://connect.vivoenergy.com`, which is a **NetScaler AAA deployment**.
This host was used **only as a reproduction environment** to demonstrate NetScaler product behavior.

- No customer or third-party data was accessed
- Only a benign JavaScript payload (`alert(1)`) was executed
- Only researcher-controlled interactions were used

This report is submitted as a **NetScaler product vulnerability**, not as an asset-specific issue.

---

## Steps to Reproduce

1. Send the following POST request to a NetScaler Gateway or NetScaler AAA instance:

```http
POST /cgi/logout HTTP/1.1
Host: <netscaler-host>
User-Agent: Mozilla/5.0 (platform; rv:gecko-version) Gecko/gecko-trail Firefox/firefox-version
Accept: */*
Content-Type: application/x-www-form-urlencoded
Connection: close
X-HackerOne-Research: bebushe

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJ0ZXN0IiBWZXJzaW9uPSIyLjAiPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0idGVzdCIgVmVyc2lvbj0iMi4wIj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRD50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD48L3NhbWw6U3ViamVjdD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U%2B
&RelayState=DQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQoNCjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4=

	2.	Observe the HTTP response:
	•	Status code: 302
	•	Content-Type: text/html
	3.	The response body reflects attacker-controlled content.
	4.	When rendered in a browser (e.g., via a logout flow or auto-submitting form), the injected JavaScript executes.

⸻

Observed Result
	•	Arbitrary JavaScript executes in the browser
	•	Script runs in the NetScaler Gateway/AAA origin
	•	Example payload triggers a JavaScript dialog (alert(1))

⸻

Expected Result

User-controlled SAML parameters such as RelayState should not be reflected into HTML responses without strict context-aware encoding.
Arbitrary script execution should not be possible in logout flows.

⸻

Impact

An attacker could craft a malicious logout request that executes arbitrary JavaScript when triggered by a victim.
This may enable:
	•	Phishing and UI redressing in authentication contexts
	•	Manipulation of user interactions during login/logout flows
	•	Chaining with other client-side weaknesses (e.g., CSRF or token exposure, depending on configuration)

No authentication bypass or sensitive data access was required to demonstrate execution.

⸻

Evidence
	•	Raw HTTP request and response
	•	Browser screenshot demonstrating JavaScript execution
	•	Automated reproduction using a custom RXSS scanner (JSON output attached)

⸻

Remediation Recommendations
	•	Apply strict, context-aware output encoding to RelayState
	•	Reject CRLF and HTML/script injection in SAML parameters
	•	Ensure Content Security Policy is consistently enforced and cannot be bypassed
	•	Avoid rendering user-controlled SAML inputs directly into HTML responses

⸻

Additional Notes
	•	Testing was performed with low request rates
	•	No brute force, denial-of-service, or privacy-impacting activity was conducted
	•	Only researcher-controlled interactions were used
