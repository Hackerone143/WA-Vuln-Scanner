"""
AutoVulnX - XSS Scanner
Detects Reflected XSS by injecting payloads into:
  - URL query parameters
  - HTML form fields (GET and POST)

Detection strategy: payload reflection in the response body.
"""

import os
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from core.requester import Requester
from core.crawler import CrawlResult
from utils.logger import get_logger
from utils.helpers import inject_param, get_param_names, response_contains, truncate

logger = get_logger(__name__)

PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "../../payloads/xss.txt")

# A unique marker embedded in each payload so we can detect reflection
# without false-positiving on the payload appearing in a different context
MARKER = "AutoVulnX"

# We only need a small subset for speed on low-end hardware
MAX_PAYLOADS_PER_POINT = 5


@dataclass
class XSSFinding:
    severity: str
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    vuln_type: str = "Reflected XSS"


def _load_payloads(max_count: int = MAX_PAYLOADS_PER_POINT) -> list[str]:
    try:
        with open(PAYLOAD_FILE) as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads[:max_count]
    except FileNotFoundError:
        logger.warning(f"[XSS] Payload file not found: {PAYLOAD_FILE}")
        return ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']


def scan(requester: Requester, crawl_result: CrawlResult, dom_xss: bool = False) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    payloads = _load_payloads()

    logger.info(f"[XSS] Starting scan with {len(payloads)} payload(s)")

    # --- 1. Test parameterised URLs (GET) ---
    for url in crawl_result.parameterised_urls:
        param_names = get_param_names(url)
        for param in param_names:
            result = _test_url_param(requester, url, param, payloads)
            findings.extend(result)
            if result:
                break  # param is vulnerable, move to next URL

    # --- 2. Test forms ---
    for form in crawl_result.forms:
        result = _test_form(requester, form, payloads)
        findings.extend(result)
        
    # --- 3. Test DOM XSS ---
    if dom_xss:
        logger.info("[XSS] DOM XSS scanning enabled.")
        for url in crawl_result.visited_urls:
            # We would statically analyze the HTML/JS for sinks or use a headless browser.
            # Here we do a mock check for document.write or innerHTML.
            resp = requester.get(url)
            if resp and ("document.write" in resp.text or "innerHTML" in resp.text):
                finding = XSSFinding(
                    severity="MEDIUM",
                    url=url,
                    method="GET",
                    parameter="DOM_SINK",
                    payload="<script>alert(1)</script>",
                    evidence="DOM Sink (document.write / innerHTML) detected",
                    vuln_type="DOM XSS"
                )
                findings.append(finding)
                logger.warning(f"[XSS][MEDIUM] Potential DOM XSS sink found at url={truncate(url, 80)}")

    logger.info(f"[XSS] Scan complete. {len(findings)} finding(s).")
    return findings


def _test_url_param(
    requester: Requester,
    url: str,
    param: str,
    payloads: list[str],
) -> list[XSSFinding]:
    findings = []

    for payload in payloads:
        injected_url = inject_param(url, param, payload)
        resp = requester.get(injected_url)

        if resp is None:
            continue

        if response_contains(resp, payload, case_sensitive=True):
            evidence = _extract_evidence(resp.text, payload)
            finding = XSSFinding(
                severity="HIGH",
                url=injected_url,
                method="GET",
                parameter=param,
                payload=payload,
                evidence=evidence,
            )
            findings.append(finding)
            logger.warning(
                f"[XSS][HIGH] Reflected XSS — param='{param}' "
                f"url={truncate(injected_url, 80)}"
            )
            break  # One confirmed hit per param is enough

    return findings


def _test_form(
    requester: Requester,
    form: dict,
    payloads: list[str],
) -> list[XSSFinding]:
    findings = []
    url = form["url"]
    method = form["method"]
    inputs = form["inputs"]

    # Skip forms with no text-like inputs
    injectable = [
        i for i in inputs
        if i["type"] not in ("submit", "button", "image", "reset", "file", "hidden")
    ]

    if not injectable:
        return findings

    for payload in payloads:
        # Build form data with payload in every injectable field
        data = {i["name"]: i["value"] for i in inputs}
        for inp in injectable:
            data[inp["name"]] = payload

        if method == "POST":
            resp = requester.post(url, data=data)
        else:
            resp = requester.get(url, params=data)

        if resp is None:
            continue

        if response_contains(resp, payload, case_sensitive=True):
            param_name = ", ".join(i["name"] for i in injectable)
            evidence = _extract_evidence(resp.text, payload)
            finding = XSSFinding(
                severity="HIGH",
                url=url,
                method=method,
                parameter=param_name,
                payload=payload,
                evidence=evidence,
                vuln_type="Reflected XSS (Form)",
            )
            findings.append(finding)
            logger.warning(
                f"[XSS][HIGH] Reflected XSS (form) — fields='{param_name}' "
                f"url={truncate(url, 80)}"
            )
            break

    return findings


def _extract_evidence(body: str, payload: str, context: int = 100) -> str:
    """Return a short snippet around the reflected payload."""
    idx = body.find(payload)
    if idx == -1:
        return "(payload reflected — context extraction failed)"
    start = max(0, idx - context)
    end = min(len(body), idx + len(payload) + context)
    snippet = body[start:end].replace("\n", " ").replace("\r", "")
    return truncate(snippet, 250)
