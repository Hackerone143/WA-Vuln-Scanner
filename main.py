#!/usr/bin/env python3
"""
AutoVulnX — Automated OWASP Top 10 Vulnerability Scanner
=========================================================
Usage:
    python main.py -u https://example.com
    python main.py -u https://example.com --xss --sqli --report html json
    python main.py -u https://example.com --all --verbose --delay 1.0

This tool is intended ONLY for authorised security testing.
Unauthorised scanning may violate laws and regulations.
"""

import sys
import argparse
import time

import utils.logger as log_config
from utils.logger import get_logger

from core.validator import TargetValidator, ValidationError
from core.requester import Requester
from core.crawler import Crawler
from reports.generator import ReportGenerator

BANNER = r"""
    _         _     __     __     _      __  __
   / \  _   _| |_ __\ \   / /   | |__  \ \/ /
  / _ \| | | | __/ _ \ \ / /____| '_ \  \  /
 / ___ \ |_| | || (_) \ V /_____| | | | /  \
/_/   \_\__,_|\__\___/ \_/      |_| |_|/_/\_\

 AutoVulnX — OWASP Top 10 Scanner
 For authorised testing only.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="AutoVulnX",
        description="Automated OWASP Top 10 vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python main.py -u https://example.com --all --report html json",
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")

    # Module selection
    module_group = parser.add_argument_group("Scan modules (defaults: all enabled)")
    module_group.add_argument("--all",    action="store_true", help="Enable all modules (default)")
    module_group.add_argument("--headers",action="store_true", help="Security headers scan")
    module_group.add_argument("--xss",    action="store_true", help="Reflected XSS scan")
    module_group.add_argument("--sqli",   action="store_true", help="SQL injection scan")
    module_group.add_argument("--redirect",action="store_true",help="Open redirect scan")
    module_group.add_argument("--sensitive",action="store_true",help="Sensitive file / info disclosure scan")
    module_group.add_argument("--csrf",   action="store_true", help="CSRF token detection")

    # Crawl settings
    crawl_group = parser.add_argument_group("Crawler settings")
    crawl_group.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    crawl_group.add_argument("--max-depth", type=int, default=3,  help="BFS depth limit (default: 3)")
    crawl_group.add_argument("--js-render", action="store_true", help="Enable JavaScript rendering (requires playwright)")

    # Request settings
    req_group = parser.add_argument_group("Request settings")
    req_group.add_argument("--delay",   type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    req_group.add_argument("--timeout", type=int,   default=10,  help="Request timeout in seconds (default: 10)")
    req_group.add_argument("--proxy",   type=str,   default=None,help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    req_group.add_argument("--no-verify", action="store_true",   help="Disable SSL certificate verification")
    req_group.add_argument("--auth-cookie", type=str, default=None, help="Authentication cookie string")
    req_group.add_argument("--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    req_group.add_argument("--allow-internal", action="store_true", help="Allow scanning of internal/private IPs")
    req_group.add_argument("--dom-xss", action="store_true", help="Enable DOM XSS detection (requires js-render)")

    # Output
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("--report",  nargs="+", choices=["terminal", "html", "json"],
                            default=["terminal"], help="Report format(s) (default: terminal)")
    out_group.add_argument("--output-dir", default="reports/", help="Directory for report files (default: reports/)")
    out_group.add_argument("-v", "--verbose", action="store_true", help="Verbose / debug logging")

    return parser.parse_args()


def resolve_modules(args: argparse.Namespace) -> dict[str, bool]:
    """
    If no specific modules are flagged (and --all isn't set),
    default to running everything.
    """
    explicit = any([args.headers, args.xss, args.sqli, args.redirect, args.sensitive, args.csrf])

    if args.all or not explicit:
        return {m: True for m in ("headers", "xss", "sqli", "redirect", "sensitive", "csrf")}

    return {
        "headers":   args.headers,
        "xss":       args.xss,
        "sqli":      args.sqli,
        "redirect":  args.redirect,
        "sensitive": args.sensitive,
        "csrf":      args.csrf,
    }


def main():
    print(BANNER)
    args = parse_args()

    # Configure logging first
    log_config.configure(verbose=args.verbose)
    logger = get_logger("main")

    # ── 1. Validate target ──
    validator = TargetValidator(allow_internal=args.allow_internal)
    try:
        target = validator.validate(args.url)
    except ValidationError as e:
        print(f"\n[ERROR] {e}\n")
        sys.exit(1)

    base_url = validator.extract_base(target)
    modules = resolve_modules(args)

    logger.info(f"Target  : {target}")
    logger.info(f"Base URL: {base_url}")
    logger.info(f"Modules : {', '.join(k for k, v in modules.items() if v)}")

    # ── 2. Set up requester ──
    requester = Requester(
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not args.no_verify,
        proxy=args.proxy,
        auth_cookie=args.auth_cookie,
        waf_bypass=args.waf_bypass
    )

    # ── 3. Crawl ──
    crawler = Crawler(
        requester=requester,
        base_url=target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        js_render=args.js_render
    )
    crawl_result = crawler.crawl()

    # ── 4. Run scanner modules ──
    report = ReportGenerator(target=target)
    scan_start = time.time()

    if modules.get("headers"):
        from modules.headers.scanner import scan as scan_headers
        findings = scan_headers(requester, target)
        report.add_findings("Security Headers", findings)

    if modules.get("xss"):
        from modules.xss.scanner import scan as scan_xss
        findings = scan_xss(requester, crawl_result, dom_xss=args.dom_xss)
        report.add_findings("XSS", findings)

    if modules.get("sqli"):
        from modules.sqli.scanner import scan as scan_sqli
        findings = scan_sqli(requester, crawl_result)
        report.add_findings("SQL Injection", findings)

    if modules.get("redirect"):
        from modules.open_redirect.scanner import scan as scan_redirect
        findings = scan_redirect(requester, crawl_result)
        report.add_findings("Open Redirect", findings)

    if modules.get("sensitive"):
        from modules.sensitive.scanner import scan as scan_sensitive
        findings = scan_sensitive(requester, base_url)
        report.add_findings("Sensitive Files", findings)

    if modules.get("csrf"):
        from modules.csrf.scanner import scan as scan_csrf
        findings = scan_csrf(requester, crawl_result, base_url)
        report.add_findings("CSRF", findings)

    scan_duration = time.time() - scan_start
    logger.info(f"Scan completed in {scan_duration:.1f}s")

    # ── 5. Generate reports ──
    formats = args.report
    if "terminal" not in formats:
        formats = ["terminal"] + formats  # Always show terminal output

    output_paths = report.generate(formats=formats, output_dir=args.output_dir)

    for fmt, path in output_paths.items():
        print(f"\n  [{fmt.upper()} report] → {path}")

    requester.close()


if __name__ == "__main__":
    main()
