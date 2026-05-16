"""
AutoVulnX - Web Crawler
Lightweight BFS crawler that stays within the target domain.
Extracts links, forms, query parameters, and interesting paths.
Designed to be memory-safe on low-RAM systems (8 GB laptop).
"""

from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from bs4 import BeautifulSoup

from core.requester import Requester
from utils.logger import get_logger

logger = get_logger(__name__)


class CrawlResult:
    """Container for everything the crawler discovers."""

    def __init__(self):
        self.visited_urls: list[str] = []
        self.forms: list[dict] = []          # [{url, method, inputs: [{name, type, value}]}]
        self.parameterised_urls: list[str] = []  # URLs with ?param=value
        self.interesting_paths: list[str] = []   # admin, backup, .git, etc.

    def summary(self) -> str:
        return (
            f"  Pages crawled   : {len(self.visited_urls)}\n"
            f"  Forms found     : {len(self.forms)}\n"
            f"  Param URLs      : {len(self.parameterised_urls)}\n"
            f"  Interesting     : {len(self.interesting_paths)}"
        )


INTERESTING_KEYWORDS = {
    "admin", "login", "dashboard", "backup", "config",
    "test", "dev", "api", "debug", "secret", ".git",
    ".env", "upload", "manage", "private", "internal",
}


class Crawler:
    """
    BFS web crawler constrained to the target domain.

    Args:
        requester:   Shared Requester instance.
        base_url:    Canonical target URL (e.g. https://example.com).
        max_pages:   Hard cap on pages visited (default 50).
        max_depth:   BFS depth limit (default 3).
    """

    def __init__(
        self,
        requester: Requester,
        base_url: str,
        max_pages: int = 50,
        max_depth: int = 3,
    ):
        self.requester = requester
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._base_netloc = urlparse(base_url).netloc

    def crawl(self) -> CrawlResult:
        """Run the BFS crawl and return a CrawlResult."""
        result = CrawlResult()
        # queue items: (url, depth)
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        seen: set[str] = set()

        logger.info(f"Crawling {self.base_url} (max_pages={self.max_pages}, max_depth={self.max_depth})")

        while queue and len(result.visited_urls) < self.max_pages:
            url, depth = queue.popleft()

            if url in seen:
                continue
            seen.add(url)

            if depth > self.max_depth:
                continue

            resp = self.requester.get(url)
            if resp is None or resp.status_code not in (200, 301, 302):
                continue

            result.visited_urls.append(url)
            logger.debug(f"[{len(result.visited_urls)}/{self.max_pages}] {url}")

            # Check for interesting path keywords
            path = urlparse(url).path.lower()
            if any(kw in path for kw in INTERESTING_KEYWORDS):
                result.interesting_paths.append(url)

            # Track parameterised URLs
            if urlparse(url).query:
                result.parameterised_urls.append(url)

            # Parse HTML
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "lxml")

            # Extract and queue links
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                absolute = self._resolve(url, href)
                if absolute and absolute not in seen:
                    queue.append((absolute, depth + 1))

            # Extract forms
            for form in soup.find_all("form"):
                form_data = self._parse_form(url, form)
                result.forms.append(form_data)

        logger.info(f"Crawl complete.\n{result.summary()}")
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve(self, base: str, href: str) -> str | None:
        """
        Resolve a (possibly relative) href against base.
        Returns None if the resolved URL is outside the target domain,
        is a non-HTTP scheme, or is a fragment-only link.
        """
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            return None

        absolute = urljoin(base, href)
        parsed = urlparse(absolute)

        # Must stay on the same netloc
        if parsed.netloc != self._base_netloc:
            return None

        if parsed.scheme not in ("http", "https"):
            return None

        # Drop fragments to avoid re-crawling same page
        clean = absolute.split("#")[0]
        return clean if clean else None

    def _parse_form(self, page_url: str, form_tag) -> dict:
        """Extract structured data from a <form> tag."""
        action = form_tag.get("action", "")
        action_url = urljoin(page_url, action) if action else page_url
        method = (form_tag.get("method", "get") or "get").upper()

        inputs = []
        for tag in form_tag.find_all(["input", "textarea", "select"]):
            name = tag.get("name") or tag.get("id") or ""
            input_type = tag.get("type", "text").lower()
            value = tag.get("value", "test")

            if not name:
                continue

            inputs.append({
                "name": name,
                "type": input_type,
                "value": value,
            })

        return {
            "url": action_url,
            "method": method,
            "inputs": inputs,
            "source_page": page_url,
        }
