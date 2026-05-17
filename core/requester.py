import requests
import random
import time
from utils.logger import get_logger

logger = get_logger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
]

class Requester:
    def __init__(self, timeout=10, delay=0.5, verify_ssl=True, proxy=None, auth_cookie=None, waf_bypass=False):
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.auth_cookie = auth_cookie
        self.waf_bypass = waf_bypass
        
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if self.proxies:
            self.session.proxies.update(self.proxies)

    def _prepare_kwargs(self, kwargs):
        headers = kwargs.get("headers", {})
        
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie
            
        if self.waf_bypass:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            headers["X-Forwarded-For"] = f"127.0.0.{random.randint(1, 255)}"
            headers["X-Originating-IP"] = "127.0.0.1"
            headers["X-Remote-IP"] = "127.0.0.1"
            headers["X-Remote-Addr"] = "127.0.0.1"
            headers["Client-IP"] = "127.0.0.1"
        else:
            if "User-Agent" not in headers:
                headers["User-Agent"] = "AutoVulnX Scanner"
                
        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout
        return kwargs

    def get(self, url, **kwargs):
        time.sleep(self.delay)
        kwargs = self._prepare_kwargs(kwargs)
        try:
            return self.session.get(url, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.debug(f"GET {url} failed: {e}")
            return None

    def post(self, url, **kwargs):
        time.sleep(self.delay)
        kwargs = self._prepare_kwargs(kwargs)
        try:
            return self.session.post(url, **kwargs)
        except requests.exceptions.RequestException as e:
            logger.debug(f"POST {url} failed: {e}")
            return None

    def close(self):
        self.session.close()
