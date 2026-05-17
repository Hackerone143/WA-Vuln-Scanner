import socket
from urllib.parse import urlparse
import ipaddress

class ValidationError(Exception):
    pass

class TargetValidator:
    def __init__(self, allow_internal=False):
        self.allow_internal = allow_internal

    def validate(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValidationError("Invalid URL format.")
            
        hostname = parsed.hostname
        if not hostname:
            raise ValidationError("Could not extract hostname.")
            
        if not self.allow_internal:
            try:
                ip = socket.gethostbyname(hostname)
                if ipaddress.ip_address(ip).is_private:
                    raise ValidationError(f"Hostname {hostname} resolves to private IP {ip}. Internal scanning is disabled. Use --allow-internal to enable.")
            except socket.gaierror:
                pass # Unresolvable, let requester handle it
            except ValueError:
                pass # Invalid IP format

        return url

    def extract_base(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
