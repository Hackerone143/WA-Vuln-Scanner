from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def get_param_names(url: str) -> list[str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys())

def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param in params:
        params[param] = [payload]
    
    # Rebuild URL
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def response_contains(resp, payload: str, case_sensitive: bool = True) -> bool:
    if not resp or not resp.text:
        return False
    text = resp.text if case_sensitive else resp.text.lower()
    search = payload if case_sensitive else payload.lower()
    return search in text

def truncate(text: str, length: int = 100) -> str:
    if len(text) > length:
        return text[:length-3] + "..."
    return text
