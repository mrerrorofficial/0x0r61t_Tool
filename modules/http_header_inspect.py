# modules/http_header_inspect.py
import requests

def inspect_headers(url):
    """Fetch and return HTTP headers for the given URL."""
    response = requests.head(url)
    return response.headers