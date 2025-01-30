# core/utils.py
import re
import socket

def validate_ip(ip):
    """Validate the given IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_hostname(hostname):
    """Validate the given hostname."""
    if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", hostname):
        return True
    return False

def extract_hostname(url):
    """Extract hostname from a URL."""
    if url.startswith("http://") or url.startswith("https://"):
        return url.split("://")[1].split("/")[0]
    return url
