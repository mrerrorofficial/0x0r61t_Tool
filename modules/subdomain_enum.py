# modules/subdomain_enum.py
import requests
from core.utils import extract_hostname

def enum_subdomains(target, wordlist):
    """Enumerate subdomains on the target using the provided wordlist."""
    hostname = extract_hostname(target)
    subdomains = []
    with open(wordlist, 'r') as f:
        for line in f:
            subdomain = line.strip()
            url = f"http://{subdomain}.{hostname}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    subdomains.append(subdomain)
            except requests.ConnectionError:
                pass
    return subdomains
