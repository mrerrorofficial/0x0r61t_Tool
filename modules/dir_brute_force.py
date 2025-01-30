# modules/dir_brute_force.py
import requests

def brute_force_dirs(target, wordlist):
    """Brute force directories on the target using the provided wordlist."""
    dirs = []
    with open(wordlist, 'r') as f:
        for line in f:
            directory = line.strip()
            url = f"{target}/{directory}"
            response = requests.get(url)
            if response.status_code == 200:
                dirs.append(directory)
    return dirs
