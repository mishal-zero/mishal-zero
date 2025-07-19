import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import re

visited = set()
results = []

def find_parameters(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return qs.keys()

def test_reflection(url, param):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = ['19']
    new_query = urlencode(qs, doseq=True)
    new_url = parsed._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, timeout=5)
        if '19' in response.text:
            return "Reflected"
        else:
            return "Not Reflected"
    except Exception as e:
        return f"Error: {e}"

def crawl(url, max_depth=3, depth=0):
    if url in visited or depth > max_depth:
        return
    visited.add(url)

    try:
        res = requests.get(url, timeout=5)
    except Exception:
        return

    soup = BeautifulSoup(res.text, "html.parser")
    links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]

    for link in links:
        parsed = urlparse(link)
        if parsed.scheme.startswith('http'):
            params = find_parameters(link)
            for param in params:
                status = test_reflection(link, param)
                results.append((link, param, status))
                print(f"[+] {link} -> {param} = {status}")
            crawl(link, max_depth, depth + 1)

# === MAIN ===
start_url = "https://sshssonline.com/"  # change this to your target
crawl(start_url)

# Output Summary
print("\n--- Results ---")
for url, param, status in results:
    print(f"{url} :: {param} -> {status}")

