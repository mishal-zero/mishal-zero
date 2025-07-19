import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urlparse, urljoin
import subprocess

# Initialize
visited_urls = set()
parameters_found = {}

def crawl(url, max_depth=3, current_depth=0):
    if current_depth > max_depth or url in visited_urls:
        return
    visited_urls.add(url)
    print(f"[*] Crawling: {url}")

    try:
        # Fetch the page
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links and queue them for crawling
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            if urlparse(next_url).netloc == urlparse(url).netloc:  # Stay on same domain
                crawl(next_url, max_depth, current_depth + 1)

        # Extract forms (GET/POST parameters)
        for form in soup.find_all('form'):
            form_action = urljoin(url, form.get('action', ''))
            form_method = form.get('method', 'get').lower()
            inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all('input') if inp.get('name')}
            
            if form_method == 'get':
                test_url = f"{form_action}?{'&'.join([f'{k}=19' for k in inputs.keys()])}"
                test_reflection(test_url, inputs.keys())
            elif form_method == 'post':
                test_data = {k: '19' for k in inputs.keys()}
                test_reflection(form_action, test_data.keys(), method='POST', data=test_data)

    except Exception as e:
        print(f"[!] Error crawling {url}: {e}")

def test_reflection(url, params, method='GET', data=None):
    for param in params:
        try:
            if method == 'GET':
                test_url = f"{url}?{param}=19"
                response = requests.get(test_url)
            elif method == 'POST':
                response = requests.post(url, data={param: '19'})
            
            # Check if '19' is reflected
            if '19' in response.text:
                parameters_found[param] = f"{param} (Reflected)"
                print(f"[+] Found reflected parameter: {param} in {url}")
            else:
                parameters_found[param] = f"{param} (Not Reflected)"
        except Exception as e:
            print(f"[!] Error testing {param}: {e}")

def run_arjun(url):
    print("[*] Running Arjun for parameter discovery...")
    try:
        # Run Arjun and save results to JSON
        subprocess.run(f"arjun -u {url} -o arjun_results.json --stable", shell=True, check=True)
        
        # Load and test Arjun's findings
        with open('arjun_results.json') as f:
            data = json.load(f)
            for param in data.get('params', []):
                test_url = f"{url}?{param}=19"
                response = requests.get(test_url)
                if '19' in response.text:
                    parameters_found[param] = f"{param} (Reflected)"
                else:
                    parameters_found[param] = f"{param} (Not Reflected)"
    except Exception as e:
        print(f"[!] Arjun failed: {e}")

if __name__ == "__main__":
    target_url = input("Enter target URL (e.g., https://example.com): ").strip()
    crawl(target_url)
    run_arjun(target_url)
    
    # Print final results
    print("\n[+] Parameter Reflection Results:")
    for param, status in parameters_found.items():
        print(f"- {status}")
