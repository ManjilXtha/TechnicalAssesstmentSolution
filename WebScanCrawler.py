import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import time

# Function to check HTTP headers for security
def check_http_headers(url):
    headers_to_check = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy']
    missing_headers = []
    
    try:
        response = requests.get(url)
        for header in headers_to_check:
            if header not in response.headers:
                missing_headers.append(header)
    except requests.RequestException as e:
        print(f"Error checking headers for {url}: {e}")
    
    return missing_headers

# Function to detect software versions
def check_software_versions(url):
    outdated_versions = []
    
    try:
        # Check headers for software versions
        response = requests.head(url)
        server_header = response.headers.get('Server', '')
        if 'Apache' in server_header:
            match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
            if match and match.group(1) < '2.4.8':
                outdated_versions.append(f'Apache {match.group(1)}')
        
        # Check the page content for software versions
        response = requests.get(url)
        if 'version' in response.text:
            version_matches = re.findall(r'[\w]+\s*[\d\.\w]+', response.text)
            for version in version_matches:
                outdated_versions.append(version)
    
    except requests.RequestException as e:
        print(f"Error checking versions for {url}: {e}")
    
    return outdated_versions

# Function to check forms for security attributes
def check_forms_for_security(url):
    forms_without_security = []
    
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET')
            
            # Check for missing action or insecure method (GET)
            if not action or method.upper() == 'GET':
                forms_without_security.append(action or 'Unnamed form')
    
    except requests.RequestException as e:
        print(f"Error checking forms for {url}: {e}")
    
    return forms_without_security

# Function to crawl a website and gather vulnerabilities
def crawl_and_scan(url, visited_urls):
    # Avoid revisiting URLs
    if url in visited_urls:
        return []
    
    visited_urls.add(url)
    print(f"Scanning {url} for vulnerabilities...")
    
    vulnerabilities = {
        'missing_http_headers': [],
        'outdated_software': [],
        'insecure_forms': []
    }
    
    # Check for missing HTTP headers
    vulnerabilities['missing_http_headers'] = check_http_headers(url)
    
    # Check for outdated software versions
    vulnerabilities['outdated_software'] = check_software_versions(url)
    
    # Check for insecure forms
    vulnerabilities['insecure_forms'] = check_forms_for_security(url)
    
    # Crawl linked pages on the website
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            full_url = urljoin(url, href)
            # Recursively crawl the linked pages if they are from the same domain
            if urlparse(full_url).netloc == urlparse(url).netloc:
                vulnerabilities += crawl_and_scan(full_url, visited_urls)
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")
    
    return vulnerabilities

# Function to print the results in a user-friendly format
def generate_report(url, vulnerabilities):
    print(f"\nVULNERABILITY SCAN REPORT FOR {url.upper()}:")
    
    if vulnerabilities['missing_http_headers']:
        print(f"- MISSING HTTP SECURITY HEADERS: {', '.join(vulnerabilities['missing_http_headers'])}")
    
    if vulnerabilities['outdated_software']:
        print(f"- OUTDATED SOFTWARE VERSION DETECTED: {', '.join(vulnerabilities['outdated_software'])}")
    
    if vulnerabilities['insecure_forms']:
        print(f"- FORM WITHOUT PROPER METHOD ATTRIBUTE: {', '.join(vulnerabilities['insecure_forms'])}")

# Main function to start the crawler
def main():
    url = input("Enter the URL to scan (e.g., https://example.com): ")
    
    # Ensure the URL starts with http or https
    if not url.startswith(('http://', 'https://')):
        print("Invalid URL format. Please make sure the URL starts with http:// or https://")
        return
    
    visited_urls = set()  # To keep track of visited URLs
    vulnerabilities = crawl_and_scan(url, visited_urls)
    generate_report(url, vulnerabilities)

# Run the crawler
if __name__ == "__main__":
    main()
