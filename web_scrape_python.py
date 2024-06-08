import requests
from bs4 import BeautifulSoup
from googlesearch import search
import sublist3r
import nmap
from Wappalyzer import Wappalyzer, WebPage
import subprocess

def scrape_google_results(query, num_results=10):
    results = []
    for url in search(query, num=num_results, stop=num_results, pause=2):
        results.append(url)
    return results

def scrape_web_page(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def find_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')
    return nm[target]

def gather_tech_info(url):
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        return technologies
    except Exception as e:
        print(f"Error gathering tech info for {url}: {e}")
        return []

def run_bandit(target_file):
    result = subprocess.run(['bandit', '-r', target_file], capture_output=True, text=True)
    return result.stdout

def save_to_document(content, filename="results.txt"):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)

def main():
    query = input("Enter search query: ")
    num_results = int(input("Enter number of results to fetch: "))
    
    # Scrape Google search results
    urls = scrape_google_results(query, num_results)
    
    all_content = ""

    # Scrape each web page
    for url in urls:
        print(f"Scraping {url} ...")
        content = scrape_web_page(url)
        all_content += f"URL: {url}\n\n{content}\n\n{'='*80}\n\n"
    
    # Save scraped content to a document
    save_to_document(all_content, "scraped_results.txt")
    
    # Perform information gathering and security audit on each domain
    for url in urls:
        print(f"Information gathering for {url} ...")
        domain = url.split('//')[-1].split('/')[0]
        
        # Subdomain enumeration
        subdomains = find_subdomains(domain)
        all_content += f"Subdomains of {domain}:\n{subdomains}\n\n{'='*80}\n\n"
        
        # Port scanning
        port_info = scan_ports(domain)
        all_content += f"Port scan results for {domain}:\n{port_info}\n\n{'='*80}\n\n"
        
        # Technology identification
        tech_info = gather_tech_info(url)
        all_content += f"Technologies used by {url}:\n{tech_info}\n\n{'='*80}\n\n"

        # Security audit using Bandit (as an example; it requires a Python codebase)
        # Assuming we have a local codebase to audit
        # Replace 'path_to_codebase' with the actual path of the codebase you want to audit
        bandit_results = run_bandit('path_to_codebase')
        all_content += f"Security audit results:\n{bandit_results}\n\n{'='*80}\n\n"
    
    # Save all gathered information to a document
    save_to_document(all_content, "security_audit_results.txt")
    print("Information gathering and security audit completed. Results saved to 'security_audit_results.txt'")

if __name__ == "__main__":
    main()
