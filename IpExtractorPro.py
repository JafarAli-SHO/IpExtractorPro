import requests
import subprocess
import re
import os
import pyfiglet
from termcolor import colored
# Print the logo
def print_logo():
    figlet = pyfiglet.Figlet(font='digital')
    logo = figlet.renderText("IPExtractorPro")
    colored_logo = colored(logo, color='magenta')
    print(colored_logo)

# Function to perform VirusTotal API request and extract subdomains
def fetch_subdomains_virustotal(domain, api_key):
    api_url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    response = requests.get(api_url)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = data.get('subdomains', [])
        return subdomains
    else:
        print(f"Error fetching subdomains from VirusTotal: {response.status_code}")
        return []

# Function to perform SecurityTrails API request and extract subdomains
def fetch_subdomains_securitytrails(domain, api_key):
    headers = {'APIKEY': api_key}
    api_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = data.get('subdomains', [])
        return [f"{sub}.{domain}" for sub in subdomains]
    else:
        print(f"Error fetching subdomains from SecurityTrails: {response.status_code}")
        return []

# Function to perform DNS queries for A records
def fetch_dns_records(domain):
    try:
        result = subprocess.run(['dig', 'A', domain], capture_output=True, text=True).stdout
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result)
        return ips
    except Exception as e:
        print(f"Error fetching DNS records for {domain}: {e}")
        return []

# Main function to orchestrate the entire process
def main():
    print_logo()
    if not os.path.exists('config.txt'):
        with open('config.txt', 'w') as config_file:
            vtotal_api = input(colored("Enter your VirusTotal API key: ",color='cyan')).strip()
            securitytrails_api = input("Enter your SecurityTrails API key: ").strip()
            config_file.write(f"{vtotal_api}\n{securitytrails_api}")
    else:
        with open('config.txt', 'r') as config_file:
            vtotal_api, securitytrails_api = config_file.read().splitlines()

    url = input("Enter the URL (e.g., https://example.com): ").strip()
    domain = url.replace('https://', '').replace('http://', '')

    # Fetch subdomains from both VirusTotal and SecurityTrails
    print("[*]Fetching subdomain from virustotal and security trails")
    subdomains_vt = fetch_subdomains_virustotal(domain, vtotal_api)
    subdomains_st = fetch_subdomains_securitytrails(domain, securitytrails_api)
    subdomains = list(set(subdomains_vt + subdomains_st))
    if not subdomains:
        print("No subdomains found.")
        return

    all_ips = set()
    for index, subdomain in enumerate(subdomains, start=1):
        print(f"[-] Scanning Subdomains: {index}/{len(subdomains)}")
        ips = fetch_dns_records(subdomain)
        all_ips.update(ips)
        print(f"{index} - {subdomain} - IPs: {', '.join(ips)}")

    if not all_ips:
        print("No IP addresses found.")
    else:
        print("\nExtracted IP addresses:")
        for ip in sorted(all_ips):
            #print(ip)
             print(colored(ip, color='magenta'))
if __name__ == "__main__":
    main()
