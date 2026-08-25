import requests
import os
import re
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# List of URLs containing domain blocklists
DOMAIN_LIST_URLS = [
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/option/domain.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt",
    "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
    "https://raw.githubusercontent.com/fabriziosalmi/blacklists/main/custom/streaming.txt",
]

# File where the final merged and deduplicated domain list will be saved
OUTPUT_FILE = "dns_blacklist.txt"

# Temporary directory to store downloaded domain lists
TEMP_DIR = "temp_domain_lists"
os.makedirs(TEMP_DIR, exist_ok=True)

# Regular expression to match valid FQDNs
FQDN_REGEX = re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')

# Set to store unique domains
domain_set: Set[str] = set()

def is_valid_fqdn(domain: str) -> bool:
    """
    Validates if a domain is a valid FQDN.
    """
    return FQDN_REGEX.match(domain) is not None

def download_domain_list(url: str, temp_dir: str) -> str:
    """
    Downloads a domain list from a given URL and saves it to a temporary directory.
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        filename = os.path.join(temp_dir, os.path.basename(url))
        with open(filename, "w", encoding="utf-8") as f:
            f.write(response.text)
        return filename
    except Exception as e:
        logging.error(f"Failed to download {url}: {e}")
        return None

def process_domain_list(file_path: str):
    """
    Processes a downloaded domain list file and extracts valid FQDNs.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith(("#", "!", "//", "[")):
                # Extract domain from lines like "0.0.0.0 example.com" or "example.com"
                parts = line.split()
                if parts:
                    domain = parts[-1].lower()  # Use the last part as the domain
                    if is_valid_fqdn(domain):
                        domain_set.add(domain)

def download_and_process_all(urls: List[str], temp_dir: str):
    """
    Downloads and processes all domain lists concurrently.
    """
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_domain_list, url, temp_dir): url for url in urls}
        for future in tqdm(as_completed(futures), total=len(urls), desc="Downloading"):
            file_path = future.result()
            if file_path:
                process_domain_list(file_path)

def save_domains_to_file(domains: Set[str], output_file: str):
    """
    Saves the deduplicated domains to the output file.
    """
    with open(output_file, "w", encoding="utf-8") as f:
        for domain in sorted(domains):
            f.write(domain + "\n")
    logging.info(f"Merged domain list saved to {output_file}")

def cleanup_temp_dir(temp_dir: str):
    """
    Cleans up the temporary directory.
    """
    for temp_file in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, temp_file))
    os.rmdir(temp_dir)
    logging.info("Temporary files cleaned up.")

def main():
    # Download and process all domain lists
    download_and_process_all(DOMAIN_LIST_URLS, TEMP_DIR)

    # Save the final list to the output file
    save_domains_to_file(domain_set, OUTPUT_FILE)

    # Print the total count of unique FQDNs
    total_fqdns = len(domain_set)
    logging.info(f"Total unique FQDNs: {total_fqdns}")

    # Clean up temporary files
    cleanup_temp_dir(TEMP_DIR)

if __name__ == "__main__":
    main()
