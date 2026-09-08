import requests
import re
import ipaddress
from tqdm import tqdm

# List of blocklist URLs and expected line formats
blocklist_sources = {
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "CI Army List": "https://cinsscore.com/list/ci-badguys.txt",
    "IPsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "BlockList.de": "https://www.blocklist.de/lists/all.txt",
    "Blocklist.de - SSH": "https://www.blocklist.de/lists/ssh.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
}

# Tor Exit Node Source
tor_exit_nodes_url = "https://check.torproject.org/exit-addresses"


def extract_ips(source_name, url):
    """Fetches data from the given URL and extracts IP addresses in CIDR format."""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {source_name} from {url}: {e}")
        return ips

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        # MODIFIED: Preserve CIDR notation if it already exists
        if "/" in line:
            try:
                # Validate it's a real network and add it
                net = ipaddress.ip_network(line, strict=False)
                ips.add(net.with_prefixlen)
            except ValueError:
                continue
        else:
            # MODIFIED: Convert single IPs to CIDR notation
            try:
                ip_obj = ipaddress.ip_address(line)
                if ip_obj.version == 4:
                    ips.add(f"{line}/32")
                else:
                    ips.add(f"{line}/128")
            except ValueError:
                continue
    return ips


def extract_tor_exit_nodes(url):
    """Fetches Tor exit node IPs and returns them in CIDR format."""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Tor exit nodes from {url}: {e}")
        return ips

    for line in content.splitlines():
        if line.startswith("ExitAddress"):
            parts = line.split(" ")
            if len(parts) > 1:
                ip_str = parts[1].strip()
                # MODIFIED: Convert single IPs to CIDR notation
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.version == 4:
                        ips.add(f"{ip_str}/32")
                    else:
                        ips.add(f"{ip_str}/128")
                except ValueError:
                    continue
    return ips


def main():
    combined_ips = set()
    for source_name, url in tqdm(blocklist_sources.items(), desc="Processing Blocklists"):
        print(f"Processing {source_name} from {url}")
        ips = extract_ips(source_name, url)
        print(f"  Found {len(ips)} IPs/CIDRs in {source_name}")
        combined_ips.update(ips)

    # Tor Exit Node Processing
    tor_exit_ips = extract_tor_exit_nodes(tor_exit_nodes_url)
    print(f"Total Tor exit node IPs/CIDRs: {len(tor_exit_ips)}")
    combined_ips.update(tor_exit_ips)

    print(f"Total Unique IPs/CIDRs after deduplication: {len(combined_ips)}")

    # MODIFIED: The final write loop is simpler. The sorting key is removed as sorting CIDRs as integers is incorrect.
    # A simple lexicographical sort is sufficient here.
    with open("ip_blacklist.txt", "w") as f:
        for ip_cidr in sorted(list(combined_ips)):
            f.write(f"{ip_cidr}\n")

    print("IP blacklist saved to ip_blacklist.txt")


if __name__ == "__main__":
    main()
