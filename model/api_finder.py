"""
API-Based Subdomain Finder
Alternative to command-line tools - uses free public APIs
No installation required!
"""

import requests
import json
from typing import List, Set
import time


class APISubdomainFinder:
    """Find subdomains using free public APIs"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

    def find_subdomains(self, domain: str) -> Set[str]:
        """Find subdomains using multiple free APIs"""
        all_subdomains = set()

        print(f"🔍 Searching for subdomains of {domain}...")

        # 1. crt.sh - Certificate Transparency Logs
        print("  [1/4] Checking crt.sh...")
        all_subdomains.update(self._crtsh(domain))

        # 2. HackerTarget
        print("  [2/4] Checking HackerTarget...")
        all_subdomains.update(self._hackertarget(domain))

        # 3. ThreatCrowd
        print("  [3/4] Checking ThreatCrowd...")
        all_subdomains.update(self._threatcrowd(domain))

        # 4. VirusTotal (no API key needed for basic)
        print("  [4/4] Checking DNS records...")
        all_subdomains.update(self._dnsdumpster_alternative(domain))

        print(f"✓ Found {len(all_subdomains)} unique subdomains")
        return all_subdomains

    def _crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Split by newlines (crt.sh can return multiple names)
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain.endswith(domain):
                            # Remove wildcards
                            subdomain = subdomain.replace("*.", "")
                            if subdomain:
                                subdomains.add(subdomain)
        except Exception as e:
            print(f"    Warning: crt.sh failed - {e}")

        return subdomains

    def _hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                text = response.text
                for line in text.split("\n"):
                    if "," in line:
                        subdomain = line.split(",")[0].strip().lower()
                        if subdomain and subdomain.endswith(domain):
                            subdomains.add(subdomain)
        except Exception as e:
            print(f"    Warning: HackerTarget failed - {e}")

        return subdomains

    def _threatcrowd(self, domain: str) -> Set[str]:
        """Query ThreatCrowd API"""
        subdomains = set()
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if "subdomains" in data:
                    for subdomain in data["subdomains"]:
                        subdomain = subdomain.strip().lower()
                        if subdomain:
                            subdomains.add(subdomain)
        except Exception as e:
            print(f"    Warning: ThreatCrowd failed - {e}")

        return subdomains

    def _dnsdumpster_alternative(self, domain: str) -> Set[str]:
        """Try to find common subdomains"""
        subdomains = set()
        common_prefixes = [
            "www",
            "mail",
            "ftp",
            "localhost",
            "webmail",
            "smtp",
            "webdisk",
            "pop",
            "cpanel",
            "whm",
            "ns1",
            "ns2",
            "autodiscover",
            "autoconfig",
            "api",
            "dev",
            "staging",
            "admin",
            "portal",
            "vpn",
            "secure",
            "login",
        ]

        import socket

        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
            except:
                pass

        return subdomains


def main():
    """Test the API finder"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_finder.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    finder = APISubdomainFinder()

    start_time = time.time()
    subdomains = finder.find_subdomains(domain)
    elapsed = time.time() - start_time

    print(f"\n{'='*60}")
    print(f"Results for {domain}")
    print(f"{'='*60}")
    print(f"Total subdomains: {len(subdomains)}")
    print(f"Execution time: {elapsed:.2f}s")
    print(f"\nSubdomains found:")
    for subdomain in sorted(subdomains):
        print(f"  • {subdomain}")

    # Save to file
    output_file = f"{domain.replace('.', '_')}_subdomains.txt"
    with open(output_file, "w") as f:
        for subdomain in sorted(subdomains):
            f.write(f"{subdomain}\n")

    print(f"\n💾 Results saved to: {output_file}")


if __name__ == "__main__":
    main()
