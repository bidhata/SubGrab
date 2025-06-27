#!/usr/bin/env python3
"""
Enhanced Subdomain Discovery Tool with Shodan Integration
For authorized security testing and bug bounty programs only.
me@krishnendu.com
https://www.linkedin.com/in/krishpaul/ 
"""
import requests
import dns.resolver
import socket
import concurrent.futures
import argparse
import json
import time
import os
import ssl
import re
import shodan

class SubdomainFinder:
    def __init__(self, domain, threads=100, shodan_api_key=None, timeout=3, wordlist_file=None, custom_nameservers=None, scan_ssh=False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.subdomains = set()
        self.active_subdomains = set()
        self.inactive_subdomains = set()
        self.subdomain_details = {}
        self.shodan_api_key = shodan_api_key
        self.wordlist_file = wordlist_file
        self.custom_nameservers = custom_nameservers
        self.scan_ssh = scan_ssh
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        })
        # Configure session for speed
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=1
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # Initialize Shodan API if key provided
        if self.shodan_api_key:
            try:
                self.shodan_api = shodan.Shodan(self.shodan_api_key)
                print(f"[+] Shodan API initialized")
            except Exception as e:
                print(f"[-] Shodan API initialization failed: {e}")
                self.shodan_api = None
        else:
            self.shodan_api = None

    def load_wordlist(self):
        """Load wordlist from external file"""
        wordlist = []
        # Default wordlist
        default_wordlist = [
            'www', 'mail', 'ftp', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'api', 'dev', 'staging', 'test',
            'portal', 'host', 'mx', 'pop', 'imap', 'gateway', 'proxy', 'dashboard',
            'app', 'mobile', 'api1', 'api2', 'v1', 'v2', 'cdn', 'static',
            'img', 'images', 'assets', 'css', 'js', 'media', 'download',
            'files', 'docs', 'support', 'help', 'forum', 'community',
            'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
            'crm', 'erp', 'hr', 'finance', 'sales', 'marketing',
            'news', 'events', 'calendar', 'booking', 'reservation',
            'beta', 'alpha', 'demo', 'sandbox', 'lab', 'internal',
            'intranet', 'extranet', 'vpn', 'remote', 'ssh', 'ftp',
            'sftp', 'git', 'svn', 'jenkins', 'ci', 'cd', 'build',
            'deploy', 'monitor', 'log', 'logs', 'metrics', 'stats',
            'db', 'database', 'mysql', 'postgres', 'redis', 'cache',
            'queue', 'worker', 'task', 'job', 'cron', 'backup',
            'old', 'new', 'legacy', 'archive', 'temp', 'tmp',
            'public', 'private', 'protected', 'secure', 'ssl',
            'wap', 'm', 'mobile', 'tablet', 'touch', 'responsive'
        ]
        # Add numbered variations
        numbered_subs = []
        for sub in ['api', 'cdn', 'mail', 'ftp', 'ns', 'web', 'app']:
            for i in range(1, 11):
                numbered_subs.append(f"{sub}{i}")
        default_wordlist.extend(numbered_subs)
        if self.wordlist_file:
            if os.path.exists(self.wordlist_file):
                print(f"[+] Loading wordlist from {self.wordlist_file}")
                try:
                    with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain and not subdomain.startswith('#'):
                                # Clean the subdomain
                                subdomain = subdomain.lower()
                                # Remove common prefixes that might be in wordlists
                                subdomain = subdomain.replace('http://', '').replace('https://', '')
                                subdomain = subdomain.split('.')[0] if '.' in subdomain else subdomain
                                if subdomain and (subdomain.isalnum() or '-' in subdomain or '_' in subdomain):
                                    wordlist.append(subdomain)
                    print(f"[+] Loaded {len(wordlist)} subdomains from wordlist")
                    # Combine with default wordlist and remove duplicates
                    combined_wordlist = list(set(default_wordlist + wordlist))
                    print(f"[+] Total wordlist size: {len(combined_wordlist)} subdomains")
                    return combined_wordlist
                except Exception as e:
                    print(f"[-] Error loading wordlist: {e}")
                    print(f"[+] Using default wordlist instead")
            else:
                print(f"[-] Wordlist file not found: {self.wordlist_file}")
                print(f"[+] Using default wordlist instead")
        return default_wordlist

    def passive_recon(self):
        """Perform passive reconnaissance using various APIs"""
        print(f"[+] Starting passive reconnaissance for {self.domain}")
        # Certificate Transparency logs
        self.cert_transparency()
        # Shodan search
        self.shodan_search()
        # DNS enumeration
        self.dns_enumeration()
        # Web archives
        self.web_archives()

    def cert_transparency(self):
        """Query Certificate Transparency logs with faster processing"""
        print("[+] Querying Certificate Transparency logs...")
        try:
            # Use multiple CT log sources for better coverage
            ct_sources = [
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                f" https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            ]
            for url in ct_sources:
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    if response.status_code == 200:
                        if 'crt.sh' in url:
                            certificates = response.json()
                            for cert in certificates[:500]:  # Limit for speed
                                name_value = cert.get('name_value', '')
                                for subdomain in name_value.split('\n'):
                                    subdomain = subdomain.strip().replace('*', '')
                                    if subdomain and subdomain.endswith(f'.{self.domain}'):
                                        self.subdomains.add(subdomain)
                                        print(f"[CT] Found: {subdomain}")
                        elif 'certspotter' in url:
                            data = response.json()
                            for entry in data[:100]:  # Limit for speed
                                dns_names = entry.get('dns_names', [])
                                for name in dns_names:
                                    name = name.replace('*', '')
                                    if name.endswith(f'.{self.domain}'):
                                        self.subdomains.add(name)
                                        print(f"[CT-Spot] Found: {name}")
                except Exception as e:
                    print(f"[-] CT source {url} failed: {e}")
                    continue
        except Exception as e:
            print(f"[-] Certificate Transparency error: {e}")

    def dns_enumeration(self):
        """Perform fast DNS enumeration with expanded wordlist"""
        print("[+] Performing fast DNS enumeration...")
        # Load wordlist (external or default)
        wordlist = self.load_wordlist()
        print(f"[+] Testing {len(wordlist)} subdomains with {self.threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_subdomain_fast, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    result = future.result(timeout=1)
                    if result:
                        self.subdomains.add(result)
                        print(f"[DNS] Found: {result}")
                except (concurrent.futures.TimeoutError, Exception):
                    continue

    def web_archives(self):
        """Query web archives for subdomains with faster processing"""
        print("[+] Querying web archives...")
        try:
            # Multiple archive sources
            archive_sources = [
                f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey&limit=1000",
                f" https://otx.alienvault.com/api/v1/indicators/domain/ {self.domain}/passive_dns"
            ]
            for url in archive_sources:
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    if response.status_code == 200:
                        if 'web.archive.org' in url:
                            data = response.json()
                            for entry in data[1:]:  # Skip header
                                if len(entry) > 2:
                                    archived_url = entry[2]
                                    parsed = urlparse(archived_url)
                                    if parsed.hostname and parsed.hostname.endswith(f'.{self.domain}'):
                                        self.subdomains.add(parsed.hostname)
                                        print(f"[Archive] Found: {parsed.hostname}")
                        elif 'alienvault.com' in url:
                            data = response.json()
                            passive_dns = data.get('passive_dns', [])
                            for entry in passive_dns[:200]:  # Limit for speed
                                hostname = entry.get('hostname', '')
                                if hostname.endswith(f'.{self.domain}'):
                                    self.subdomains.add(hostname)
                                    print(f"[OTX] Found: {hostname}")
                except Exception as e:
                    print(f"[-] Archive source failed: {e}")
                    continue
        except Exception as e:
            print(f"[-] Web archive error: {e}")

    def shodan_search(self):
        """Search Shodan for subdomains and IPs"""
        if not self.shodan_api:
            print("[-] Shodan API key not provided, skipping Shodan search")
            return
        print("[+] Searching Shodan...")
        try:
            # Search for hostnames
            hostname_query = f"hostname:{self.domain}"
            results = self.shodan_api.search(hostname_query, limit=100)
            for result in results['matches']:
                # Extract hostnames
                hostnames = result.get('hostnames', [])
                for hostname in hostnames:
                    if hostname.endswith(f'.{self.domain}'):
                        self.subdomains.add(hostname)
                        print(f"[Shodan] Found: {hostname}")
                # Extract SSL certificate hostnames
                ssl_info = result.get('ssl', {})
                if ssl_info:
                    cert = ssl_info.get('cert', {})
                    subject = cert.get('subject', {})
                    if 'CN' in subject:
                        cn = subject['CN']
                        if cn.endswith(f'.{self.domain}'):
                            self.subdomains.add(cn)
                            print(f"[Shodan-SSL] Found: {cn}")
                    # Check Subject Alternative Names
                    extensions = cert.get('extensions', [])
                    for ext in extensions:
                        if ext.get('name') == 'subjectAltName':
                            san_data = ext.get('data', '')
                            # Parse SAN data for DNS names
                            dns_names = re.findall(r'DNS:([^,\s]+)', san_data)
                            for dns_name in dns_names:
                                if dns_name.endswith(f'.{self.domain}'):
                                    self.subdomains.add(dns_name)
                                    print(f"[Shodan-SAN] Found: {dns_name}")
            # Additional search queries
            additional_queries = [
                f'ssl:"{self.domain}"',
                f'org:"{self.domain}"',
                f'html:"{self.domain}"'
            ]
            for query in additional_queries:
                try:
                    results = self.shodan_api.search(query, limit=50)
                    for result in results['matches']:
                        hostnames = result.get('hostnames', [])
                        for hostname in hostnames:
                            if hostname.endswith(f'.{self.domain}'):
                                self.subdomains.add(hostname)
                                print(f"[Shodan-Extra] Found: {hostname}")
                except Exception as e:
                    print(f"[-] Shodan query '{query}' failed: {e}")
        except Exception as e:
            print(f"[-] Shodan search error: {e}")

    def get_shodan_info(self, ip):
        """Get additional information from Shodan for an IP"""
        if not self.shodan_api:
            return None
        try:
            host_info = self.shodan_api.host(ip)
            return {
                'org': host_info.get('org', 'Unknown'),
                'isp': host_info.get('isp', 'Unknown'),
                'country': host_info.get('country_name', 'Unknown'),
                'city': host_info.get('city', 'Unknown'),
                'ports': host_info.get('ports', []),
                'hostnames': host_info.get('hostnames', []),
                'last_update': host_info.get('last_update', 'Unknown')
            }
        except Exception:
            return None

    def check_subdomain_fast(self, subdomain):
        """Fast subdomain checking with optimized DNS resolution"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            # Use custom resolver with shorter timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            if self.custom_nameservers:
                resolver.nameservers = self.custom_nameservers
            answers = resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            return None

    def check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        return self.check_subdomain_fast(subdomain)

    def active_recon(self):
        """Perform active reconnaissance"""
        print(f"[+] Starting active reconnaissance...")
        # Zone transfer attempt
        self.zone_transfer()
        # HTTP enumeration
        self.http_enumeration()
        # SSH port scan
        if self.scan_ssh:
            self.ssh_port_scan()

    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        print("[+] Attempting DNS zone transfer...")
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain))
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}"
                        if subdomain != self.domain:
                            self.subdomains.add(subdomain)
                            print(f"[Zone] Found: {subdomain}")
                except Exception:
                    continue
        except Exception as e:
            print(f"[-] Zone transfer failed: {e}")

    def http_enumeration(self):
        """Fast HTTP-based subdomain enumeration"""
        print(f"[+] HTTP enumeration on {len(self.subdomains)} subdomains...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_http_fast, sub) for sub in self.subdomains]
            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    result = future.result(timeout=1)
                    if result:
                        subdomain = result['subdomain']
                        self.active_subdomains.add(subdomain)
                        self.subdomain_details[subdomain] = result
                        print(f"[HTTP-Active] {subdomain} [{result['status']}] via {result['scheme']}")
                    else:
                        # This subdomain exists in DNS but not HTTP-accessible
                        pass
                except (concurrent.futures.TimeoutError, Exception):
                    continue
        # Determine inactive subdomains (found in DNS but not HTTP-accessible)
        self.inactive_subdomains = self.subdomains - self.active_subdomains
        print(f"[+] Active subdomains: {len(self.active_subdomains)}")
        print(f"[+] Inactive subdomains: {len(self.inactive_subdomains)}")

    def check_http_fast(self, subdomain):
        """Fast HTTP response check for subdomain"""
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                return {
                    'subdomain': subdomain,
                    'status': response.status_code,
                    'scheme': scheme,
                    'ip': self.get_real_ip_fast(subdomain),
                    'title': self.extract_title(response.text) if response.text else None,
                    'server': response.headers.get('Server', 'Unknown')
                }
            except:
                continue
        return None

    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]  # Limit title length
        except:
            pass
        return None

    def get_real_ip_fast(self, subdomain):
        """Fast IP resolution with caching"""
        ips = []
        # Standard DNS resolution with timeout
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            if self.custom_nameservers:
                resolver.nameservers = self.custom_nameservers
            answers = resolver.resolve(subdomain, 'A')
            for rdata in answers:
                ip_addr = str(rdata)
                ips.append(('DNS', ip_addr, None))  # Skip Shodan for speed initially
                break  # Take first IP for speed
        except:
            pass
        return ips

    def get_real_ip(self, subdomain):
        """Get real IP address, attempting to bypass CDN (full version)"""
        ips = []
        # Standard DNS resolution
        try:
            result = socket.gethostbyname(subdomain)
            shodan_info = self.get_shodan_info(result) if self.shodan_api else None
            ips.append(('DNS', result, shodan_info))
        except:
            pass
        # Try different DNS servers (limit to 2 for speed)
        dns_servers = ['8.8.8.8', '1.1.1.1']
        for dns_server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                answers = resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    ip_addr = str(rdata)
                    shodan_info = self.get_shodan_info(ip_addr) if self.shodan_api else None
                    ips.append((f'DNS-{dns_server}', ip_addr, shodan_info))
                    break  # Take first IP for speed
            except:
                continue
        # Check for common direct-connect subdomains (reduced list for speed)
        direct_subs = ['direct', 'origin']
        for prefix in direct_subs:
            try:
                direct_domain = f"{prefix}.{subdomain}"
                result = socket.gethostbyname(direct_domain)
                shodan_info = self.get_shodan_info(result) if self.shodan_api else None
                ips.append(('Direct', result, shodan_info))
            except:
                pass
        return ips

    def ssh_port_scan(self):
        """Scan active subdomains for SSH port (22)"""
        print("[+] Scanning active subdomains for SSH port (22)...")
        ssh_subdomains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_ssh_port, sub) for sub in self.active_subdomains]
            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    result = future.result(timeout=1)
                    if result:
                        ssh_subdomains.append(result)
                        print(f"[SSH] Found SSH service on {result}")
                except (concurrent.futures.TimeoutError, Exception):
                    continue
        if ssh_subdomains:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"{self.domain}_ssh_{timestamp}.txt"
            with open(filename, 'w') as f:
                for subdomain in ssh_subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[+] SSH subdomains saved to {filename}")

    def check_ssh_port(self, subdomain):
        """Check if SSH port (22) is open on a subdomain"""
        try:
            ip = socket.gethostbyname(subdomain)
            with socket.create_connection((ip, 22), timeout=self.timeout) as sock:
                return subdomain
        except:
            return None

    def run(self):
        """Run the complete reconnaissance"""
        print(f"[+] Starting subdomain discovery for {self.domain}")
        print("=" * 50)
        # Passive reconnaissance
        self.passive_recon()
        # Active reconnaissance
        self.active_recon()
        # Display results
        print("\n" + "=" * 50)
        print(f"[+] Found {len(self.subdomains)} total subdomains")
        print(f"[+] Active subdomains: {len(self.active_subdomains)}")
        print(f"[+] Inactive subdomains: {len(self.inactive_subdomains)}")
        print("=" * 50)
        # Display active subdomains
        if self.active_subdomains:
            print("\n[+] ACTIVE SUBDOMAINS:")
            for subdomain in sorted(self.active_subdomains):
                details = self.subdomain_details.get(subdomain, {})
                print(f"[ACTIVE] {subdomain}")
                if details:
                    print(f"    Status: {details.get('status', 'Unknown')}")
                    print(f"    Scheme: {details.get('scheme', 'Unknown')}")
                    print(f"    Server: {details.get('server', 'Unknown')}")
                    if details.get('title'):
                        print(f"    Title: {details['title']}")
                ips = self.get_real_ip(subdomain)
                for source, ip, shodan_info in ips:
                    print(f"    [{source}] {ip}")
                    if shodan_info:
                        print(f"        Org: {shodan_info['org']}")
                        print(f"        ISP: {shodan_info['isp']}")
                        print(f"        Location: {shodan_info['city']}, {shodan_info['country']}")
                        if shodan_info['ports']:
                            print(f"        Open Ports: {', '.join(map(str, shodan_info['ports'][:10]))}")
        # Display inactive subdomains
        if self.inactive_subdomains:
            print("\n[+] INACTIVE SUBDOMAINS (DNS only):")
            for subdomain in sorted(self.inactive_subdomains):
                print(f"[INACTIVE] {subdomain}")
                ips = self.get_real_ip(subdomain)
                for source, ip, shodan_info in ips:
                    print(f"    [{source}] {ip}")
                    if shodan_info:
                        print(f"        Org: {shodan_info['org']}")
                        print(f"        ISP: {shodan_info['isp']}")
                        print(f"        Location: {shodan_info['city']}, {shodan_info['country']}")
        # Save results
        self.save_results()
        return list(self.subdomains)

    def save_results(self):
        """Save results to separate files"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        # Save comprehensive JSON results
        filename = f"{self.domain}_subdomains_{timestamp}.json"
        results = {
            'domain': self.domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_subdomains': len(self.subdomains),
            'active_subdomains': len(self.active_subdomains),
            'inactive_subdomains': len(self.inactive_subdomains),
            'wordlist_used': self.wordlist_file if self.wordlist_file else 'default',
            'subdomains': {
                'active': [],
                'inactive': []
            }
        }
        # Process active subdomains
        for subdomain in sorted(self.active_subdomains):
            details = self.subdomain_details.get(subdomain, {})
            ips = self.get_real_ip(subdomain)
            ip_data = []
            for source, ip, shodan_info in ips:
                ip_entry = {'source': source, 'ip': ip}
                if shodan_info:
                    ip_entry['shodan'] = shodan_info
                ip_data.append(ip_entry)
            subdomain_data = {
                'subdomain': subdomain,
                'status': 'active',
                'ips': ip_data
            }
            if details:
                subdomain_data.update({
                    'http_status': details.get('status'),
                    'scheme': details.get('scheme'),
                    'server': details.get('server'),
                    'title': details.get('title')
                })
            results['subdomains']['active'].append(subdomain_data)
        # Process inactive subdomains
        for subdomain in sorted(self.inactive_subdomains):
            ips = self.get_real_ip(subdomain)
            ip_data = []
            for source, ip, shodan_info in ips:
                ip_entry = {'source': source, 'ip': ip}
                if shodan_info:
                    ip_entry['shodan'] = shodan_info
                ip_data.append(ip_entry)
            results['subdomains']['inactive'].append({
                'subdomain': subdomain,
                'status': 'inactive',
                'ips': ip_data
            })
        # Save comprehensive JSON
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Comprehensive results saved to {filename}")
        # Save active subdomains to separate file
        active_filename = f"{self.domain}_active_{timestamp}.txt"
        with open(active_filename, 'w') as f:
            for subdomain in sorted(self.active_subdomains):
                f.write(f"{subdomain}\n")
        print(f"[+] Active subdomains saved to {active_filename}")
        # Save inactive subdomains to separate file
        inactive_filename = f"{self.domain}_inactive_{timestamp}.txt"
        with open(inactive_filename, 'w') as f:
            for subdomain in sorted(self.inactive_subdomains):
                f.write(f"{subdomain}\n")
        print(f"[+] Inactive subdomains saved to {inactive_filename}")
        # Save all subdomains to one file
        all_filename = f"{self.domain}_all_{timestamp}.txt"
        with open(all_filename, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        print(f"[+] All subdomains saved to {all_filename}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Subdomain Discovery Tool with Shodan Integration')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Number of threads (default: 200)')
    parser.add_argument('-o', '--output', help='Output file (deprecated - use automatic naming)')
    parser.add_argument('-s', '--shodan', help='Shodan API key')
    parser.add_argument('-w', '--wordlist', help='External wordlist file path')
    parser.add_argument('--timeout', type=int, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('--fast', action='store_true', help='Fast mode - skip Shodan lookups during scan')
    parser.add_argument('--active-only', action='store_true', help='Only save active subdomains')
    parser.add_argument('--inactive-only', action='store_true', help='Only save inactive subdomains')
    parser.add_argument('--scan-ssh', action='store_true', help='Scan active subdomains for SSH port (22)')
    parser.add_argument('--custom-nameservers', nargs='+', help='Custom DNS nameservers to use')
    args = parser.parse_args()
    # Validate domain
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, args.domain):
        print("[-] Invalid domain format")
        return
    # Validate wordlist file if provided
    if args.wordlist and not os.path.exists(args.wordlist):
        print(f"[-] Wordlist file not found: {args.wordlist}")
        return
    print("[!] This tool should only be used on domains you own or have permission to test")
    print("[!] Unauthorized scanning may be illegal in your jurisdiction")
    print(f"[+] Using {args.threads} threads with {args.timeout}s timeout")
    if args.wordlist:
        print(f"[+] Using external wordlist: {args.wordlist}")
    if args.fast:
        print("[+] Fast mode enabled - Shodan lookups will be skipped during initial scan")
    if args.scan_ssh:
        print("[+] SSH port scan enabled for active subdomains")
    if args.custom_nameservers:
        print(f"[+] Using custom DNS nameservers: {', '.join(args.custom_nameservers)}")
    finder = SubdomainFinder(args.domain, args.threads, args.shodan, args.timeout, args.wordlist, args.custom_nameservers, args.scan_ssh)
    subdomains = finder.run()
    # Legacy output file support
    if args.output:
        with open(args.output, 'w') as f:
            if args.active_only:
                for subdomain in finder.active_subdomains:
                    f.write(f"{subdomain}\n")
                print(f"[+] Active subdomains saved to {args.output}")
            elif args.inactive_only:
                for subdomain in finder.inactive_subdomains:
                    f.write(f"{subdomain}\n")
                print(f"[+] Inactive subdomains saved to {args.output}")
            else:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
                print(f"[+] All subdomains saved to {args.output}")

if __name__ == "__main__":
    main()
