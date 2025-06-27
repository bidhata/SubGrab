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
import re
import shodan
import threading
from functools import lru_cache
from urllib.parse import urlparse

# Thread-local storage for session and resolver
thread_local = threading.local()

class SubdomainFinder:
    def __init__(self, domain, threads=100, shodan_api_key=None, timeout=3, 
                 wordlist_file=None, custom_nameservers=None, scan_ssh=False, 
                 fast_mode=False):
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
        self.fast_mode = fast_mode
        self.dns_cache = {}
        self.ip_cache = {}
        
        # Initialize Shodan API
        if not fast_mode and shodan_api_key:
            try:
                self.shodan_api = shodan.Shodan(shodan_api_key)
                print(f"[+] Shodan API initialized")
            except Exception as e:
                print(f"[-] Shodan API initialization failed: {e}")
                self.shodan_api = None
        else:
            self.shodan_api = None

    def get_session(self):
        """Get thread-local requests session"""
        if not hasattr(thread_local, "session"):
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            })
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=1
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            thread_local.session = session
        return thread_local.session

    def get_resolver(self):
        """Get thread-local DNS resolver"""
        if not hasattr(thread_local, "resolver"):
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            if self.custom_nameservers:
                resolver.nameservers = self.custom_nameservers
            thread_local.resolver = resolver
        return thread_local.resolver

    def load_wordlist(self):
        """Optimized wordlist loading with caching"""
        if hasattr(self, '_wordlist_cache'):
            return self._wordlist_cache

        # Default wordlist
        default_wordlist = [
            'www', 'mail', 'ftp', 'ns1', 'ns2', 'vpn', 'api', 'cdn', 'blog',
            'webmail', 'server', 'smtp', 'secure', 'admin', 'dev', 'staging',
            'test', 'portal', 'host', 'mx', 'pop', 'imap', 'gateway', 'proxy',
            'dashboard', 'app', 'mobile', 'static', 'assets', 'support', 'shop',
            'store', 'crm', 'erp', 'news', 'events', 'beta', 'alpha', 'internal',
            'intranet', 'git', 'jenkins', 'db', 'mysql', 'redis', 'backup'
        ]
        wordlist = set(default_wordlist)
        
        if self.wordlist_file and os.path.exists(self.wordlist_file):
            try:
                with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        sub = line.strip()
                        if sub and not sub.startswith('#'):
                            # Clean and extract base subdomain
                            sub = sub.replace('http://', '').replace('https://', '')
                            sub = sub.split('.')[0].lower()
                            if sub and (sub.isalnum() or '-' in sub or '_' in sub):
                                wordlist.add(sub)
                print(f"[+] Loaded {len(wordlist)} words from external list")
            except Exception as e:
                print(f"[-] Error loading wordlist: {e}")
        
        # Cache for repeated use
        self._wordlist_cache = list(wordlist)
        print(f"[+] Total wordlist size: {len(self._wordlist_cache)}")
        return self._wordlist_cache

    def passive_recon(self):
        """Parallel passive reconnaissance"""
        print(f"[+] Starting parallel passive reconnaissance for {self.domain}")
        methods = [
            self.cert_transparency,
            self.dns_enumeration,
            self.web_archives
        ]
        
        if self.shodan_api:
            methods.append(self.shodan_search)
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, self.threads)) as executor:
            futures = {executor.submit(method) for method in methods}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Passive recon error: {e}")

    def cert_transparency(self):
        """Optimized CT log queries"""
        print("[+] Querying Certificate Transparency logs...")
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = {executor.submit(self.query_ct_source, url) for url in sources}
            for future in concurrent.futures.as_completed(futures):
                try:
                    for subdomain in future.result():
                        if subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            print(f"[CT] Found: {subdomain}")
                except Exception as e:
                    print(f"[-] CT error: {e}")

    def query_ct_source(self, url):
        """Query a single CT source"""
        session = self.get_session()
        try:
            response = session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return set()
                
            subdomains = set()
            if 'crt.sh' in url:
                for cert in response.json()[:300]:  # Limit results
                    for name in cert.get('name_value', '').split('\n'):
                        name = name.strip().replace('*', '').lower()
                        if name.endswith(f'.{self.domain}') and name != self.domain:
                            subdomains.add(name)
            elif 'certspotter' in url:
                for entry in response.json()[:150]:
                    for name in entry.get('dns_names', []):
                        name = name.replace('*', '').lower()
                        if name.endswith(f'.{self.domain}') and name != self.domain:
                            subdomains.add(name)
            return subdomains
        except Exception as e:
            print(f"[-] CT query failed: {e}")
            return set()

    def dns_enumeration(self):
        """Optimized DNS enumeration with caching"""
        print("[+] Performing DNS enumeration...")
        wordlist = self.load_wordlist()
        new_subdomains = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(futures):
                sub = futures[future]
                try:
                    result = future.result()
                    if result and result not in self.subdomains:
                        new_subdomains.add(result)
                        print(f"[DNS] Found: {result}")
                except Exception:
                    pass
                    
        self.subdomains.update(new_subdomains)

    def check_subdomain(self, subdomain):
        """Cached subdomain check"""
        full_domain = f"{subdomain}.{self.domain}"
        
        # Check cache first
        if full_domain in self.dns_cache:
            return full_domain if self.dns_cache[full_domain] else None
            
        exists = self.cached_dns_lookup(full_domain)
        self.dns_cache[full_domain] = exists
        return full_domain if exists else None

    @lru_cache(maxsize=10000)
    def cached_dns_lookup(self, domain):
        """Cached DNS lookup"""
        try:
            resolver = self.get_resolver()
            answers = resolver.resolve(domain, 'A')
            return bool(answers)
        except Exception:
            return False

    def web_archives(self):
        """Query web archives for subdomains"""
        print("[+] Querying web archives...")
        sources = [
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey&limit=1000",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = {executor.submit(self.query_archive_source, url) for url in sources}
            for future in concurrent.futures.as_completed(futures):
                try:
                    for subdomain in future.result():
                        if subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            print(f"[Archive] Found: {subdomain}")
                except Exception as e:
                    print(f"[-] Archive error: {e}")

    def query_archive_source(self, url):
        """Query a single archive source"""
        session = self.get_session()
        try:
            response = session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return set()
                
            subdomains = set()
            if 'web.archive.org' in url:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        archived_url = entry[2]
                        parsed = urlparse(archived_url)
                        if parsed.hostname and parsed.hostname.endswith(f'.{self.domain}'):
                            subdomains.add(parsed.hostname)
            elif 'alienvault.com' in url:
                data = response.json()
                passive_dns = data.get('passive_dns', [])
                for entry in passive_dns[:200]:  # Limit for speed
                    hostname = entry.get('hostname', '')
                    if hostname.endswith(f'.{self.domain}'):
                        subdomains.add(hostname)
            return subdomains
        except Exception as e:
            print(f"[-] Archive query failed: {e}")
            return set()

    def shodan_search(self):
        """Search Shodan for subdomains"""
        if not self.shodan_api:
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
                    if hostname.endswith(f'.{self.domain}') and hostname not in self.subdomains:
                        self.subdomains.add(hostname)
                        print(f"[Shodan] Found: {hostname}")
        except Exception as e:
            print(f"[-] Shodan search error: {e}")

    def active_recon(self):
        """Parallel active reconnaissance"""
        print(f"[+] Starting parallel active reconnaissance...")
        self.zone_transfer()
        self.http_enumeration()
        
        if self.scan_ssh:
            self.ssh_port_scan()

    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        print("[+] Attempting DNS zone transfer...")
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, self.threads)) as executor:
                futures = []
                for ns in ns_records:
                    futures.append(executor.submit(self.try_zone_transfer, str(ns)))
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        for subdomain in future.result():
                            if subdomain not in self.subdomains:
                                self.subdomains.add(subdomain)
                                print(f"[Zone] Found: {subdomain}")
                    except Exception:
                        pass
        except Exception as e:
            print(f"[-] Zone transfer failed: {e}")

    def try_zone_transfer(self, nameserver):
        """Attempt zone transfer with a specific nameserver"""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.domain))
            subdomains = set()
            for name, node in zone.nodes.items():
                subdomain = f"{name}.{self.domain}"
                if subdomain != self.domain:
                    subdomains.add(subdomain)
            return subdomains
        except Exception:
            return set()

    def http_enumeration(self):
        """Optimized HTTP checks with session reuse"""
        if not self.subdomains:
            print("[!] No subdomains to check")
            return
            
        print(f"[+] HTTP enumeration on {len(self.subdomains)} subdomains...")
        active = set()
        details = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_http, sub): sub for sub in self.subdomains}
            for future in concurrent.futures.as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        active.add(subdomain)
                        details[subdomain] = result
                        print(f"[HTTP] {subdomain} [{result['status']}]")
                except Exception:
                    pass
                    
        self.active_subdomains = active
        self.subdomain_details = details
        self.inactive_subdomains = self.subdomains - active
        print(f"[+] Active: {len(active)}, Inactive: {len(self.inactive_subdomains)}")

    def check_http(self, subdomain):
        """HTTP check with incremental backoff"""
        schemes = ['https', 'http']
        session = self.get_session()
        
        for scheme in schemes:
            try:
                url = f"{scheme}://{subdomain}"
                response = session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=False,
                    stream=True  # Don't download content immediately
                )
                
                # Only read title if status is interesting
                title = None
                if response.status_code < 400:
                    try:
                        # Only read first 8KB for title
                        content = response.content[:8192].decode('utf-8', 'ignore')
                        title = self.extract_title(content)
                    except:
                        pass
                
                return {
                    'status': response.status_code,
                    'scheme': scheme,
                    'title': title,
                    'server': response.headers.get('Server', 'Unknown')
                }
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                continue
            except Exception:
                # Short delay between attempts
                time.sleep(0.05)
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

    def ssh_port_scan(self):
        """Scan active subdomains for SSH port (22)"""
        if not self.active_subdomains:
            return
            
        print("[+] Scanning active subdomains for SSH port (22)...")
        ssh_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_ssh_port, sub): sub for sub in self.active_subdomains}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        ssh_subdomains.append(result)
                        print(f"[SSH] Found SSH service on {result}")
                except Exception:
                    pass
                    
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 22))
            sock.close()
            return subdomain if result == 0 else None
        except:
            return None

    def precompute_ip_info(self):
        """Prefetch IP information in parallel"""
        if not self.subdomains:
            return
            
        print("[+] Precomputing IP information...")
        all_subs = list(self.subdomains)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.get_real_ip, sub): sub for sub in all_subs}
            for future in concurrent.futures.as_completed(futures):
                sub = futures[future]
                try:
                    ips = future.result()
                    self.ip_cache[sub] = ips
                except Exception as e:
                    print(f"[-] IP lookup failed for {sub}: {e}")

    def get_real_ip(self, subdomain):
        """Get real IP address with caching"""
        if subdomain in self.ip_cache:
            return self.ip_cache[subdomain]
            
        ips = []
        try:
            # Standard DNS resolution
            result = socket.gethostbyname(subdomain)
            ips.append(('DNS', result))
        except:
            pass
            
        return ips

    def save_results(self):
        """Save results to files"""
        if not self.subdomains:
            print("[!] No results to save")
            return
            
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Save all subdomains
        all_filename = f"{self.domain}_all_{timestamp}.txt"
        with open(all_filename, 'w') as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")
        print(f"[+] All subdomains saved to {all_filename}")
        
        # Save active subdomains
        if self.active_subdomains:
            active_filename = f"{self.domain}_active_{timestamp}.txt"
            with open(active_filename, 'w') as f:
                for sub in sorted(self.active_subdomains):
                    f.write(f"{sub}\n")
            print(f"[+] Active subdomains saved to {active_filename}")
            
        # Save inactive subdomains
        if self.inactive_subdomains:
            inactive_filename = f"{self.domain}_inactive_{timestamp}.txt"
            with open(inactive_filename, 'w') as f:
                for sub in sorted(self.inactive_subdomains):
                    f.write(f"{sub}\n")
            print(f"[+] Inactive subdomains saved to {inactive_filename}")

    def run(self):
        """Optimized execution flow"""
        print(f"[+] Starting discovery for {self.domain}")
        start_time = time.time()
        
        # Phase 1: Passive recon
        self.passive_recon()
        
        # Phase 2: Active recon
        self.active_recon()
        
        # Phase 3: Precompute IP info
        self.precompute_ip_info()
        
        # Results
        print(f"\n[+] Completed in {time.time()-start_time:.2f} seconds")
        print(f"[+] Total subdomains: {len(self.subdomains)}")
        print(f"[+] Active subdomains: {len(self.active_subdomains)}")
        print(f"[+] Inactive subdomains: {len(self.inactive_subdomains)}")
        
        self.save_results()
        return list(self.subdomains)

def main():
    parser = argparse.ArgumentParser(description='Optimized Subdomain Discovery Tool')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Number of threads (default: 200)')
    parser.add_argument('-s', '--shodan', help='Shodan API key')
    parser.add_argument('-w', '--wordlist', help='External wordlist file path')
    parser.add_argument('--timeout', type=int, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('--fast', action='store_true', help='Fast mode - skip intensive operations')
    parser.add_argument('--scan-ssh', action='store_true', help='Scan active subdomains for SSH port (22)')
    parser.add_argument('--custom-nameservers', nargs='+', help='Custom DNS nameservers to use')
    args = parser.parse_args()
    
    # Validate domain
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, args.domain):
        print("[-] Invalid domain format")
        return
        
    print("[!] This tool should only be used on domains you own or have permission to test")
    print("[!] Unauthorized scanning may be illegal in your jurisdiction")
    print(f"[+] Using {args.threads} threads with {args.timeout}s timeout")
    
    # Initialize finder
    finder = SubdomainFinder(
        args.domain, 
        args.threads, 
        args.shodan,
        args.timeout,
        args.wordlist,
        args.custom_nameservers,
        args.scan_ssh,
        args.fast
    )
    
    finder.run()

if __name__ == "__main__":
    main()
