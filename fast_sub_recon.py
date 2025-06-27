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
                 fast_mode=False, security_trails_key=None, virustotal_key=None):
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
        self.security_trails_key = security_trails_key
        self.virustotal_key = virustotal_key
        self.dns_cache = {}
        self.ip_cache = {}
        self.domain_dir = f"./{domain}"  # Domain-specific output directory
        self.ssh_filename = None  # To store SSH results filename
        self.ssh_subdomains = set()  # Store SSH results in memory
        
        # Create output directory
        os.makedirs(self.domain_dir, exist_ok=True)
        print(f"[+] Created output directory: {self.domain_dir}")
        
        # Initialize APIs
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

        # Enhanced default wordlist
        default_wordlist = [
            'www', 'mail', 'ftp', 'ns1', 'ns2', 'vpn', 'api', 'cdn', 'blog',
            'webmail', 'server', 'smtp', 'secure', 'admin', 'dev', 'staging',
            'test', 'portal', 'host', 'mx', 'pop', 'imap', 'gateway', 'proxy',
            'dashboard', 'app', 'mobile', 'static', 'assets', 'support', 'shop',
            'store', 'crm', 'erp', 'news', 'events', 'beta', 'alpha', 'internal',
            'intranet', 'git', 'jenkins', 'db', 'mysql', 'redis', 'backup',
            'origin', 'edge', 'cache', 'cdn1', 'cdn2', 'lb', 'loadbalancer',
            'elk', 'kibana', 'grafana', 'prometheus', 'monitor', 'status',
            'auth', 'sso', 'login', 'oauth', 'api-gateway', 'service', 'services',
            'internal-api', 'external-api', 'legacy', 'old', 'new', 'temp',
            'staging1', 'staging2', 'testing', 'qa', 'preprod', 'sandbox', 'demo'
        ]
        
        # Add numbered subdomains
        numbered = [f"www{i}" for i in range(1, 21)]
        numbered += [f"api{i}" for i in range(1, 21)]
        numbered += [f"app{i}" for i in range(1, 21)]
        numbered += [f"web{i}" for i in range(1, 21)]
        numbered += [f"mx{i}" for i in range(1, 11)]
        numbered += [f"ns{i}" for i in range(1, 11)]
        
        wordlist = set(default_wordlist + numbered)
        
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
        
        # Add permutations with common prefixes/suffixes
        permutations = set()
        prefixes = ['dev-', 'test-', 'staging-', 'prod-', 'uat-', 'pre-', 'new-']
        suffixes = ['-dev', '-test', '-staging', '-prod', '-uat', '-old', '-new']
        
        for sub in list(wordlist):
            # Add common prefix variations
            for prefix in prefixes:
                permutations.add(f"{prefix}{sub}")
            
            # Add common suffix variations
            for suffix in suffixes:
                permutations.add(f"{sub}{suffix}")
            
            # Add number variations
            for i in range(1, 4):
                permutations.add(f"{sub}{i}")
                permutations.add(f"{sub}-{i}")
        
        wordlist |= permutations  # Merge sets
        
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
            self.web_archives,
            self.search_engines,
            self.rapiddns_search,
            self.dnsdumpster_search,
            self.common_crawl_search,
            self.dns_brute_advanced
        ]
        
        # Add API-based methods if keys are available
        if self.security_trails_key:
            methods.append(self.security_trails_search)
        if self.virustotal_key:
            methods.append(self.virustotal_search)
        if self.shodan_api:
            methods.append(self.shodan_search)
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, self.threads)) as executor:
            futures = {executor.submit(method) for method in methods}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Passive recon error: {e}")
                    
        # Perform PTR lookups after initial discovery
        if self.subdomains:
            self.precompute_ip_info()
            self.ptr_lookup()

    def dnsdumpster_search(self):
        """Query DNSdumpster for subdomains"""
        print("[+] Querying DNSdumpster...")
        url = "https://dnsdumpster.com/"
        try:
            session = self.get_session()
            # Get CSRF token
            response = session.get(url, timeout=self.timeout)
            csrf_match = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", response.text)
            if not csrf_match:
                print("[-] DNSdumpster: Failed to get CSRF token")
                return
                
            csrf_token = csrf_match.group(1)
            
            # Perform search
            headers = {'Referer': url}
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain
            }
            response = session.post(url, data=data, headers=headers, timeout=self.timeout)
            
            if response.status_code != 200:
                print(f"[-] DNSdumpster returned status {response.status_code}")
                return
                
            # Extract subdomains
            pattern = r'([a-zA-Z0-9][a-zA-Z0-9\-]*\.)+' + re.escape(self.domain)
            subdomains = set(re.findall(pattern, response.text))
            
            for sub in subdomains:
                if sub not in self.subdomains:
                    self.subdomains.add(sub)
                    print(f"[DNSdumpster] Found: {sub}")
        except Exception as e:
            print(f"[-] DNSdumpster error: {e}")

    def common_crawl_search(self):
        """Query CommonCrawl for subdomains"""
        print("[+] Querying CommonCrawl...")
        url = f"https://index.commoncrawl.org/collinfo.json"
        try:
            session = self.get_session()
            response = session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                print(f"[-] CommonCrawl index returned status {response.status_code}")
                return
                
            indexes = response.json()
            if not indexes:
                print("[-] No CommonCrawl indexes available")
                return
                
            latest_index = indexes[0]['id']
            api_url = f"https://index.commoncrawl.org/{latest_index}-index?url=*.{self.domain}&output=json"
            response = session.get(api_url, stream=True, timeout=self.timeout)
            
            if response.status_code != 200:
                print(f"[-] CommonCrawl API returned status {response.status_code}")
                return
                
            subdomains = set()
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        if not url:
                            continue
                        hostname = urlparse(url).hostname
                        if hostname and hostname.endswith(f'.{self.domain}') and hostname != self.domain:
                            subdomains.add(hostname)
                    except json.JSONDecodeError:
                        continue
            
            for sub in subdomains:
                if sub not in self.subdomains:
                    self.subdomains.add(sub)
                    print(f"[CommonCrawl] Found: {sub}")
        except Exception as e:
            print(f"[-] CommonCrawl error: {e}")

    def dns_brute_advanced(self):
        """Advanced DNS brute-forcing with common prefixes"""
        print("[+] Performing advanced DNS brute-forcing...")
        prefixes = [
            'dev', 'test', 'staging', 'prod', 'uat', 'preprod', 'sandbox', 
            'api', 'app', 'web', 'mobile', 'admin', 'internal', 'external',
            'backup', 'db', 'mail', 'email', 'vpn', 'gateway', 'proxy',
            'aws', 'azure', 'gcp', 'cloud', 'cdn', 'lb', 's3'
        ]
        
        # Generate permutations
        candidates = set()
        base_domain = self.domain.split('.')[0]
        
        for prefix in prefixes:
            candidates.add(f"{prefix}.{base_domain}")
            candidates.add(f"{prefix}-{base_domain}")
            for i in range(1, 5):
                candidates.add(f"{prefix}{i}.{base_domain}")
                candidates.add(f"{prefix}-{i}.{base_domain}")
        
        # Add common cloud patterns
        cloud_patterns = [
            f"{base_domain}-aws", f"{base_domain}-azure", f"{base_domain}-gcp",
            f"{base_domain}-cloud", f"aws-{base_domain}", f"azure-{base_domain}",
            f"gcp-{base_domain}", f"cloud-{base_domain}", f"s3-{base_domain}",
            f"{base_domain}-s3", f"storage-{base_domain}"
        ]
        candidates.update(cloud_patterns)
        
        # Add environment-specific permutations
        for env in ['dev', 'test', 'staging', 'prod', 'qa']:
            candidates.add(f"{env}.{base_domain}")
            candidates.add(f"{env}-{base_domain}")
            candidates.add(f"{base_domain}-{env}")
            for i in range(1, 3):
                candidates.add(f"{env}{i}.{base_domain}")
                candidates.add(f"{env}-{i}.{base_domain}")
        
        print(f"[+] Generated {len(candidates)} advanced permutations")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, candidate.split('.')[0]): candidate for candidate in candidates}
            for future in concurrent.futures.as_completed(futures):
                candidate = futures[future]
                try:
                    result = future.result()
                    if result and result not in self.subdomains:
                        self.subdomains.add(result)
                        print(f"[Brute] Found: {result}")
                except Exception:
                    pass

    def ptr_lookup(self):
        """Perform reverse DNS lookups on known IP ranges"""
        print("[+] Performing PTR lookups on discovered IPs...")
        all_ips = set()
        for ips in self.ip_cache.values():
            for _, ip in ips:
                all_ips.add(ip)
        
        if not all_ips:
            print("[!] No IP information available for PTR lookups")
            return
            
        print(f"[+] Checking {len(all_ips)} unique IPs for PTR records")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_ptr_record, ip): ip for ip in all_ips}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    hostnames = future.result()
                    for hostname in hostnames:
                        if hostname.endswith(f'.{self.domain}') and hostname not in self.subdomains:
                            self.subdomains.add(hostname)
                            print(f"[PTR] Found: {hostname}")
                except Exception:
                    pass

    def check_ptr_record(self, ip):
        """Check PTR record for an IP address"""
        try:
            hostnames = socket.gethostbyaddr(ip)
            return [h.lower() for h in hostnames] if hostnames else []
        except socket.herror:
            return []
        except Exception:
            return []

    def cert_transparency(self):
        """Optimized CT log queries"""
        print("[+] Querying Certificate Transparency logs...")
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain={self.domain}&include_expired=true&include_subdomains=true"
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
                for cert in response.json()[:500]:  # Limit results
                    for name in cert.get('name_value', '').split('\n'):
                        name = name.strip().replace('*', '').lower()
                        if name.endswith(f'.{self.domain}') and name != self.domain:
                            subdomains.add(name)
            
            elif 'certspotter' in url:
                for entry in response.json()[:200]:
                    for name in entry.get('dns_names', []):
                        name = name.replace('*', '').lower()
                        if name.endswith(f'.{self.domain}') and name != self.domain:
                            subdomains.add(name)
            
            elif 'google.com' in url:
                # Google Transparency Report has a unique format
                data = response.text.split('\n')
                if len(data) > 3:
                    json_str = data[3]
                    try:
                        json_data = json.loads(json_str)
                        certs = json_data[0][3]
                        for cert in certs:
                            domains = cert[4]
                            for domain in domains:
                                domain = domain.lower()
                                if domain.endswith(f'.{self.domain}') and domain != self.domain:
                                    subdomains.add(domain)
                    except:
                        pass
            
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
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey&limit=5000",
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
                for entry in passive_dns[:500]:  # Increase limit
                    hostname = entry.get('hostname', '')
                    if hostname.endswith(f'.{self.domain}'):
                        subdomains.add(hostname)
            return subdomains
        except Exception as e:
            print(f"[-] Archive query failed: {e}")
            return set()

    def search_engines(self):
        """Query search engines for subdomains"""
        print("[+] Querying search engines...")
        sources = [
            f"https://www.bing.com/search?q=site%3A{self.domain}&count=100",
            f"https://search.yahoo.com/search?p=site%3A{self.domain}&n=100",
            f"https://www.google.com/search?q=site%3A{self.domain}&num=100"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = {executor.submit(self.query_search_engine, url) for url in sources}
            for future in concurrent.futures.as_completed(futures):
                try:
                    for subdomain in future.result():
                        if subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            print(f"[Search] Found: {subdomain}")
                except Exception as e:
                    print(f"[-] Search engine error: {e}")

    def query_search_engine(self, url):
        """Query a search engine for subdomains"""
        session = self.get_session()
        subdomains = set()
        try:
            response = session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return subdomains
                
            content = response.text.lower()
            
            # Extract all potential subdomains from the page
            pattern = r'([a-z0-9][a-z0-9\-]*\.)+' + re.escape(self.domain.lower())
            matches = re.findall(pattern, content)
            
            for match in matches:
                if match.endswith(f'.{self.domain}') and match != self.domain:
                    subdomains.add(match)
            
            return subdomains
        except Exception:
            return subdomains

    def rapiddns_search(self):
        """Query RapidDNS for subdomains"""
        print("[+] Querying RapidDNS...")
        url = f"https://rapiddns.io/subdomain/{self.domain}#result"
        
        try:
            session = self.get_session()
            response = session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return
                
            # Extract subdomains from table
            pattern = r'([a-z0-9][a-z0-9\-]*\.)+' + re.escape(self.domain.lower())
            matches = re.findall(pattern, response.text)
            
            for match in set(matches):
                if match not in self.subdomains:
                    self.subdomains.add(match)
                    print(f"[RapidDNS] Found: {match}")
        except Exception as e:
            print(f"[-] RapidDNS error: {e}")

    def security_trails_search(self):
        """Query SecurityTrails API for subdomains"""
        if not self.security_trails_key:
            return
            
        print("[+] Querying SecurityTrails API...")
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {'APIKEY': self.security_trails_key}
        
        try:
            session = self.get_session()
            response = session.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for sub in data.get('subdomains', []):
                    full_domain = f"{sub}.{self.domain}"
                    if full_domain not in self.subdomains:
                        self.subdomains.add(full_domain)
                        print(f"[SecurityTrails] Found: {full_domain}")
            else:
                print(f"[-] SecurityTrails API error: {response.status_code}")
        except Exception as e:
            print(f"[-] SecurityTrails API error: {e}")

    def virustotal_search(self):
        """Query VirusTotal API for subdomains"""
        if not self.virustotal_key:
            return
            
        print("[+] Querying VirusTotal API...")
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=500"
        headers = {'x-apikey': self.virustotal_key}
        
        try:
            session = self.get_session()
            response = session.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    domain = item.get('id', '')
                    if domain.endswith(f'.{self.domain}') and domain not in self.subdomains:
                        self.subdomains.add(domain)
                        print(f"[VirusTotal] Found: {domain}")
            else:
                print(f"[-] VirusTotal API error: {response.status_code}")
        except Exception as e:
            print(f"[-] VirusTotal API error: {e}")

    def shodan_search(self):
        """Search Shodan for subdomains"""
        if not self.shodan_api:
            return
            
        print("[+] Searching Shodan...")
        try:
            # Search for hostnames
            hostname_query = f"hostname:{self.domain}"
            results = self.shodan_api.search(hostname_query, limit=200)  # Increased limit
            
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
            print("[!] No active subdomains to scan for SSH")
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
            self.ssh_filename = os.path.join(self.domain_dir, f"{self.domain}_ssh_{timestamp}.txt")
            with open(self.ssh_filename, 'w') as f:
                for subdomain in ssh_subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[+] SSH subdomains saved to {self.ssh_filename}")
            self.ssh_subdomains = set(ssh_subdomains)

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

    def escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

    def generate_html_report(self):
        """Generate minimalist sortable HTML report"""
        if not self.subdomains:
            print("[!] No results to generate HTML report")
            return None
            
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        html_filename = os.path.join(self.domain_dir, f"{self.domain}_report_{timestamp}.html")
        
        # Prepare data rows
        rows = []
        for sub in sorted(self.subdomains):
            status = "Active" if sub in self.active_subdomains else "Inactive"
            ips = self.ip_cache.get(sub, [])
            ip_str = ", ".join([ip[1] for ip in ips]) if ips else "N/A"
            
            details = self.subdomain_details.get(sub, {})
            http_status = details.get('status', 'N/A') if details else 'N/A'
            title = details.get('title', 'N/A') if details else 'N/A'
            server = details.get('server', 'N/A') if details else 'N/A'
            ssh = "Yes" if sub in self.ssh_subdomains else "No"
            
            rows.append({
                'subdomain': sub,
                'status': status,
                'ip': ip_str,
                'http_status': http_status,
                'title': title,
                'server': server,
                'ssh': ssh
            })
        
        # Generate HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Report for {self.domain}</title>
    <style>
        * {{
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eaeaea;
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        .summary {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 15px 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
            min-width: 150px;
        }}
        .summary-card h3 {{
            margin: 0;
            font-size: 24px;
            color: #3498db;
        }}
        .summary-card p {{
            margin: 5px 0 0;
            color: #7f8c8d;
        }}
        .filters {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 8px 16px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: #3498db;
            color: white;
            border-color: #3498db;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background-color: #f1f5f9;
            font-weight: 600;
            color: #2c3e50;
            cursor: pointer;
            position: relative;
        }}
        th:hover {{
            background-color: #e3e8ed;
        }}
        th::after {{
            content: '↕';
            position: absolute;
            right: 10px;
            opacity: 0.5;
        }}
        tr:hover {{
            background-color: #f8fafc;
        }}
        .status-active {{
            color: #27ae60;
            font-weight: 500;
        }}
        .status-inactive {{
            color: #e74c3c;
        }}
        .ssh-yes {{
            color: #27ae60;
            font-weight: 500;
        }}
        .ssh-no {{
            color: #95a5a6;
        }}
        .http-200 {{
            color: #27ae60;
        }}
        .http-3xx {{
            color: #f39c12;
        }}
        .http-4xx, .http-5xx {{
            color: #e74c3c;
        }}
        footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eaeaea;
            color: #7f8c8d;
            font-size: 14px;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            th, td {{
                padding: 8px 10px;
                font-size: 14px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Subdomain Report for {self.domain}</h1>
            <h2>Using <font color=red><a href="https://github.com/bidhata/fast-subrecon/">Fast_Sub_Recon</a></font></h2>
            <p>Script maintained by <a href="https://www.linkedin.com/in/krishpaul/">Krishnendu Paul</a></p>
            <p>Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{len(self.subdomains)}</h3>
                <p>Total Subdomains</p>
            </div>
            <div class="summary-card">
                <h3>{len(self.active_subdomains)}</h3>
                <p>Active Subdomains</p>
            </div>
            <div class="summary-card">
                <h3>{len(self.inactive_subdomains)}</h3>
                <p>Inactive Subdomains</p>
            </div>
            <div class="summary-card">
                <h3>{len(self.ssh_subdomains)}</h3>
                <p>SSH Services Found</p>
            </div>
        </div>
        
        <div class="filters">
            <button class="filter-btn active" onclick="filterTable('all')">All</button>
            <button class="filter-btn" onclick="filterTable('active')">Active Only</button>
            <button class="filter-btn" onclick="filterTable('inactive')">Inactive Only</button>
            <button class="filter-btn" onclick="filterTable('ssh')">With SSH</button>
        </div>
        
        <table id="reportTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Subdomain</th>
                    <th onclick="sortTable(1)">Status</th>
                    <th onclick="sortTable(2)">IP Address</th>
                    <th onclick="sortTable(3)">HTTP Status</th>
                    <th onclick="sortTable(4)">Title</th>
                    <th onclick="sortTable(5)">Server</th>
                    <th onclick="sortTable(6)">SSH Open</th>
                </tr>
            </thead>
            <tbody>
                {"".join([f"""
                <tr>
                    <td>{row['subdomain']}</td>
                    <td class="{'status-active' if row['status'] == 'Active' else 'status-inactive'}">{row['status']}</td>
                    <td>{row['ip']}</td>
                    <td class="http-{str(row['http_status'])[0] if str(row['http_status']).isdigit() else ''}xx">
                        {row['http_status']}
                    </td>
                    <td>{self.escape_html(row['title'])[:80] + ('...' if len(row['title'] or '') > 80 else '')}</td>
                    <td>{row['server']}</td>
                    <td class="{'ssh-yes' if row['ssh'] == 'Yes' else 'ssh-no'}">{row['ssh']}</td>
                </tr>
                """ for row in rows])}
            </tbody>
        </table>
        
        <footer>
            <p>Generated by Subdomain Discovery Tool | {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
    
    <script>
        let currentColumn = -1;
        let ascending = true;
        
        function sortTable(columnIndex) {{
            const table = document.getElementById("reportTable");
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.rows);
            
            // Reset all rows to show before sorting
            rows.forEach(row => row.style.display = '');
            
            // If clicking the same column, reverse order
            if (currentColumn === columnIndex) {{
                ascending = !ascending;
            }} else {{
                currentColumn = columnIndex;
                ascending = true;
            }}
            
            rows.sort((a, b) => {{
                let aValue = a.cells[columnIndex].textContent.trim();
                let bValue = b.cells[columnIndex].textContent.trim();
                
                // Numeric sorting for HTTP status
                if (columnIndex === 3 && !isNaN(aValue) && !isNaN(bValue)) {{
                    return ascending ? 
                        parseInt(aValue) - parseInt(bValue) : 
                        parseInt(bValue) - parseInt(aValue);
                }}
                
                // Status column sorting
                if (columnIndex === 1) {{
                    return ascending ? 
                        aValue.localeCompare(bValue) : 
                        bValue.localeCompare(aValue);
                }}
                
                // SSH column sorting
                if (columnIndex === 6) {{
                    return ascending ? 
                        (aValue === 'Yes' ? -1 : 1) : 
                        (aValue === 'Yes' ? 1 : -1);
                }}
                
                // Default string sorting
                return ascending ? 
                    aValue.localeCompare(bValue) : 
                    bValue.localeCompare(aValue);
            }});
            
            // Remove existing rows
            while (tbody.firstChild) {{
                tbody.removeChild(tbody.firstChild);
            }}
            
            // Add sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}
        
        function filterTable(filter) {{
            const rows = document.querySelectorAll('#reportTable tbody tr');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => {{
                btn.classList.toggle('active', btn.textContent.includes(filter));
            }});
            
            // Filter rows
            rows.forEach(row => {{
                const status = row.cells[1].textContent.trim();
                const ssh = row.cells[6].textContent.trim();
                
                if (filter === 'all') {{
                    row.style.display = '';
                }} 
                else if (filter === 'active' && status === 'Active') {{
                    row.style.display = '';
                }} 
                else if (filter === 'inactive' && status === 'Inactive') {{
                    row.style.display = '';
                }} 
                else if (filter === 'ssh' && ssh === 'Yes') {{
                    row.style.display = '';
                }}
                else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
        """
        
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[+] HTML report saved to {html_filename}")
        return html_filename

    def save_results(self):
        """Save results to files in domain directory"""
        if not self.subdomains:
            print("[!] No results to save")
            return
            
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Save all subdomains
        all_filename = os.path.join(self.domain_dir, f"{self.domain}_all_{timestamp}.txt")
        with open(all_filename, 'w') as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")
        print(f"[+] All subdomains saved to {all_filename}")
        
        # Save active subdomains
        if self.active_subdomains:
            active_filename = os.path.join(self.domain_dir, f"{self.domain}_active_{timestamp}.txt")
            with open(active_filename, 'w') as f:
                for sub in sorted(self.active_subdomains):
                    f.write(f"{sub}\n")
            print(f"[+] Active subdomains saved to {active_filename}")
            
        # Save inactive subdomains
        if self.inactive_subdomains:
            inactive_filename = os.path.join(self.domain_dir, f"{self.domain}_inactive_{timestamp}.txt")
            with open(inactive_filename, 'w') as f:
                for sub in sorted(self.inactive_subdomains):
                    f.write(f"{sub}\n")
            print(f"[+] Inactive subdomains saved to {inactive_filename}")
        
        # Save SSH results if they exist
        if hasattr(self, 'ssh_filename') and self.ssh_filename:
            print(f"[+] SSH subdomains already saved to {self.ssh_filename}")
        
        # Generate HTML report
        self.generate_html_report()
        
        # Save comprehensive JSON report
        json_filename = os.path.join(self.domain_dir, f"{self.domain}_report_{timestamp}.json")
        report = {
            'domain': self.domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_subdomains': len(self.subdomains),
            'active_subdomains': len(self.active_subdomains),
            'inactive_subdomains': len(self.inactive_subdomains),
            'ssh_subdomains': len(self.ssh_subdomains),
            'subdomains': {
                'active': sorted(self.active_subdomains),
                'inactive': sorted(self.inactive_subdomains),
                'ssh': sorted(self.ssh_subdomains)
            }
        }
        
        # Add details if available
        if self.subdomain_details:
            report['details'] = {}
            for sub, details in self.subdomain_details.items():
                report['details'][sub] = details
        
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Comprehensive report saved to {json_filename}")

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
        
        # Save results
        self.save_results()
        
        # Print summary
        print(f"\n[+] Completed in {time.time()-start_time:.2f} seconds")
        print(f"[+] Total subdomains: {len(self.subdomains)}")
        print(f"[+] Active subdomains: {len(self.active_subdomains)}")
        print(f"[+] Inactive subdomains: {len(self.inactive_subdomains)}")
        if self.scan_ssh:
            print(f"[+] SSH services found: {len(self.ssh_subdomains)}")
        
        return list(self.subdomains)

def main():
    parser = argparse.ArgumentParser(description='Enhanced Subdomain Discovery Tool')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Number of threads (default: 200)')
    parser.add_argument('-s', '--shodan', help='Shodan API key')
    parser.add_argument('-w', '--wordlist', help='External wordlist file path')
    parser.add_argument('--timeout', type=int, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('--fast', action='store_true', help='Fast mode - skip intensive operations')
    parser.add_argument('--scan-ssh', action='store_true', help='Scan active subdomains for SSH port (22)')
    parser.add_argument('--custom-nameservers', nargs='+', help='Custom DNS nameservers to use')
    parser.add_argument('--security-trails', help='SecurityTrails API key')
    parser.add_argument('--virustotal', help='VirusTotal API key')
    args = parser.parse_args()
    
    # Validate domain
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, args.domain):
        print("[-] Invalid domain format")
        return
        
    print("[!] This tool should only be used on domains you own or have permission to test")
    print("[!] Unauthorized scanning may be illegal in your jurisdiction")
    print("[!] Made by @bidhata for personal usage. Connect with me https://www.linkedin.com/in/krishpaul/")
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
        args.fast,
        args.security_trails,
        args.virustotal
    )
    
    finder.run()

if __name__ == "__main__":
    main()
