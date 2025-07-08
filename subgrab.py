#!/usr/bin/env python3
"""
Enhanced Subdomain Discovery Tool with Shodan Integration
For authorized security testing and bug bounty programs only.
managed by Krishnendu Paul < me@krishnendu.com >
https://www.linkedin.com/in/krishpaul/ 
"""

import argparse
import asyncio
import csv
import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import json
import os
import random
import re
import requests
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse, urljoin
from datetime import datetime
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Third-party imports (install with: pip install requests dnspython colorama beautifulsoup4 tqdm shodan)
try:
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from tqdm import tqdm
    import ratelimit
    import shodan
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install requests dnspython colorama beautifulsoup4 tqdm ratelimit shodan")
    sys.exit(1)

init(autoreset=True)

class SubdomainEnumerator:
    def __init__(self, domain, threads=50, timeout=30, fast_mode=False, stealth=False, 
                 proxies=None, wordlist=None, nameservers=None, api_keys=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.fast_mode = fast_mode
        self.stealth = stealth
        self.proxies = proxies or []
        self.wordlist = wordlist
        self.nameservers = nameservers or ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        self.api_keys = api_keys or {}
        
        # Results storage
        self.subdomains = set()
        self.active_subdomains = set()
        self.inactive_subdomains = set()
        self.ssh_enabled = set()
        self.takeover_candidates = set()
        self.subdomain_info = {}
     
        # Thread-local storage
        self.thread_local = threading.local()
        
        # Wildcard detection
        self.wildcard_ips = set()
        self._detect_wildcards()
        
        # Create output directory
        self.output_dir = f"{domain}_results"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Default wordlist
        self.default_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'mail2',
            'dev', 'staging', 'admin', 'api', 'app', 'blog', 'cdn', 'chat', 'demo',
            'docs', 'forum', 'help', 'mobile', 'news', 'portal', 'shop', 'support',
            'vpn', 'wiki', 'secure', 'static', 'assets', 'img', 'video', 'search',
            'beta', 'alpha', 'prod', 'production', 'uat', 'qa', 'staging', 'dev',
            'mail1', 'mail3', 'mx', 'mx1', 'mx2', 'pop3', 'imap', 'smtp1', 'smtp2',
            'ns', 'dns', 'dns1', 'dns2', 'subdomain', 'host', 'server', 'web1', 'web2'
        ]
        
        # Known takeover services
        self.takeover_services = {
            'amazonaws.com': ['NoSuchBucket', 'The specified bucket does not exist'],
            'github.io': ['There isn\'t a GitHub Pages site here'],
            'herokuapp.com': ['No such app'],
            'azurewebsites.net': ['Web App - Unavailable'],
            'cloudfront.net': ['The request could not be satisfied'],
            'surge.sh': ['project not found'],
            'bitbucket.io': ['Repository not found'],
            'fastly.com': ['Fastly error: unknown domain'],
            'helpjuice.com': ['We could not find what you\'re looking for'],
            'desk.com': ['Please try again or try Desk.com'],
            'campaignmonitor.com': ['Double check the URL'],
            'statuspage.io': ['You are being redirected'],
            'uservoice.com': ['This UserVoice subdomain is currently available'],
            'ghost.io': ['The thing you were looking for is no longer here'],
            'zendesk.com': ['Help Center Closed'],
            'tilda.cc': ['Domain has been assigned'],
            'wordpress.com': ['Do you want to register'],
            'pantheonsite.io': ['The gods are wise'],
            'gitbook.com': ['An error occurred']
        }

    def get_session(self):
        """Get thread-local session"""
        if not hasattr(self.thread_local, 'session'):
            self.thread_local.session = requests.Session()
            self.thread_local.session.verify = False
            self.thread_local.session.timeout = self.timeout
            if self.proxies:
                proxy = random.choice(self.proxies)
                self.thread_local.session.proxies = {'http': proxy, 'https': proxy}
        return self.thread_local.session

    def get_resolver(self):
        """Get thread-local DNS resolver"""
        if not hasattr(self.thread_local, 'resolver'):
            self.thread_local.resolver = dns.resolver.Resolver()
            self.thread_local.resolver.nameservers = self.nameservers
            self.thread_local.resolver.timeout = 10
            self.thread_local.resolver.lifetime = 10
        return self.thread_local.resolver

    def _detect_wildcards(self):
        """Detect wildcard DNS responses"""
        print(f"{Fore.YELLOW}[*] Detecting wildcard DNS responses...")
        test_subdomain = f"nonexistent{random.randint(1000, 9999)}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.nameservers
            answers = resolver.resolve(test_subdomain, 'A')
            for answer in answers:
                self.wildcard_ips.add(str(answer))
            print(f"{Fore.RED}[!] Wildcard DNS detected: {', '.join(self.wildcard_ips)}")
        except:
            print(f"{Fore.GREEN}[+] No wildcard DNS detected")

    @lru_cache(maxsize=1000)
    def resolve_domain(self, subdomain):
        """Resolve domain to IP with caching"""
        try:
            resolver = self.get_resolver()
            answers = resolver.resolve(subdomain, 'A')
            ips = [str(answer) for answer in answers]
            # Filter out wildcard IPs
            ips = [ip for ip in ips if ip not in self.wildcard_ips]
            return ips if ips else None
        except:
            return None

    def stealth_delay(self):
        """Add random delay for stealth mode"""
        if self.stealth:
            time.sleep(random.uniform(0.5, 2.0))

    def shodan_scan(self):
        """Perform Shodan scanning on discovered IPs"""
        if 'shodan' not in self.api_keys:
            return set()
        
        print(f"{Fore.CYAN}[*] Performing Shodan scanning...")
        subdomains = set()
        
        try:
            api = shodan.Shodan(self.api_keys['shodan'])
            
            # Scan each unique IP found
            unique_ips = set()
            for subdomain, info in self.subdomain_info.items():
                if info.get('ip'):
                    unique_ips.add(info['ip'])
            
            for ip in unique_ips:
                try:
                    host = api.host(ip)
                    
                    # Add any hostnames that match our domain
                    for hostname in host.get('hostnames', []):
                        if hostname.endswith(f'.{self.domain}'):
                            subdomains.add(hostname)
                    
                    # Add any domains from SSL certificates
                    if 'ssl' in host.get('data', [{}])[0]:
                        cert = host['data'][0]['ssl'].get('cert', {})
                        for name in cert.get('subject', {}).get('CN', '').split(','):
                            name = name.strip()
                            if name.endswith(f'.{self.domain}'):
                                subdomains.add(name)
                        for alt_name in cert.get('alt_names', []):
                            if alt_name.endswith(f'.{self.domain}'):
                                subdomains.add(alt_name)
                    
                    # Add any domains from HTTP responses
                    for item in host.get('data', []):
                        if 'http' in item:
                            for header in ['host', 'server', 'location']:
                                if header in item['http']:
                                    value = item['http'][header]
                                    if isinstance(value, str) and value.endswith(f'.{self.domain}'):
                                        subdomains.add(value)
                    
                    self.stealth_delay()
                except shodan.exception.APIError as e:
                    print(f"{Fore.YELLOW}[!] Shodan error for {ip}: {e}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error processing Shodan data for {ip}: {e}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Shodan API error: {e}")
        
        return subdomains

    # Passive Discovery Methods
    def certificate_transparency(self):
        """Search Certificate Transparency logs"""
        print(f"{Fore.CYAN}[*] Searching Certificate Transparency logs...")
        subdomains = set()
        
        # crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.get_session().get(url, timeout=70)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name = cert.get('name_value', '')
                    if name:
                        for domain in name.split('\n'):
                            domain = domain.strip()
                            if domain.endswith(f'.{self.domain}'):
                                subdomains.add(domain)
        except Exception as e:
            print(f"{Fore.RED}[!] Error with crt.sh: {e}")
        
        # CertSpotter
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = self.get_session().get(url, timeout=30)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    for dns_name in cert.get('dns_names', []):
                        if dns_name.endswith(f'.{self.domain}'):
                            subdomains.add(dns_name)
        except Exception as e:
            print(f"{Fore.RED}[!] Error with CertSpotter: {e}")
        
        return subdomains

    def web_archives(self):
        """Search web archives"""
        print(f"{Fore.CYAN}[*] Searching web archives...")
        subdomains = set()
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.get_session().get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data[1:]:  # Skip header
                    url = item[0]
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname and hostname.endswith(f'.{self.domain}'):
                        subdomains.add(hostname)
        except Exception as e:
            print(f"{Fore.RED}[!] Error with web archives: {e}")
        
        return subdomains

    def search_engines(self):
        """Search engines enumeration"""
        print(f"{Fore.CYAN}[*] Searching search engines...")
        subdomains = set()
        
        search_queries = [
            f"site:*.{self.domain}",
            f"site:{self.domain} -www",
            f"inurl:{self.domain}"
        ]
        
        for query in search_queries:
            try:
                # Google search simulation
                url = f"https://www.google.com/search?q={query}&num=100"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = self.get_session().get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    # Extract domains from search results
                    domains = re.findall(r'https?://([^/\s]+)', response.text)
                    for domain in domains:
                        if domain.endswith(f'.{self.domain}'):
                            subdomains.add(domain)
                
                self.stealth_delay()
            except Exception as e:
                print(f"{Fore.RED}[!] Error with search engines: {e}")
        
        return subdomains

    def dnsdumpster(self):
        """DNSDumpster enumeration"""
        print(f"{Fore.CYAN}[*] Searching DNSDumpster...")
        subdomains = set()
        
        try:
            url = "https://dnsdumpster.com/"
            session = self.get_session()
            
            # Get CSRF token with better error handling
            response = session.get(url, timeout=30)
            if response.status_code != 200:
                print(f"{Fore.RED}[!] DNSDumpster returned status {response.status_code}")
                return subdomains
                
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            
            if not csrf_token:
                print(f"{Fore.RED}[!] Could not find CSRF token in DNSDumpster response")
                return subdomains
                
            csrf_token = csrf_token.get('value')
            
            # Submit query
            headers = {
                'Referer': url,
                'X-CSRFToken': csrf_token
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain
            }
            response = session.post(url, data=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                # Extract subdomains from results
                domains = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', response.text)
                subdomains.update(domains)
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error with DNSDumpster: {str(e)}")
        
        return subdomains

    def security_apis(self):
        """Use security APIs for enumeration"""
        print(f"{Fore.CYAN}[*] Querying security APIs...")
        subdomains = set()
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            try:
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {
                    'apikey': self.api_keys['virustotal'],
                    'domain': self.domain
                }
                response = self.get_session().get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for subdomain in data.get('subdomains', []):
                        if subdomain.endswith(f'.{self.domain}'):
                            subdomains.add(subdomain)
            except Exception as e:
                print(f"{Fore.RED}[!] Error with VirusTotal: {e}")
        
        # SecurityTrails
        if 'securitytrails' in self.api_keys:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
                headers = {
                    'APIKEY': self.api_keys['securitytrails']
                }
                response = self.get_session().get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for subdomain in data.get('subdomains', []):
                        full_subdomain = f"{subdomain}.{self.domain}"
                        subdomains.add(full_subdomain)
            except Exception as e:
                print(f"{Fore.RED}[!] Error with SecurityTrails: {e}")
        
        # Censys
        if 'censys' in self.api_keys:
            try:
                url = "https://search.censys.io/api/v2/certificates/search"
                auth = (self.api_keys['censys']['id'], self.api_keys['censys']['secret'])
                params = {
                    'q': f'names: *.{self.domain}',
                    'per_page': 100
                }
                response = self.get_session().get(url, auth=auth, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for result in data.get('result', {}).get('hits', []):
                        for name in result.get('names', []):
                            if name.endswith(f'.{self.domain}'):
                                subdomains.add(name)
            except Exception as e:
                print(f"{Fore.RED}[!] Error with Censys: {e}")
        
        # Shodan integration
        if 'shodan' in self.api_keys:
            try:
                shodan_domains = self.shodan_scan()
                subdomains.update(shodan_domains)
            except Exception as e:
                print(f"{Fore.RED}[!] Error with Shodan scan: {e}")
        
        return subdomains

    def github_code_search(self):
        """Search GitHub for domain mentions"""
        print(f"{Fore.CYAN}[*] Searching GitHub code...")
        subdomains = set()
        
        try:
            url = f"https://api.github.com/search/code?q={self.domain}&sort=indexed"
            if 'github' in self.api_keys:
                headers = {'Authorization': f'token {self.api_keys["github"]}'}
            else:
                headers = {}
            
            response = self.get_session().get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    # Extract domains from code content
                    content = item.get('text_matches', [])
                    for match in content:
                        fragment = match.get('fragment', '')
                        domains = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', fragment)
                        subdomains.update(domains)
        except Exception as e:
            print(f"{Fore.RED}[!] Error with GitHub search: {e}")
        
        return subdomains

    def dns_enumeration(self):
        """Advanced DNS enumeration techniques"""
        print(f"{Fore.CYAN}[*] Performing DNS enumeration...")
        subdomains = set()
        
        # Standard DNS brute force
        wordlist = self.default_wordlist
        if self.wordlist:
            try:
                with open(self.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except:
                print(f"{Fore.RED}[!] Could not read wordlist file, using default")
        
        # Add permutations
        permutations = []
        prefixes = ['dev', 'test', 'prod', 'uat', 'new', 'old', 'staging', 'beta', 'alpha']
        suffixes = ['dev', 'prod', 'test', 'api', 'app', 'web', 'mobile']
        
        for word in wordlist:
            permutations.append(word)
            for prefix in prefixes:
                permutations.append(f"{prefix}-{word}")
                permutations.append(f"{prefix}{word}")
            for suffix in suffixes:
                permutations.append(f"{word}-{suffix}")
                permutations.append(f"{word}{suffix}")
            # Number variations
            for i in range(1, 10):
                permutations.append(f"{word}{i}")
        
        # Remove duplicates
        permutations = list(set(permutations))
        
        # DNS brute force
        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            if self.resolve_domain(subdomain):
                return subdomain
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, word) for word in permutations]
            with tqdm(total=len(futures), desc="DNS Brute Force") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.add(result)
                    pbar.update(1)
        
        # SRV Record enumeration
        srv_records = ['_sip._tcp', '_sips._tcp', '_jabber._tcp', '_xmpp-server._tcp']
        for srv in srv_records:
            try:
                resolver = self.get_resolver()
                answers = resolver.resolve(f"{srv}.{self.domain}", 'SRV')
                for answer in answers:
                    target = str(answer.target).rstrip('.')
                    if target.endswith(f'.{self.domain}'):
                        subdomains.add(target)
            except:
                pass
        
        # Zone transfer attempt
        try:
            resolver = self.get_resolver()
            ns_answers = resolver.resolve(self.domain, 'NS')
            for ns in ns_answers:
                ns_server = str(ns.target).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    for name in zone.nodes.keys():
                        if name != dns.name.root:
                            subdomain = f"{name}.{self.domain}"
                            subdomains.add(subdomain)
                except:
                    pass
        except:
            pass
        
        return subdomains

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookups"""
        print(f"{Fore.CYAN}[*] Performing reverse DNS lookups...")
        subdomains = set()
        
        # Get IP ranges for the domain
        try:
            main_ips = self.resolve_domain(self.domain)
            if main_ips:
                for ip in main_ips:
                    # Get IP range (assuming /24)
                    ip_parts = ip.split('.')
                    base_ip = '.'.join(ip_parts[:3])
                    
                    # Check nearby IPs
                    for i in range(max(1, int(ip_parts[3]) - 10), min(255, int(ip_parts[3]) + 10)):
                        test_ip = f"{base_ip}.{i}"
                        try:
                            hostname = socket.gethostbyaddr(test_ip)[0]
                            if hostname.endswith(f'.{self.domain}'):
                                subdomains.add(hostname)
                        except:
                            pass
        except Exception as e:
            print(f"{Fore.RED}[!] Error with reverse DNS: {e}")
        
        return subdomains

    def check_subdomain_takeover(self, subdomain):
        """Check if subdomain is vulnerable to takeover"""
        try:
            # Check DNS records
            resolver = self.get_resolver()
            try:
                cname_answers = resolver.resolve(subdomain, 'CNAME')
                for cname in cname_answers:
                    cname_target = str(cname.target).rstrip('.')
                    
                    # Check if CNAME points to known vulnerable services
                    for service, indicators in self.takeover_services.items():
                        if service in cname_target:
                            # Try to access the service
                            try:
                                response = self.get_session().get(f"http://{subdomain}", timeout=10)
                                content = response.text
                                
                                # Check for takeover indicators
                                for indicator in indicators:
                                    if indicator in content:
                                        return True
                            except:
                                pass
            except:
                pass
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking takeover for {subdomain}: {e}")
        
        return False

    def active_reconnaissance(self):
        """Perform active reconnaissance on discovered subdomains"""
        print(f"{Fore.CYAN}[*] Performing active reconnaissance...")
        
        def check_subdomain_active(subdomain):
            info = {
                'subdomain': subdomain,
                'active': False,
                'status_code': None,
                'server': None,
                'title': None,
                'ip': None,
                'ssh_open': False,
                'takeover_vulnerable': False,
                'ports': []
            }
            
            # Resolve IP
            ips = self.resolve_domain(subdomain)
            if ips:
                info['ip'] = ips[0]
            else:
                return info
            
            # HTTP/HTTPS check
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.get_session().get(url, timeout=10, allow_redirects=True)
                    info['active'] = True
                    info['status_code'] = response.status_code
                    info['server'] = response.headers.get('Server', 'Unknown')
                    
                    # Extract title
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            info['title'] = title_tag.text.strip()[:100]
                    
                    break
                except:
                    continue
            
            # SSH check
            if not self.fast_mode:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((subdomain, 22))
                    if result == 0:
                        info['ssh_open'] = True
                        self.ssh_enabled.add(subdomain)
                    sock.close()
                except:
                    pass
            
            # Takeover check
            if not self.fast_mode:
                if self.check_subdomain_takeover(subdomain):
                    info['takeover_vulnerable'] = True
                    self.takeover_candidates.add(subdomain)
            
            # Shodan port scan for additional services
            if 'shodan' in self.api_keys and not self.fast_mode:
                try:
                    api = shodan.Shodan(self.api_keys['shodan'])
                    ip = info['ip']
                    host = api.host(ip)
                    
                    # Add discovered ports to the info
                    if 'ports' in host:
                        info['ports'] = host['ports']
                    
                    # Check for interesting services
                    for item in host.get('data', []):
                        port = item.get('port', 0)
                        product = item.get('product', '')
                        
                        # Add service detection
                        if port == 22 and not info['ssh_open']:
                            info['ssh_open'] = True
                            self.ssh_enabled.add(subdomain)
                        
                        # Add other service checks as needed
                        if port == 3306:
                            info['mysql'] = True
                        if port == 5432:
                            info['postgresql'] = True
                        if port == 27017:
                            info['mongodb'] = True
                        if port == 5984:
                            info['couchdb'] = True
                        if port == 6379:
                            info['redis'] = True
                except shodan.exception.APIError:
                    pass
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Shodan scan error for {ip}: {e}")
            
            # Categorize
            if info['active']:
                self.active_subdomains.add(subdomain)
            else:
                self.inactive_subdomains.add(subdomain)
            
            self.subdomain_info[subdomain] = info
            self.stealth_delay()
            
            return info
        
        # Process all subdomains
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain_active, sub) for sub in self.subdomains]
            with tqdm(total=len(futures), desc="Active Reconnaissance") as pbar:
                for future in as_completed(futures):
                    future.result()
                    pbar.update(1)

    def run_passive_discovery(self):
        """Run all passive discovery methods"""
        print(f"{Fore.GREEN}[+] Starting passive discovery for {self.domain}")
        
        discovery_methods = [
            self.certificate_transparency,
            self.web_archives,
            self.search_engines,
            self.dnsdumpster,
            self.security_apis,
            self.github_code_search,
            self.dns_enumeration,
            self.reverse_dns_lookup
        ]
        
        for method in discovery_methods:
            try:
                if self.fast_mode and method in [self.reverse_dns_lookup, self.github_code_search]:
                    continue
                    
                discovered = method()
                self.subdomains.update(discovered)
                print(f"{Fore.GREEN}[+] {method.__name__}: {len(discovered)} subdomains found")
            except Exception as e:
                print(f"{Fore.RED}[!] Error in {method.__name__}: {e}")

    def generate_reports(self):
        """Generate comprehensive reports"""
        print(f"{Fore.CYAN}[*] Generating reports...")
        
        # Text reports - add encoding='utf-8'
        with open(f"{self.output_dir}/all_subdomains.txt", 'w', encoding='utf-8') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        with open(f"{self.output_dir}/active_subdomains.txt", 'w', encoding='utf-8') as f:
            for subdomain in sorted(self.active_subdomains):
                f.write(f"{subdomain}\n")
        
        with open(f"{self.output_dir}/inactive_subdomains.txt", 'w', encoding='utf-8') as f:
            for subdomain in sorted(self.inactive_subdomains):
                f.write(f"{subdomain}\n")
        
        if self.ssh_enabled:
            with open(f"{self.output_dir}/ssh_enabled.txt", 'w', encoding='utf-8') as f:
                for subdomain in sorted(self.ssh_enabled):
                    f.write(f"{subdomain}\n")
        
        if self.takeover_candidates:
            with open(f"{self.output_dir}/takeover_candidates.txt", 'w', encoding='utf-8') as f:
                for subdomain in sorted(self.takeover_candidates):
                    f.write(f"{subdomain}\n")
        
        # JSON report
        json_report = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'total_subdomains': len(self.subdomains),
            'active_subdomains': len(self.active_subdomains),
            'inactive_subdomains': len(self.inactive_subdomains),
            'ssh_enabled': len(self.ssh_enabled),
            'takeover_candidates': len(self.takeover_candidates),
            'subdomains': self.subdomain_info
        }
        
        with open(f"{self.output_dir}/scan_results.json", 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)  # ensure_ascii=False for Unicode
        
        # CSV report
        with open(f"{self.output_dir}/scan_results.csv", 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'Active', 'Status Code', 'Server', 'Title', 'IP', 'SSH Open', 'Takeover Vulnerable', 'Ports'])
            
            for subdomain in sorted(self.subdomains):
                info = self.subdomain_info.get(subdomain, {})
                writer.writerow([
                    subdomain,
                    info.get('active', False),
                    info.get('status_code', ''),
                    info.get('server', ''),
                    info.get('title', ''),
                    info.get('ip', ''),
                    info.get('ssh_open', False),
                    info.get('takeover_vulnerable', False),
                    ','.join(map(str, info.get('ports', [])))
                ])
        
        # HTML report
        self.generate_html_report()
        
        print(f"{Fore.GREEN}[+] Reports generated in {self.output_dir}/")

    def generate_html_report(self):
        """Generate interactive HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Subdomain Enumeration Report - {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #3483eb; color: white; padding: 20px; border-radius: 8px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-card {{ background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
                .filters {{ margin: 20px 0; }}
                .filter-btn {{ background-color: #3498db; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer; }}
                .filter-btn:hover {{ background-color: #2980b9; }}
                .filter-btn.active {{ background-color: #e74c3c; }}
                table {{ width: 100%; border-collapse: collapse; background-color: white; border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
                tr:hover {{ background-color: #f8f9fa; }}
                .status-active {{ color: #27ae60; font-weight: bold; }}
                .status-inactive {{ color: #e74c3c; font-weight: bold; }}
                .status-ssh {{ color: #f39c12; font-weight: bold; }}
                .status-takeover {{ color: #e74c3c; font-weight: bold; background-color: #ffebee; }}
                .hidden {{ display: none; }}
                .ports {{ max-width: 200px; overflow-x: auto; white-space: nowrap; }}
            </style>
        </head>
        <body>
            <div class="header" align="center">
                <center><h1><a href="https://github.com/bidhata/SubGrab/">SubGrab</a> Tool - By Krishnendu</h1>
                <h2>Report for Domain: {self.domain}</h2>
                <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(self.subdomains)}</div>
                    <div>Total Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.active_subdomains)}</div>
                    <div>Active Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.inactive_subdomains)}</div>
                    <div>Inactive Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.ssh_enabled)}</div>
                    <div>SSH Enabled</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.takeover_candidates)}</div>
                    <div>Takeover Candidates</div>
                </div>
            </div>
            
            <div class="filters">
                <button class="filter-btn" onclick="filterTable('all')">All</button>
                <button class="filter-btn" onclick="filterTable('active')">Active Only</button>
                <button class="filter-btn" onclick="filterTable('inactive')">Inactive Only</button>
                <button class="filter-btn" onclick="filterTable('ssh')">SSH Enabled</button>
                <button class="filter-btn" onclick="filterTable('takeover')">Takeover Candidates</button>
            </div>
            
            <table id="subdomainTable">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>Status Code</th>
                        <th>Server</th>
                        <th>Title</th>
                        <th>IP Address</th>
                        <th>SSH</th>
                        <th>Takeover Risk</th>
                        <th>Ports</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for subdomain in sorted(self.subdomains):
            info = self.subdomain_info.get(subdomain, {})
            status = "Active" if info.get('active', False) else "Inactive"
            status_class = "status-active" if info.get('active', False) else "status-inactive"
            
            row_classes = []
            if info.get('active', False):
                row_classes.append('active')
            else:
                row_classes.append('inactive')
            
            if info.get('ssh_open', False):
                row_classes.append('ssh')
            
            if info.get('takeover_vulnerable', False):
                row_classes.append('takeover')
            
            html_content += f"""
                    <tr class="{' '.join(row_classes)}">
                        <td><a href="http://{subdomain}" target="_blank">{subdomain}</a></td>
                        <td class="{status_class}">{status}</td>
                        <td>{info.get('status_code', '')}</td>
                        <td>{info.get('server', '')}</td>
                        <td>{info.get('title', '')}</td>
                        <td>{info.get('ip', '')}</td>
                        <td class="{'status-ssh' if info.get('ssh_open', False) else ''}">{
                            'Yes' if info.get('ssh_open', False) else 'No'
                        }</td>
                        <td class="{'status-takeover' if info.get('takeover_vulnerable', False) else ''}">{
                            'Yes' if info.get('takeover_vulnerable', False) else 'No'
                        }</td>
                        <td class="ports">{', '.join(map(str, info.get('ports', [])))}</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
            
            <script>
                function filterTable(filter) {
                    const table = document.getElementById('subdomainTable');
                    const rows = table.getElementsByTagName('tr');
                    
                    // Remove active class from all buttons
                    const buttons = document.getElementsByClassName('filter-btn');
                    for (let btn of buttons) {
                        btn.classList.remove('active');
                    }
                    
                    // Add active class to clicked button
                    event.target.classList.add('active');
                    
                    // Filter rows
                    for (let i = 1; i < rows.length; i++) {
                        const row = rows[i];
                        let show = false;
                        
                        switch(filter) {
                            case 'all':
                                show = true;
                                break;
                            case 'active':
                                show = row.classList.contains('active');
                                break;
                            case 'inactive':
                                show = row.classList.contains('inactive');
                                break;
                            case 'ssh':
                                show = row.classList.contains('ssh');
                                break;
                            case 'takeover':
                                show = row.classList.contains('takeover');
                                break;
                        }
                        
                        row.style.display = show ? '' : 'none';
                    }
                }
            </script>
        </body>
        </html>
        """
        
        with open(f"{self.output_dir}/report.html", 'w', encoding='utf-8') as f:
            f.write(html_content)

    def run(self):
        """Main execution method"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SubGrab - Advanced Subdomain Enumeration Tool.")
        print(f"{Fore.CYAN}by Krishnendu Paul @bidhata ")
        print(f"{Fore.RED}Target: {self.domain}")
        print(f"{Fore.CYAN}{'='*60}")
        
        start_time = time.time()
        
        # Passive discovery
        self.run_passive_discovery()
        
        print(f"{Fore.GREEN}[+] Total subdomains discovered: {len(self.subdomains)}")
        
        # Active reconnaissance
        if self.subdomains:
            self.active_reconnaissance()
        
        # Generate reports
        self.generate_reports()
        
        # Summary
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}[+] Enumeration completed in {duration:.2f} seconds")
        print(f"{Fore.GREEN}[+] Total subdomains: {len(self.subdomains)}")
        print(f"{Fore.GREEN}[+] Active subdomains: {len(self.active_subdomains)}")
        print(f"{Fore.GREEN}[+] Inactive subdomains: {len(self.inactive_subdomains)}")
        print(f"{Fore.GREEN}[+] SSH enabled: {len(self.ssh_enabled)}")
        print(f"{Fore.GREEN}[+] Takeover candidates: {len(self.takeover_candidates)}")
        print(f"{Fore.GREEN}[+] Results saved to: {self.output_dir}/")
        print(f"{Fore.CYAN}{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="SubGrab - Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subgrab.py example.com
  python subgrab.py example.com -t 100 --fast
  python subgrab.py example.com --stealth --proxy-file proxies.txt
  python subgrab.py example.com --wordlist custom.txt --timeout 60
  python subgrab.py example.com --shodan-key YOUR_API_KEY
        """
    )
    
    parser.add_argument('domain', help='Target domain to enumerate')
    parser.add_argument('-t', '--threads', type=int, default=50, 
                       help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--fast', action='store_true',
                       help='Fast mode - skip intensive tasks')
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth mode with random delays')
    parser.add_argument('--proxy-file', help='File containing proxy list')
    parser.add_argument('--wordlist', help='Custom wordlist file')
    parser.add_argument('--nameservers', nargs='+', 
                       default=['8.8.8.8', '8.8.4.4', '1.1.1.1'],
                       help='DNS nameservers to use')
    
    # API keys
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--securitytrails-key', help='SecurityTrails API key')
    parser.add_argument('--virustotal-key', help='VirusTotal API key')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API secret')
    parser.add_argument('--github-token', help='GitHub API token')
    
    args = parser.parse_args()
    
    # Load proxies if provided
    proxies = []
    if args.proxy_file:
        try:
            with open(args.proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
        except:
            print(f"{Fore.RED}[!] Could not read proxy file")
    
    # Prepare API keys
    api_keys = {}
    if args.shodan_key:
        api_keys['shodan'] = args.shodan_key
    if args.securitytrails_key:
        api_keys['securitytrails'] = args.securitytrails_key
    if args.virustotal_key:
        api_keys['virustotal'] = args.virustotal_key
    if args.censys_id and args.censys_secret:
        api_keys['censys'] = {'id': args.censys_id, 'secret': args.censys_secret}
    if args.github_token:
        api_keys['github'] = args.github_token
    
    # Initialize and run enumeration
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        fast_mode=args.fast,
        stealth=args.stealth,
        proxies=proxies,
        wordlist=args.wordlist,
        nameservers=args.nameservers,
        api_keys=api_keys
    )
    
    try:
        enumerator.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Enumeration interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")


if __name__ == "__main__":
    main()