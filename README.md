# fast-scanner
A Very Fast Subdomain Scanner with optinal Shodan api 

Passive reconnaissance (Certificate Transparency, DNS enumeration, Web archives)
Shodan integration for enhanced discovery and IP intelligence
Active reconnaissance (Zone transfers, HTTP enumeration)
CDN bypass techniques
Comprehensive output with Shodan data

1. Increased Concurrency

Default threads increased from 50 to 200
Connection pooling with 100 persistent connections
Timeout reduced to 3 seconds (configurable)

2. Enhanced DNS Resolution

Custom DNS resolver with optimized timeouts
Faster subdomain checking with check_subdomain_fast()
Limited DNS server queries for speed

3. Expanded Wordlist

80+ common subdomains instead of 24
Auto-generated numbered variations (api1, api2, etc.)
Strategic subdomain selection for better coverage

4. Multiple Data Sources

Certificate Transparency: crt.sh + CertSpotter API
Archives: Wayback Machine + AlienVault OTX
Parallel API queries with limits for speed

5. Smart Timeouts & Limits

Configurable timeouts (default 3s)
Limited results per source (500 certs, 200 DNS entries)
Future timeouts to prevent hanging

6. Fast Mode Option

--fast flag to skip Shodan lookups during initial scan
Immediate IP resolution without full Shodan data
Batch processing optimizations

Required Dependencies:
Before running this script, you'll need to install the required packages:

# Basic usage
python fast_scanner.py example.com

# With Shodan API key and custom thread count
python fast_scanner.py example.com -s YOUR_SHODAN_API_KEY -t 100

# Save results to file
python fast_scanner.py example.com -o subdomains.txt

# Fast mode (skip Shodan lookups during scan)
python fast_scanner example.com --fast
