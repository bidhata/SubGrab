<div align="center"># 🚀 Fast Sub Recon</div>

<div align="center">

![Python](https://img.shields.io/badge/python-v3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)
![Version](https://img.shields.io/badge/version-2.0-orange.svg)

**Enhanced Subdomain Discovery Tool with Shodan Integration**

*Fast, comprehensive, and intelligent subdomain enumeration for security researchers and bug bounty hunters*

</div>

---

## 🎯 Overview

Fast Sub Recon is a powerful Python-based subdomain discovery tool designed for authorized security testing and bug bounty programs. It combines multiple reconnaissance techniques including passive enumeration, active scanning, and Shodan integration to provide comprehensive subdomain discovery with detailed analysis.

### 🌟 Key Highlights

- **Multi-threaded Performance**: Up to 200+ concurrent threads for lightning-fast scanning
- **Comprehensive Coverage**: Combines passive and active reconnaissance techniques
- **Shodan Integration**: Leverages Shodan API for enhanced intelligence gathering
- **Smart Enumeration**: Uses multiple data sources including Certificate Transparency, DNS, and web archives
- **Detailed Reporting**: Generates JSON and text reports with comprehensive subdomain analysis
- **Customizable Wordlists**: Support for external wordlist files
- **CDN Bypass Attempts**: Tries to identify real IP addresses behind CDNs

---

## 🔥 Features

### 🔍 **Passive Reconnaissance**
- **Certificate Transparency Logs**: Queries crt.sh and CertSpotter
- **DNS Enumeration**: Fast DNS resolution with custom resolvers
- **Web Archives**: Searches Archive.org and AlienVault OTX
- **Shodan Search**: Multiple query types for comprehensive coverage

### ⚡ **Active Reconnaissance**
- **Zone Transfer Attempts**: Tests for misconfigured DNS servers
- **HTTP Enumeration**: Identifies active web services
- **SSL Certificate Analysis**: Extracts hostnames from SSL certificates
- **Real IP Discovery**: Attempts to bypass CDN protection

### 📊 **Intelligence Gathering**
- **Shodan Integration**: Detailed host information including:
  - Organization and ISP details
  - Geographic location
  - Open ports and services
  - Last update timestamps
- **HTTP Analysis**: Status codes, server headers, page titles
- **DNS Resolution**: Multiple DNS server queries for accuracy

### 📁 **Output Formats**
- **Comprehensive JSON**: Detailed analysis with all metadata
- **Active Subdomains**: HTTP-accessible hosts only
- **Inactive Subdomains**: DNS-only discoverable hosts
- **Combined Lists**: All discovered subdomains

---

## 🛠 Installation

### Prerequisites
```bash
# Python 3.6+ required
python3 --version
```

### Method 1: Clone Repository
```bash
git clone https://github.com/bidhata/fast-subrecon/
cd fast-sub-recon
pip3 install -r requirements.txt
```

### Method 2: Direct Download
```bash
wget https://raw.githubusercontent.com/bidhata/fast-subrecon/main/fast_sub_recon.py
pip3 install requests dnspython shodan
```

### Dependencies
```bash
pip3 install requests dnspython shodan
```

---

## 🚀 Usage

### Basic Usage
```bash
# Simple subdomain discovery
python3 fast_sub_recon.py example.com

# With custom thread count
python3 fast_sub_recon.py example.com -t 300

# With Shodan integration
python3 fast_sub_recon.py example.com -s YOUR_SHODAN_API_KEY
```

### Advanced Usage
```bash
# Custom wordlist
python3 fast_sub_recon.py example.com -w /path/to/wordlist.txt

# Fast mode (skip detailed Shodan lookups)
python3 fast_sub_recon.py example.com --fast

# Custom timeout
python3 fast_sub_recon.py example.com --timeout 5

# Save only active subdomains
python3 fast_sub_recon.py example.com -o active_subs.txt --active-only
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Target domain to scan | Required |
| `-t, --threads` | Number of concurrent threads | 200 |
| `-s, --shodan` | Shodan API key for enhanced data | None |
| `-w, --wordlist` | Custom wordlist file path | Built-in list |
| `--timeout` | Request timeout in seconds | 3 |
| `--fast` | Skip detailed Shodan lookups | False |
| `-o, --output` | Legacy output file (deprecated) | Auto-generated |
| `--active-only` | Save only active subdomains | False |
| `--inactive-only` | Save only inactive subdomains | False |

---

## 📋 Examples

### Example 1: Basic Scan
```bash
$ python3 fast_sub_recon.py example.com
[+] Starting subdomain discovery for example.com
[+] Starting passive reconnaissance for example.com
[+] Querying Certificate Transparency logs...
[CT] Found: www.example.com
[CT] Found: mail.example.com
[+] Performing fast DNS enumeration...
[+] Testing 127 subdomains with 200 threads...
[DNS] Found: api.example.com
[+] Starting active reconnaissance...
[HTTP-Active] www.example.com [200] via https
[+] Found 15 total subdomains
[+] Active subdomains: 8
[+] Inactive subdomains: 7
```

### Example 2: With Shodan Integration
```bash
$ python3 fast_sub_recon.py example.com -s YOUR_API_KEY
[+] Shodan API initialized
[+] Starting subdomain discovery for example.com
[Shodan] Found: api.example.com
[Shodan-SSL] Found: secure.example.com
[ACTIVE] www.example.com
    Status: 200
    Scheme: https
    [DNS] 93.184.216.34
        Org: EdgeCast Networks
        ISP: EdgeCast Networks
        Location: Los Angeles, United States
        Open Ports: 80, 443
```

### Example 3: Custom Wordlist
```bash
$ python3 fast_sub_recon.py example.com -w subdomains.txt -t 500
[+] Loading wordlist from subdomains.txt
[+] Loaded 50000 subdomains from wordlist
[+] Total wordlist size: 50089 subdomains
[+] Testing 50089 subdomains with 500 threads...
```

---

## 📊 Output Files

The tool automatically generates timestamped output files:

```
example.com_subdomains_20241225_143022.json    # Comprehensive JSON report
example.com_active_20241225_143022.txt         # Active subdomains only
example.com_inactive_20241225_143022.txt       # Inactive subdomains only
example.com_all_20241225_143022.txt           # All discovered subdomains
```

### JSON Output Structure
```json
{
  "domain": "example.com",
  "timestamp": "2024-12-25 14:30:22",
  "total_subdomains": 23,
  "active_subdomains": 12,
  "inactive_subdomains": 11,
  "subdomains": {
    "active": [
      {
        "subdomain": "www.example.com",
        "status": "active",
        "http_status": 200,
        "scheme": "https",
        "server": "nginx/1.18.0",
        "title": "Example Domain",
        "ips": [
          {
            "source": "DNS",
            "ip": "93.184.216.34",
            "shodan": {
              "org": "EdgeCast Networks",
              "isp": "EdgeCast Networks",
              "country": "United States",
              "city": "Los Angeles",
              "ports": [80, 443],
              "last_update": "2024-12-20T10:30:00.000000"
            }
          }
        ]
      }
    ]
  }
}
```

---

## 🎯 Wordlists

### Built-in Wordlist
The tool includes a comprehensive built-in wordlist with:
- Common subdomain patterns (www, mail, api, etc.)
- Numbered variations (api1, api2, cdn1, etc.)
- Technical subdomains (staging, dev, test, etc.)
- Infrastructure subdomains (vpn, proxy, gateway, etc.)

### Custom Wordlists
You can use external wordlist files:
```bash
# SecLists subdomain wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
python3 fast_sub_recon.py example.com -w subdomains-top1million-110000.txt

# Assetnote wordlist
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
python3 fast_sub_recon.py example.com -w best-dns-wordlist.txt
```

---

## 🔧 Configuration

### Shodan API Setup
1. Sign up at [Shodan.io](https://www.shodan.io/)
2. Get your API key from your account dashboard
3. Use it with the `-s` parameter:
```bash
python3 fast_sub_recon.py example.com -s YOUR_SHODAN_API_KEY
```

### Performance Tuning
```bash
# High-performance scan (use with caution)
python3 fast_sub_recon.py example.com -t 500 --timeout 2

# Conservative scan for slower networks
python3 fast_sub_recon.py example.com -t 50 --timeout 10

# Fast mode for quick results
python3 fast_sub_recon.py example.com --fast
```

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing and bug bounty programs only.

- ✅ **Authorized Use**: Only scan domains you own or have explicit permission to test
- ❌ **Unauthorized Use**: Scanning domains without permission may be illegal
- 📋 **Compliance**: Ensure compliance with local laws and regulations
- 🛡️ **Responsibility**: Users are responsible for their actions

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest features.

### Development Setup
```bash
git clone https://github.com/bidhata/fast-subrecon.git
cd fast-sub-recon
pip3 install -r requirements.txt
python3 -m pytest tests/  # Run tests
```

### Areas for Contribution
- Additional passive reconnaissance sources
- Performance optimizations
- New output formats
- Enhanced CDN bypass techniques
- Documentation improvements

---

## 📝 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- **Certificate Transparency Logs**: crt.sh, CertSpotter
- **Shodan**: For comprehensive host intelligence
- **DNS Libraries**: dnspython for robust DNS operations
- **Community**: Security researchers and bug bounty hunters

---

<div align="center">

**⭐ Star this repository if you find it useful! ⭐**

Made with ❤️ for the security community

</div>
