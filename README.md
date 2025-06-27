# 🚀 Fast Sub Recon

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

## ✨ Features

- 🔍 Passive subdomain discovery from multiple public sources
- ⚙️ Active brute-forcing with smart permutations
- 📊 HTML, JSON, and plain text reports
- 🌐 IP, HTTP status, server headers, and title extraction
- 🔐 Optional SSH port (22) scan
- 🚀 Multithreaded for high performance
- 🔐 API Integrations:
  - Shodan
  - VirusTotal
  - SecurityTrails
  - crt.sh
  - CommonCrawl
  - DNSDumpster
  - AlienVault OTX
  - Archive.org
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

---

## 🧪 Usage Examples

Basic usage:

```bash
python fast_sub_recon.py example.com
```

Use with Shodan and a custom wordlist:

```bash
python fast_sub_recon.py example.com -s YOUR_SHODAN_API_KEY -w wordlist.txt
```

Fast mode without passive recon:

```bash
python fast_sub_recon.py example.com --fast
```

Scan active subdomains for SSH:

```bash
python fast_sub_recon.py example.com --scan-ssh
```

Use custom DNS resolvers and max threads:

```bash
python fast_sub_recon.py example.com -t 300 --custom-nameservers 1.1.1.1 8.8.8.8
```

Enable full API integrations:

```bash
python fast_sub_recon.py example.com \
  --shodan YOUR_SHODAN_API_KEY \
  --security-trails YOUR_SECURITYTRAILS_API_KEY \
  --virustotal YOUR_VIRUSTOTAL_API_KEY
```

---

## Command Line Options

| Option | Description | Default Value | Example |
|--------|-------------|---------------|---------|
| `domain` | **REQUIRED** Target domain to scan | None | `example.com` |
| `-t`, `--threads` | Number of threads to use for parallel operations | 200 | `-t 500` |
| `-s`, `--shodan` | Shodan API key for enhanced passive reconnaissance | None | `-s YOUR_SHODAN_KEY` |
| `-w`, `--wordlist` | Path to custom wordlist file | Built-in wordlist | `-w custom_words.txt` |
| `--timeout` | Timeout in seconds for network requests | 3 | `--timeout 5` |
| `--fast` | Enable fast mode (skip intensive operations like advanced brute-forcing) | False | `--fast` |
| `--scan-ssh` | Scan active subdomains for open SSH port (22) | False | `--scan-ssh` |
| `--custom-nameservers` | Custom DNS nameservers to use (space separated) | System default | `--custom-nameservers 8.8.8.8 1.1.1.1` |
| `--security-trails` | SecurityTrails API key | None | `--security-trails YOUR_KEY` |
| `--virustotal` | VirusTotal API key | None | `--virustotal YOUR_KEY` |

### Usage Examples

1. Basic scan with default settings:
   ```bash
   ./fast_sub_recon.py example.com
   ```

2. Scan with custom threads and timeout:
   ```bash
   ./fast_sub_recon.py example.com -t 500 --timeout 5
   ```

3. Scan with Shodan integration and custom wordlist:
   ```bash
   ./fast_sub_recon.py example.com -s YOUR_API_KEY -w custom_wordlist.txt
   ```

4. Full scan with SSH detection and custom DNS:
   ```bash
   ./fast_sub_recon.py example.com --scan-ssh --custom-nameservers 8.8.8.8 9.9.9.9
   ```

5. Fast scan mode:
   ```bash
   ./fast_sub_recon.py example.com --fast
   ```

---

## 📁 Output Files

Each run creates a directory named after the target domain:

```
example.com/
├── example.com_all_<timestamp>.txt
├── example.com_active_<timestamp>.txt
├── example.com_inactive_<timestamp>.txt
├── example.com_ssh_<timestamp>.txt         # if SSH scan enabled
├── example.com_report_<timestamp>.json
└── example.com_report_<timestamp>.html
```

---

## 🌐 HTML Report

The generated HTML report includes:

- ✅ Subdomain activity status
- 🌍 IP address mapping
- 🔍 HTTP status, page title, and server banner
- 🔐 SSH port availability
- 🧩 Sortable columns and filter buttons

It’s mobile-responsive, sortable, and easy to analyze visually.


### Important Notes
- Always obtain proper authorization before scanning any domain
- Shodan integration requires a valid API key from [shodan.io](https://www.shodan.io/)
- For large domains, increase thread count (`-t`) and timeout (`--timeout`) values
- Custom nameservers can help bypass DNS filtering or caching issues
- Fast mode (`--fast`) significantly speeds up scans by skipping Shodan lookups
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
