
# 🔍 SubGrab - Advanced Subdomain Enumeration Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)
![Author](https://img.shields.io/badge/Maintainer-Krishnendu%20Paul-blue)

> SubGrab is a powerful and feature-rich subdomain enumeration tool designed for **security researchers**, **bug bounty hunters**, and **pentesters**. It performs **passive**, **active**, and **stealth** recon, enriched with **visual HTML reporting**, **Shodan**, **CT logs**, **DNS analysis**, and more.

---

## ✨ Features

- 🔎 **Passive Reconnaissance**:  
  Certificate Transparency logs, Web Archives, Search Engines, RapidDNS, GitHub, VirusTotal, Censys, SecurityTrails, Shodan and more.

- 🌐 **Advanced DNS Enumeration**:  
  Brute-force with permutations, SRV records, Zone transfers, NSEC walking, Reverse DNS.

- 🕵️ **Stealth Mode**:  
  Human-like delays, proxy support, randomized requests to avoid detection.

- 🚀 **Fast & Scalable**:  
  Multi-threaded with `ThreadPoolExecutor`, supports thousands of subdomains quickly.

- 📊 **Rich Reporting**:  
  Generates `txt`, `csv`, `json`, and **interactive HTML dashboards**.

- 🔐 **Takeover Detection**:  
  Detects vulnerable subdomains by analyzing common misconfigurations.

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/subgrab.git
cd subgrab
pip install -r requirements.txt
```

Or install dependencies manually:

```bash
pip install requests dnspython colorama beautifulsoup4 tqdm ratelimit shodan certifi tenacity
```

---

## ⚙️ Usage

```bash
python subgrab.py example.com
```

### 🔧 Options:

```bash
  -t, --threads            Number of threads (default: 50)
  --timeout                Request timeout (default: 30)
  --fast                   Skip resource-intensive steps
  --stealth                Randomized request timing
  --proxy-file             Provide a list of HTTP proxies
  --wordlist               Use a custom subdomain wordlist
  --nameservers            Custom DNS resolvers

  # API keys
  --shodan-key             SHODAN API key
  --securitytrails-key     SecurityTrails API key
  --virustotal-key         VirusTotal API key
  --censys-id              Censys API ID
  --censys-secret          Censys API Secret
  --github-token           GitHub API Token
```

---

## 📁 Output

Results are saved in a folder like `example.com_results/`:
- `all_subdomains.txt`
- `active_subdomains.txt`
- `scan_results.json`
- `scan_results.csv`
- `report.html` _(interactive dashboard!)_

---

## 👨‍💻 Author

**Krishnendu Paul**  
💼 [LinkedIn](https://www.linkedin.com/in/krishpaul)  
📫 [me@krishnendu.com](mailto:me@krishnendu.com)  
🔗 [github.com/bidhata](https://github.com/bidhata)

---

## ⚠️ Disclaimer

> This tool is intended **only for authorized security testing** and educational purposes.  
> The user assumes all responsibility for usage. Always get permission before scanning domains you don’t own.

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 📌 To-Do

- [DONE] Add Shodan integration
- [ ] Dockerize the tool
- [ ] Extend to IPv6 discovery
- [ ] Support multi-domain scanning

---

## 💬 Contributions

Issues, PRs, feedback, and feature requests are welcome!
