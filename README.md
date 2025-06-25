# fast-scanner
A Very Fast Subdomain Scanner with Optional Shodan API Integration

## Description
`fast-scanner` is a high-performance subdomain scanner designed for rapid reconnaissance. It combines passive and active techniques, including Certificate Transparency, DNS enumeration, web archives, and Shodan integration for enhanced discovery and IP intelligence. The tool includes CDN bypass techniques and provides comprehensive output with Shodan data.

## Features
- **Passive Reconnaissance**: Utilizes Certificate Transparency (crt.sh, CertSpotter API), DNS enumeration, and web archives (Wayback Machine, AlienVault OTX).
- **Shodan Integration**: Enhances discovery with IP intelligence and detailed Shodan data.
- **Active Reconnaissance**: Supports zone transfers and HTTP enumeration.
- **CDN Bypass Techniques**: Identifies true IP addresses behind CDNs.
- **Comprehensive Output**: Combines results from multiple sources with Shodan data for detailed reporting.

## Improvements
1. **Increased Concurrency**
   - Default threads increased from 50 to 200.
   - Connection pooling with 100 persistent connections.
   - Timeout reduced to 3 seconds (configurable).

2. **Enhanced DNS Resolution**
   - Custom DNS resolver with optimized timeouts.
   - Faster subdomain checking with `check_subdomain_fast()`.
   - Limited DNS server queries for improved speed.

3. **Expanded Wordlist**
   - Over 80 common subdomains (up from 24).
   - Auto-generated numbered variations (e.g., `api1`, `api2`).
   - Strategic subdomain selection for better coverage.

4. **Multiple Data Sources**
   - Certificate Transparency: crt.sh and CertSpotter API.
   - Archives: Wayback Machine and AlienVault OTX.
   - Parallel API queries with rate limits for speed.

5. **Smart Timeouts & Limits**
   - Configurable timeouts (default: 3 seconds).
   - Limited results per source (500 certificates, 200 DNS entries).
   - Future-proof timeouts to prevent hanging.

6. **Fast Mode Option**
   - `--fast` flag skips Shodan lookups during the initial scan.
   - Immediate IP resolution without full Shodan data.
   - Batch processing optimizations for speed.

## Requirements
Before running the script, install the required dependencies:
```bash
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/fast-scanner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd fast-scanner
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the scanner with the following commands:

- **Basic Usage**:
  ```bash
  python fast_scanner.py example.com
  ```

- **With Shodan API Key and Custom Thread Count**:
  ```bash
  python fast_scanner.py example.com -s YOUR_SHODAN_API_KEY -t 100
  ```

- **Save Results to File**:
  ```bash
  python fast_scanner.py example.com -o subdomains.txt
  ```

- **Fast Mode (Skip Shodan Lookups)**:
  ```bash
  python fast_scanner.py example.com --fast
  ```

## Contributing
Contributions are welcome! Follow these steps to contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
