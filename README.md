# OSINTScan

**OSINTScan** is a lightweight, asynchronous network reconnaissance tool designed to gather comprehensive intelligence on IP addresses and domains.

Built with Python's `asyncio` and `aiohttp`, it performs multiple scans concurrently (DNS, WHOIS, Port Scanning, Geolocation), making it significantly faster than traditional synchronous scripts.

## Features

* **Asynchronous Execution:** Leverages non-blocking I/O to perform all scans in parallel.
* **Geolocation:** Retrieves precise location data (City, Region, Country, Coordinates).
* **WHOIS Lookup:** Fetches ISP, Organization, and location details.
* **DNS Enumeration:** Resolves common DNS records (A, MX, NS, TXT) for domains.
* **Reputation Check:** Integrates with **AbuseIPDB** to check if the target is blacklisted or malicious.
* **Port Scanner:** Fast TCP connect scan for the most common 100+ ports using semaphores to prevent congestion.
* **CLI Interface:** Clean, colorized terminal output for easy reading.

## Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/yourusername/OSINTScan.git](https://github.com/yourusername/OSINTScan.git)
    cd OSINTScan
    ```

2.  **Install dependencies**
    The tool relies on `aiohttp` for async requests.
    ```bash
    pip install -r requirements.txt
    ```

## Configuration (API Key)

This tool uses the **AbuseIPDB API** to check for malicious IP reports. You need a free API key to use this specific feature.

1.  Get a free key from [AbuseIPDB](https://www.abuseipdb.com/).
2.  Set it as an environment variable (for security, do not hardcode it in the script).

**Linux / macOS:**
```bash
export ABUSEIPDB_KEY='your_api_key_here'
```
***Windows (PowerShell)**
```bashh
$env:ABUSEIPDB_KEY='your_api_key_here'
```

## Usage
Run the script using Python. You can provide an IP address or a Domain name.

**Basic Scan (Default)**
```bash
python3 osintscan.py google.com
```

**Run all modules**<br>
This runs Geo, Whois, DNS, AbuseIPDB, and Port Scanning simultaneously.
```bash
python3 osintscan.py 8.8.8.8 --all
```

**Specific Flags**<br>
```bash
options:
  target                Target IP or Domain
  -h, --help            Show this help message and exit
  -g, --geo             Retrieve geolocation information
  -w, --whois           Fetch WHOIS-style IP ownership details
  -d, --dns             Perform DNS enumeration
  -p, --port            Scan for open ports (Common ports only)
  -s, --abuseIPDB       Query AbuseIPDB reputation score (Requires API Key)
  -a, --all             Run all available recon modules
```

## Screenshots

## Disclaimer

This tool is designed for educational purposes and authorized security assessments only. Do not use this tool on networks or systems you do not have permission to scan. The author is not responsible for any misuse.
