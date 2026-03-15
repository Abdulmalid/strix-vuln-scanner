# Automated Web Vulnerability Scanner

This is a complete, modular, high-performance Python3 automated web vulnerability scanner script for bug bounty reconnaissance and vulnerability discovery.

## Features

- **Input Handling:** Accepts single, multiple, or file-based domain inputs.
- **Subdomain Discovery:** Uses `subfinder` and `assetfinder` for comprehensive subdomain enumeration.
- **Live Host Detection:** Uses `httpx-toolkit` to identify alive hosts and their status codes.
- **URL Collection:** Gathers URLs from `waybackurls`, `gau`, and `katana`.
- **Directory Discovery:** Runs `dirsearch` against alive hosts to find hidden paths.
- **URL Filtering:** Filters for unique, in-scope, and non-static URLs.
- **Parameter Extraction:** Extracts URLs containing parameters for targeted scanning.
- **Vulnerability Scanning:** Uses `Nuclei` with severity filtering, concurrency, and rate limits.
- **Structured Results:** Saves all intermediate and final findings in a target-specific directory structure.

## Dependencies

The script requires the following tools to be installed in your environment (e.g., Kali Linux):

- `subfinder`
- `assetfinder`
- `httpx-toolkit`
- `waybackurls`
- `gau`
- `katana`
- `dirsearch`
- `nuclei`
- `strix` (optional, for autonomous AI scanning)

## Usage

```bash
python3 scanner.py example.com
python3 scanner.py -l domains.txt
```

### Optional Flags

- `--skip-subfinder`: Skip subdomain enumeration.
- `--crawl-only`: Only perform reconnaissance and crawling (no vulnerability scanning).
- `--threads 50`: Set the number of threads for scanning (default: 20).
- `--rate-limit 100`: Set the rate limit for scanning (default: 100).
- `--strix`: Enable Strix AI autonomous scanning.
- `--resume`: Resume a previous scan (not fully implemented).

## Results

All results are saved in the `output/` directory, organized by target domain. Each target directory contains:

- `subdomains.txt`: Discovered subdomains.
- `alive_subdomains.txt`: Alive subdomains with status codes.
- `all_urls.txt`: All collected URLs.
- `filtered_urls.txt`: Filtered, unique, in-scope URLs.
- `params.txt`: URLs with parameters.
- `alive_params.txt`: Alive parameter URLs.
- `findings.json`: Vulnerability findings in JSON format.
- `findings.txt`: Vulnerability findings in TXT format.
