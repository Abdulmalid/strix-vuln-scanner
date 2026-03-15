#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import json
import logging
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# --- Configuration & Constants ---
DEFAULT_THREADS = 20
DEFAULT_RATE_LIMIT = 100
OUTPUT_DIR = "output"
LOG_FILE = "scanner.log"

# Tool paths (update these if necessary)
TOOLS = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "httpx": "httpx",
    "waybackurls": "waybackurls",
    "gau": "gau",
    "katana": "katana",
    "dirsearch": "dirsearch",
    "nuclei": "nuclei",
    "strix": "strix"  # Added Strix AI
}

# --- Logging & UI ---
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.END} {msg}")
    logging.info(msg)

def log_success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {msg}")
    logging.info(msg)

def log_warning(msg):
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} {msg}")
    logging.warning(msg)

def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")
    logging.error(msg)

# --- Helper Functions ---
def check_dependencies(use_strix=False):
    """Check if required tools are installed."""
    missing_tools = []
    required_tools = list(TOOLS.keys())
    if not use_strix:
        required_tools.remove("strix")
        
    for tool in required_tools:
        path = TOOLS[tool]
        if subprocess.run(["which", path], capture_output=True).returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        log_error(f"Missing tools: {', '.join(missing_tools)}")
        sys.exit(1)
    log_success("All dependencies are met.")

def run_command(command, output_file=None):
    """Execute a shell command and optionally redirect output to a file."""
    try:
        if output_file:
            with open(output_file, "w") as f:
                subprocess.run(command, stdout=f, stderr=subprocess.PIPE, check=True)
        else:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
    except subprocess.CalledProcessError as e:
        log_error(f"Command failed: {' '.join(command)}")
        log_error(f"Error: {e.stderr}")
        return None

def normalize_domain(domain):
    """Remove protocol and trailing slash from domain."""
    domain = domain.strip().lower()
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    return domain.rstrip("/")

def get_target_dir(domain):
    """Create and return target-specific output directory."""
    path = os.path.join(OUTPUT_DIR, domain)
    os.makedirs(path, exist_ok=True)
    return path

# --- Phase Implementations ---

def phase_1_input_handling(args):
    """Handle input domains from CLI or file."""
    domains = []
    if args.domain:
        domains.append(normalize_domain(args.domain))
    if args.list:
        with open(args.list, "r") as f:
            domains.extend([normalize_domain(line) for line in f if line.strip()])
    
    unique_domains = sorted(list(set(domains)))
    log_info(f"Loaded {len(unique_domains)} unique domains.")
    return unique_domains

def phase_2_subdomain_enumeration(domain, target_dir, skip=False):
    """Discover subdomains using subfinder and assetfinder."""
    if skip:
        log_warning(f"Skipping subdomain enumeration for {domain}.")
        return
    
    output_file = os.path.join(target_dir, "subdomains.txt")
    log_info(f"Enumerating subdomains for {domain}...")
    
    # Run subfinder
    subfinder_cmd = [TOOLS["subfinder"], "-d", domain, "-silent"]
    subdomains = run_command(subfinder_cmd).splitlines()
    
    # Run assetfinder (optional)
    assetfinder_cmd = [TOOLS["assetfinder"], "--subs-only", domain]
    assetfinder_output = run_command(assetfinder_cmd)
    if assetfinder_output:
        subdomains.extend(assetfinder_output.splitlines())
    
    unique_subs = sorted(list(set(subdomains)))
    with open(output_file, "w") as f:
        f.write("\n".join(unique_subs))
    
    log_success(f"Found {len(unique_subs)} subdomains. Saved to {output_file}")

def phase_3_live_host_detection(target_dir):
    """Detect live hosts using httpx."""
    input_file = os.path.join(target_dir, "subdomains.txt")
    output_file = os.path.join(target_dir, "alive_subdomains.txt")
    
    if not os.path.exists(input_file):
        log_warning(f"No subdomains file found at {input_file}. Skipping live host detection.")
        return

    log_info("Detecting live hosts...")
    httpx_cmd = [TOOLS["httpx"], "-l", input_file, "-silent", "-fc", "404", "-follow-redirects", "-status-code", "-o", output_file]
    run_command(httpx_cmd)
    
    with open(output_file, "r") as f:
        count = len(f.readlines())
    log_success(f"Found {count} live hosts. Saved to {output_file}")

def phase_4_url_collection(domain, target_dir):
    """Collect URLs from waybackurls, gau, and katana."""
    output_file = os.path.join(target_dir, "all_urls.txt")
    log_info(f"Collecting URLs for {domain}...")
    
    urls = []
    
    # Waybackurls
    wayback_cmd = [TOOLS["waybackurls"], domain]
    wayback_output = run_command(wayback_cmd)
    if wayback_output:
        urls.extend(wayback_output.splitlines())
        
    # GAU
    gau_cmd = [TOOLS["gau"], domain]
    gau_output = run_command(gau_cmd)
    if gau_output:
        urls.extend(gau_output.splitlines())
        
    # Katana
    katana_cmd = [TOOLS["katana"], "-u", domain, "-silent"]
    katana_output = run_command(katana_cmd)
    if katana_output:
        urls.extend(katana_output.splitlines())
        
    unique_urls = sorted(list(set(urls)))
    with open(output_file, "w") as f:
        f.write("\n".join(unique_urls))
    
    log_success(f"Collected {len(unique_urls)} unique URLs. Saved to {output_file}")

def phase_5_directory_discovery(target_dir):
    """Run dirsearch against live hosts."""
    input_file = os.path.join(target_dir, "alive_subdomains.txt")
    url_file = os.path.join(target_dir, "all_urls.txt")
    
    if not os.path.exists(input_file):
        return

    log_info("Running directory discovery...")
    # Using a simplified dirsearch command for speed; adjust wordlist as needed
    with open(input_file, "r") as f:
        hosts = [line.split()[0] for line in f if line.strip()]
    
    discovered_paths = []
    for host in hosts:
        dirsearch_cmd = [TOOLS["dirsearch"], "-u", host, "-e", "php,html,js", "--format", "plain", "-q"]
        output = run_command(dirsearch_cmd)
        if output:
            discovered_paths.extend(output.splitlines())
            
    if discovered_paths:
        with open(url_file, "a") as f:
            f.write("\n".join(discovered_paths) + "\n")
        log_success(f"Added {len(discovered_paths)} discovered paths to URL list.")

def phase_6_url_filtering(domain, target_dir):
    """Filter URLs to keep unique, in-scope, non-static URLs."""
    input_file = os.path.join(target_dir, "all_urls.txt")
    output_file = os.path.join(target_dir, "filtered_urls.txt")
    
    if not os.path.exists(input_file):
        return

    log_info("Filtering URLs...")
    static_exts = ('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.mp4', '.pdf')
    
    filtered_urls = []
    with open(input_file, "r") as f:
        for line in f:
            url = line.strip()
            parsed = urlparse(url)
            if domain in parsed.netloc and not parsed.path.lower().endswith(static_exts):
                filtered_urls.append(url)
                
    unique_filtered = sorted(list(set(filtered_urls)))
    with open(output_file, "w") as f:
        f.write("\n".join(unique_filtered))
    
    log_success(f"Filtered to {len(unique_filtered)} URLs. Saved to {output_file}")

def phase_7_parameter_extraction(target_dir):
    """Extract URLs containing parameters."""
    input_file = os.path.join(target_dir, "filtered_urls.txt")
    output_file = os.path.join(target_dir, "params.txt")
    
    if not os.path.exists(input_file):
        return

    log_info("Extracting parameter URLs...")
    param_urls = []
    with open(input_file, "r") as f:
        for line in f:
            url = line.strip()
            if "?" in url and "=" in url:
                param_urls.append(url)
                
    unique_params = sorted(list(set(param_urls)))
    with open(output_file, "w") as f:
        f.write("\n".join(unique_params))
    
    log_success(f"Extracted {len(unique_params)} parameter URLs. Saved to {output_file}")

def phase_8_verify_alive_params(target_dir):
    """Verify liveness of parameter URLs."""
    input_file = os.path.join(target_dir, "params.txt")
    output_file = os.path.join(target_dir, "alive_params.txt")
    
    if not os.path.exists(input_file):
        return

    log_info("Verifying alive parameter URLs...")
    httpx_cmd = [TOOLS["httpx"], "-l", input_file, "-silent", "-fc", "404", "-o", output_file]
    run_command(httpx_cmd)
    
    with open(output_file, "r") as f:
        count = len(f.readlines())
    log_success(f"Verified {count} alive parameter URLs. Saved to {output_file}")

def phase_9_vulnerability_scanning(target_dir, threads, rate_limit, use_strix=False):
    """Run Nuclei and optionally Strix AI scans on alive parameter URLs."""
    input_file = os.path.join(target_dir, "alive_params.txt")
    findings_txt = os.path.join(target_dir, "findings.txt")
    findings_json = os.path.join(target_dir, "findings.json")
    strix_findings = os.path.join(target_dir, "strix_findings.txt")
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        log_warning("No alive parameter URLs to scan for vulnerabilities.")
        return

    # Run Nuclei
    log_info("Running Nuclei vulnerability scan...")
    nuclei_cmd = [
        TOOLS["nuclei"], 
        "-l", input_file, 
        "-silent", 
        "-c", str(threads), 
        "-rl", str(rate_limit),
        "-o", findings_txt,
        "-json-export", findings_json
    ]
    run_command(nuclei_cmd)
    
    # Run Strix AI (if enabled)
    if use_strix:
        log_info("Running Strix AI autonomous vulnerability scan...")
        # Strix supports multiple targets, we'll pass the file directly in non-interactive mode
        # Adjust command based on Strix CLI specifics
        strix_cmd = [
            TOOLS["strix"],
            "--target", input_file,
            "--non-interactive"
        ]
        # Strix findings are often printed to stdout or a default log; we'll capture it
        strix_output = run_command(strix_cmd)
        if strix_output:
            with open(strix_findings, "w") as f:
                f.write(strix_output)
            log_success(f"Strix AI scan complete. Findings saved to {strix_findings}")
    
    if os.path.exists(findings_txt):
        with open(findings_txt, "r") as f:
            count = len(f.readlines())
        log_success(f"Nuclei scan complete. Found {count} potential issues.")
    else:
        log_info("Nuclei scan complete. No issues found.")

def phase_10_result_storage(domain, target_dir):
    """Finalize results and provide summary."""
    log_success(f"Scan completed for {domain}. Results stored in {target_dir}")

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="Automated Web Vulnerability Scanner for Bug Bounty")
    parser.add_argument("domain", nargs="?", help="Single domain to scan")
    parser.add_argument("-l", "--list", help="File containing list of domains to scan")
    parser.add_argument("--skip-subfinder", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--crawl-only", action="store_true", help="Only perform reconnaissance and crawling")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT, help=f"Rate limit (default: {DEFAULT_RATE_LIMIT})")
    parser.add_argument("--strix", action="store_true", help="Enable Strix AI autonomous scanning")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan (not fully implemented)")
    
    args = parser.parse_args()
    
    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)
        
    # Setup logging
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    log_info(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    check_dependencies(use_strix=args.strix)
    
    domains = phase_1_input_handling(args)
    
    for domain in domains:
        target_dir = get_target_dir(domain)
        log_info(f"Processing target: {domain}")
        
        # Reconnaissance & Discovery
        phase_2_subdomain_enumeration(domain, target_dir, skip=args.skip_subfinder)
        phase_3_live_host_detection(target_dir)
        phase_4_url_collection(domain, target_dir)
        phase_5_directory_discovery(target_dir)
        
        # Filtering & Extraction
        phase_6_url_filtering(domain, target_dir)
        phase_7_parameter_extraction(target_dir)
        phase_8_verify_alive_params(target_dir)
        
        # Scanning
        if not args.crawl_only:
            phase_9_vulnerability_scanning(target_dir, args.threads, args.rate_limit, use_strix=args.strix)
            
        phase_10_result_storage(domain, target_dir)
        
    log_info(f"All scans completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warning("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        log_error(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
