import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import sys
import argparse
import csv
from datetime import datetime

def log(message: str):
    """Prints a log message and flushes stdout immediately."""
    print(message)
    sys.stdout.flush()

def print_banner():
    """Prints the ASCII art banner."""
    banner = r"""
  _   _           _       _  _____   _____       _            _             
 | \ | |         | |     | |/ ____| |  __ \     | |          | |            
 |  \| | _____  _| |_    | | (___   | |  | | ___| |_ ___  ___| |_ ___  _ __ 
 | . ` |/ _ \ \/ / __|   | |\___ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | |\  |  __/>  <| || |__| |____) | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_| \_|\___/_/\_\\__\____/|_____/  |_____/ \___|\__\___|\___|\__\___/|_|   
                                                                                                                                                                                                             
    """
    print(banner)
    print("Next.js Detector by n1t3d0gsec\n")

def is_vulnerable_version(version: str) -> bool:
    """Check if detected version is in the vulnerable range"""
    if not version:
        return False
    
    try:
        major, minor, patch = map(int, version.split('.'))
        
        if major == 15 and minor == 2 and patch < 3:
            return True
        if major == 15 and minor < 2:
            return True
        if major == 14 and minor == 2 and patch < 25:
            return True
        if major == 14 and minor < 2:
            return True
        if major == 13 and minor == 5 and patch < 9:
            return True
        if major == 13 and minor < 5:
            return True
            
        return False
    except:
        return False

def check_nextjs(url: str) -> dict:
    """Check if a website is using Next.js and determine its version"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    results = {
        'is_nextjs': False,
        'version': None,
        'vulnerable': False,
        'indicators': []
    }

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        indicators = []

        next_scripts = soup.find_all('script', src=re.compile(r'/_next/static/'))
        if next_scripts:
            indicators.append("Found Next.js script paths (/_next/static/)")

        build_id = soup.find('script', id='__NEXT_DATA__')
        if build_id:
            indicators.append("Found Next.js build data (__NEXT_DATA__)")

        next_meta = soup.find('meta', {'name': 'next-head-count'})
        if next_meta:
            indicators.append("Found Next.js meta tag (next-head-count)")

        chunk_response = requests.get(urljoin(url, '/_next/static/chunks/main.js'), timeout=5)
        if chunk_response.status_code == 200:
            indicators.append("Found Next.js chunks (main.js)")
            version_match = re.search(r'(?:next/dist/compiled/react|next@)[\'"]\s*:\s*[\'"]([0-9]+\.[0-9]+\.[0-9]+)', chunk_response.text)
            if version_match:
                results['version'] = version_match.group(1)

        results['indicators'] = indicators
        results['is_nextjs'] = len(indicators) > 0
        
        if results['version']:
            results['vulnerable'] = is_vulnerable_version(results['version'])

    except Exception as e:
        results['error'] = str(e)

    return results

def save_results(results_list: list, output_file: str):
    """Save results to a CSV file if an output file is specified"""
    if output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_file}_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'is_nextjs', 'version', 'vulnerable', 'indicators', 'error'])
            writer.writeheader()
            writer.writerows(results_list)
        
        log(f"\n[+] Results saved to {filename}")

def main():
    print_banner() 
    parser = argparse.ArgumentParser(description='Check websites for Next.js and version vulnerabilities')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to check')
    group.add_argument('-l', '--list', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file name (will append timestamp and .csv)')
    args = parser.parse_args()

    urls_to_check = []
    if args.url:
        urls_to_check.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls_to_check.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            log(f"[!] Error: File {args.list} not found")
            sys.exit(1)

    log(f"[*] Starting scan of {len(urls_to_check)} URLs...")
    all_results = []
    nextjs_urls = []

    for url in urls_to_check:
        log(f"\n[*] Checking {url} for Next.js...")
        results = check_nextjs(url)
        scan_result = {
            'url': url,
            'is_nextjs': results.get('is_nextjs', False),
            'version': results.get('version', None),
            'vulnerable': results.get('vulnerable', False),
            'indicators': ', '.join(results.get('indicators', [])),
            'error': results.get('error', None)
        }
        all_results.append(scan_result)

        # Collect URLs using Next.js
        if results.get('is_nextjs', False):
            nextjs_urls.append(url)

        # Print results for current URL
        if 'error' in results:
            log(f"[!] Error: {results['error']}")
            continue

        log(f"Is Next.js: {'Yes' if results['is_nextjs'] else 'No'}")
        if results['indicators']:
            log("\nIndicators found:")
            for indicator in results['indicators']:
                log(f"- {indicator}")
        
        if results['version']:
            log(f"\nDetected version: {results['version']}")
            log(f"Vulnerable: {'Yes' if results['vulnerable'] else 'No'}")
            
            if results['vulnerable']:
                log("\n[!] This version is vulnerable to CVE-2025-29927")
                log("Affected versions:")
                log("- Next.js 15.x < 15.2.3")
                log("- Next.js 14.x < 14.2.25")
                log("- Next.js 13.x < 13.5.9")
        else:
            log("\nCould not determine Next.js version")

    # Save results to CSV if output file is specified
    save_results(all_results, args.output)

    # Print summary
    vulnerable_count = sum(1 for r in all_results if r['vulnerable'])
    nextjs_count = sum(1 for r in all_results if r['is_nextjs'])
    log(f"\n[*] Scan Summary:")
    log(f"Total URLs scanned: {len(urls_to_check)}")
    log(f"Next.js detected: {nextjs_count}")
    log(f"Vulnerable versions found: {vulnerable_count}")

    # Print list of URLs using Next.js
    if nextjs_urls:
        log("\nList of URLs using Next.js:")
        for url in nextjs_urls:
            log(f"- {url}")

if __name__ == "__main__":
    main()
