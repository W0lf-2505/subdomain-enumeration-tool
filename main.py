
import sys
import socket
import threading
import argparse
import time
from queue import Queue
from typing import List, Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

print_lock = threading.Lock()

def check_wildcard(domain: str, timeout: float = 1.0) -> Optional[str]:
    """Check if domain has wildcard DNS."""
    try:
        fake_sub = f"randomstringthatshouldnotexist.{domain}"
        socket.gethostbyname_ex(fake_sub)
        return "Wildcard DNS detected - results may include false positives"
    except socket.gaierror:
        return None

def resolve_subdomain(subdomain: str, domain: str, timeout: float = 1.0, show_ip: bool = False) -> Optional[dict]:
    """Resolve a subdomain and return details."""
    try:
        full_domain = f"{subdomain}.{domain}"
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyname_ex(full_domain)
        ips = result[2]
        return {
            "subdomain": subdomain,
            "full_domain": full_domain,
            "ips": ips,
            "ip": ips[0] if ips else "No IP"
        }
    except socket.gaierror:
        return None
    except Exception as e:
        return None

def worker(domain: str, queue: Queue, results: List[dict], timeout: float, show_ip: bool, verbose: bool):
    """Worker thread for subdomain checking."""
    while not queue.empty():
        subdomain = queue.get()
        result = resolve_subdomain(subdomain, domain, timeout, show_ip)
        if result:
            with print_lock:
                if verbose:
                    ip_info = f" -> {result['ip']}" if show_ip else ""
                    print(f"[+] Found: {result['full_domain']}{ip_info}")
                results.append(result)
        queue.task_done()

def enumerate_subdomains(domain: str, wordlist: str, threads: int = 10, timeout: float = 1.0,
                        show_ip: bool = False, verbose: bool = False, output_file: Optional[str] = None) -> List[dict]:
    """Enumerate subdomains using wordlist and threading."""
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist file '{wordlist}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")
        sys.exit(1)

    # Check for wildcard
    wildcard_warning = check_wildcard(domain, timeout)
    if wildcard_warning and verbose:
        print(f"[!] {wildcard_warning}")

    queue = Queue()
    results = []

    for sub in subdomains:
        queue.put(sub)

    start_time = time.time()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(domain, queue, results, timeout, show_ip, verbose))
        t.start()
        thread_list.append(t)

    # Progress bar
    pbar = tqdm(total=len(subdomains), desc="Enumerating", unit="sub") if HAS_TQDM and verbose else None

    while any(t.is_alive() for t in thread_list):
        time.sleep(0.1)
        if pbar:
            remaining = queue.qsize()
            pbar.update(len(subdomains) - remaining - pbar.n)

    for t in thread_list:
        t.join()

    if pbar:
        pbar.close()

    elapsed = time.time() - start_time

    with print_lock:
        print(f"\n[+] Enumeration completed in {elapsed:.2f}s")
        print(f"[+] Found {len(results)} subdomains")

        if output_file:
            save_results(results, output_file, domain, wildcard_warning)

    return results

def save_results(results: List[dict], output_file: str, domain: str, wildcard_warning: Optional[str]):
    """Save results to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write(f"Subdomain enumeration results for {domain}\n")
            f.write("=" * 50 + "\n")
            if wildcard_warning:
                f.write(f"Warning: {wildcard_warning}\n\n")
            for result in results:
                f.write(f"{result['full_domain']}")
                if 'ips' in result and len(result['ips']) > 1:
                    f.write(f" -> {', '.join(result['ips'])}")
                else:
                    f.write(f" -> {result['ip']}")
                f.write("\n")
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=1.0, help="DNS resolution timeout (seconds)")
    parser.add_argument("-i", "--show-ip", action="store_true", help="Show IP addresses")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file for results")

    args = parser.parse_args()

    # Validate domain
    try:
        socket.gethostbyname(args.domain)
    except socket.gaierror:
        print(f"[-] Invalid domain: {args.domain}")
        sys.exit(1)

    if args.verbose:
        print(f"[+] Enumerating subdomains for {args.domain} using {args.threads} threads...")

    results = enumerate_subdomains(args.domain, args.wordlist, args.threads, args.timeout,
                                  args.show_ip, args.verbose, args.output)

    if not args.verbose and results:
        print("Found subdomains:")
        for result in results:
            ip_info = f" -> {result['ip']}" if args.show_ip else ""
            print(f"  {result['full_domain']}{ip_info}")

if __name__ == "__main__":
    main()
