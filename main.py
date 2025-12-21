
import sys
import socket
import threading

if len(sys.argv) != 3:
    print("Usage: python main.py <domain> <wordlist>")
    sys.exit(1)

domain = sys.argv[1]
wordlist = sys.argv[2]

print_lock = threading.Lock()

def check_subdomain(subdomain):
    try:
        full_domain = f"{subdomain}.{domain}"
        socket.gethostbyname(full_domain)
        with print_lock:
            print(f"[+] Found: {full_domain}")
    except socket.gaierror:
        pass

threads = []

with open(wordlist, "r") as file:
    for line in file:
        sub = line.strip()
        t = threading.Thread(target=check_subdomain, args=(sub,))
        t.start()
        threads.append(t)

for t in threads:
    t.join()
