
# Subdomain Enumeration Tool (Python + Threading)

## Overview
This project implements a fast subdomain enumeration tool using Python and multithreading.
It helps identify valid subdomains of a target domain for reconnaissance and security testing.

## Features
- Wordlist-based subdomain brute-forcing
- Multithreading for speed
- DNS resolution to verify valid subdomains
- Clean CLI output
- Beginner-friendly, well-commented code

## Technologies Used
- Python 3
- threading
- socket

## How It Works
1. Load subdomains from a wordlist
2. Spawn multiple threads
3. Each thread resolves subdomains via DNS
4. Valid subdomains are printed and stored

## Usage
```bash
python main.py example.com wordlist.txt
```

## Example
```bash
python main.py google.com subdomains.txt
```

## Disclaimer
Use only on domains you own or have permission to test.
