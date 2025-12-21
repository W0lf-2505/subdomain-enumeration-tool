
# Subdomain Enumeration Using Python and Threading

## Objective
To design and implement a Python-based tool that discovers subdomains efficiently using multithreading.

## Introduction
Subdomain enumeration is a critical step in penetration testing and security assessments.
This project demonstrates how Python threading can significantly speed up the process.

## Methodology
- DNS-based validation using socket library
- Thread-per-subdomain model
- Wordlist-driven enumeration

## Advantages
- Faster than sequential scanning
- Simple and extensible
- Lightweight, no external dependencies

## Limitations
- No rate limiting
- DNS-based only (no HTTP probing)

## Future Enhancements
- Async implementation
- HTTP status checks
- Output to file
- Rate limiting

## Conclusion
The project successfully demonstrates a practical cybersecurity reconnaissance technique using Python.
