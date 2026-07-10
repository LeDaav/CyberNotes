
# Subdomain Bruteforcing

## Overview

Subdomain brute-force enumeration involves systematically testing a list of potential subdomain names against a target domain to discover valid subdomains. This active reconnaissance technique leverages wordlists to increase efficiency and uncover hidden or forgotten subdomains.

---

## The Process

1. **Wordlist Selection**
   - **General-Purpose:** Broad list of common subdomains (e.g., dev, mail, admin).
   - **Targeted:** Focused on specific industries, technologies, or patterns.
   - **Custom:** Created based on intelligence, keywords, or patterns relevant to the target.

2. **Iteration and Querying**
   - Append each word from the list to the main domain (e.g., `dev.example.com`).
   - Perform DNS lookups (A, AAAA, etc.) to check if the subdomain exists.

3. **Filtering and Validation**
   - Record subdomains that resolve successfully.
   - Further validate by attempting to access or interact with the subdomain.

---

## Tools for Subdomain Brute-Forcing

| Tool | Key Features | Use Cases |
| --- | --- | --- |
| **dnsenum** | DNS record enumeration, zone transfer attempts, subdomain brute-force, Google scraping, reverse lookup, WHOIS | Comprehensive DNS reconnaissance and subdomain discovery |
| **fierce** | Recursive search, wildcard detection, user-friendly interface | Subdomain enumeration, wildcard detection |
| **dnsrecon** | Multiple techniques, customizable output | Extensive DNS info gathering |
| **amass** | Integration with data sources, active subdomain discovery | Large-scale subdomain enumeration |
| **assetfinder** | Lightweight, fast subdomain finder | Quick subdomain discovery |
| **puredns** | Flexible brute-force, filtering | DNS resolution and enumeration |

---

## Example: Using `dnsenum`

Suppose we want to enumerate subdomains for `inlanefreight.com` using the SecLists top 20,000 subdomains list:

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

### Explanation:

- `--enum`: Enables enumeration mode.
- `-f`: Path to the wordlist.
- `-r`: Recursive brute-force of discovered subdomains.

### Sample Output:

```plaintext
dnsenum VERSION:1.2.6

-----   inlanefreight.com   -----

Host's addresses:
inlanefreight.com. 300 IN A 134.209.24.248

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
www.inlanefreight.com. 300 IN A 134.209.24.248
support.inlanefreight.com. 300 IN A 134.209.24.248
...
done.
```

This output shows resolved subdomains and their IP addresses, revealing potential targets or points of interest.

---

## Final Tips

- Use high-quality, relevant wordlists for better results.
- Be cautious of DNS query limits; excessive requests may trigger alerts or blockades.
- Combine brute-force with passive techniques (e.g., certificate analysis, search engines) for more comprehensive reconnaissance.
- Always operate within legal and ethical boundaries, obtaining permission before active scanning.

---

## Summary

Subdomain brute-force enumeration is a powerful technique to uncover hidden or forgotten subdomains. Proper tool selection, targeted wordlists, and cautious execution can significantly enhance your web reconnaissance efforts.