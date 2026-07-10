

# Using DNS for Web Reconnaissance

## Overview

DNS (Domain Name System) is a fundamental part of internet infrastructure, translating domain names into IP addresses. During reconnaissance, DNS queries can reveal valuable information about target infrastructure, subdomains, and configurations.

---

## Key DNS Tools

| Tool | Key Features | Use Cases |
| --- | --- | --- |
| **dig** | Versatile, supports various query types (A, MX, NS, TXT, etc.), detailed output | Manual DNS lookups, zone transfers, troubleshooting, record analysis |
| **nslookup** | Simpler, supports basic queries | Quick checks of domain resolution, mail servers |
| **host** | Concise output | Quick DNS record checks |
| **dnsenum** | Automated enumeration, subdomain discovery, zone transfers | Discovering subdomains, DNS info gathering |
| **fierce** | Recursive search, wildcard detection | Subdomain enumeration, identifying targets |
| **dnsrecon** | Multiple techniques, various output formats | Comprehensive DNS enumeration |
| **theHarvester** | OSINT, gathers email addresses, employee info | Gathering domain-related info from multiple sources |

---

## The `dig` Command

`dig` (Domain Information Groper) is a powerful DNS query tool, highly customizable for various record types.

### Common `dig` Commands

| Command | Description |
| --- | --- |
| `dig domain.com` | Default A record lookup |
| `dig domain.com A` | IPv4 address (A record) |
| `dig domain.com AAAA` | IPv6 address (AAAA record) |
| `dig domain.com MX` | Mail servers (MX records) |
| `dig domain.com NS` | Name servers (NS records) |
| `dig domain.com TXT` | TXT records |
| `dig domain.com CNAME` | Canonical name (CNAME) record |
| `dig domain.com SOA` | Start of authority (SOA) record |
| `dig @server domain.com` | Query specific DNS server |
| `dig +trace domain.com` | Show full DNS resolution path |
| `dig -x IP` | Reverse DNS lookup |
| `dig +short domain.com` | Concise answer only |
| `dig +noall +answer domain.com` | Show only answer section |
| `dig domain.com ANY` | Retrieve all records (may be blocked) |

> **Note:** Be cautious with `ANY` queries; many DNS servers limit or block them to prevent abuse.

---

## Practical DNS Reconnaissance

### Example: Basic DNS Query

```bash
LeDaav@htb[/htb]$ dig google.com


**Output Breakdown:**

- **Header:** Indicates query type, status, and flags.
- **Question:** The queried domain.
- **Answer:** The resolved IP address (`142.251.47.142`).
- **Footer:** Query time, server info, timestamp, message size.

### Example: Short Answer Query

```bash
bash

LeDaav@htb[/htb]$ dig +short hackthebox.com
```

**Output:**

```plaintext
104.18.20.126
104.18.21.126
```

This provides a quick way to get IP addresses without extra details.

---

## Additional DNS Recon Techniques

- **Zone transfers:** If misconfigured, can reveal entire DNS zone data.
- **Subdomain enumeration:** Using tools like `dnsenum`, `fierce`, or `dnsrecon`.
- **Wildcard detection:** Identifying if DNS records use wildcards to hide subdomains.
- **Reverse DNS:** Mapping IPs back to hostnames.

---

## Summary

DNS reconnaissance is a vital part of web and network security assessments. Properly configured DNS servers can leak information, while misconfigurations can be exploited for further attacks. Use tools like `dig`, `dnsrecon`, and `theHarvester` to gather intelligence, always respecting legal and ethical boundaries.