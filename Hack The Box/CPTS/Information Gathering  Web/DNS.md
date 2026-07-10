# Domain Name System (DNS)

The **Domain Name System (DNS)** acts as the Internet's GPS, translating human-friendly domain names into the IP addresses that computers use to communicate.

Instead of remembering numerical IP addresses such as:

```text
192.0.2.1
```

users can simply type:

```text
www.example.com
```

DNS performs the translation behind the scenes, allowing browsers to locate the correct web server.

Without DNS, navigating the Internet would require memorizing the IP address of every website.

---

# How DNS Works

Suppose you want to visit:

```text
www.example.com
```

Although you type a domain name, computers communicate using IP addresses.

DNS performs the translation through several steps.

## 1. Local Cache Lookup

Your computer first checks its local DNS cache.

If the IP address is already cached from a previous visit, the lookup ends immediately.

Otherwise, it sends a **DNS query** to a **recursive DNS resolver** (usually operated by your ISP or a public DNS provider like Google or Cloudflare).

---

## 2. Recursive Resolver

The recursive resolver also checks its own cache.

If it doesn't already know the answer, it begins traversing the DNS hierarchy.

---

## 3. Root Name Server

The resolver contacts a **Root Name Server**.

The root server does **not** know the IP address of the requested domain.

Instead, it tells the resolver which **Top-Level Domain (TLD)** server to ask.

Example:

```text
www.example.com
               ↑
              .com
```

The root server returns the address of the `.com` TLD server.

---

## 4. TLD Name Server

The **Top-Level Domain (TLD)** server manages domains ending in:

- `.com`
- `.org`
- `.net`
- `.io`
- etc.

It does not know the website's IP address either.

Instead, it tells the resolver which **Authoritative Name Server** is responsible for the requested domain.

Example:

```text
example.com
```

↓

```text
ns1.example.com
ns2.example.com
```

---

## 5. Authoritative Name Server

The **Authoritative Name Server** stores the official DNS records for the domain.

It returns the requested record, for example:

```text
www.example.com. IN A 192.0.2.1
```

This answer is authoritative because it comes directly from the server responsible for the domain.

---

## 6. DNS Resolver Caches the Result

The recursive resolver:

- Returns the IP address to your computer.
- Stores the answer in its cache for future requests.

---

## 7. Browser Connects

Now that the browser knows the destination IP address, it can establish a connection to the web server.

```text
Browser
    │
    ▼
Recursive Resolver
    │
    ▼
Root Server
    │
    ▼
TLD Server (.com)
    │
    ▼
Authoritative Name Server
    │
    ▼
IP Address
    │
    ▼
Web Server
```

---

# The Hosts File

Before querying DNS, operating systems consult the **hosts file**, which provides local hostname-to-IP mappings.

This allows manual overrides of DNS resolution.

## Default Locations

### Windows

```text
C:\Windows\System32\drivers\etc\hosts
```

### Linux / macOS

```text
/etc/hosts
```

---

## Format

Each entry follows this format:

```text
<IP Address>    <Hostname> [Alias...]
```

Example:

```text
127.0.0.1       localhost
192.168.1.10    devserver.local
```

---

## Common Uses

### Local Development

Redirect a hostname to your local machine:

```text
127.0.0.1 myapp.local
```

---

### Testing

Force a hostname to resolve to a specific server:

```text
192.168.1.20 testserver.local
```

---

### Blocking Websites

Redirect unwanted domains to a non-routable address:

```text
0.0.0.0 unwanted-site.com
```

---

# DNS as a Relay Race

A useful analogy is a relay race.

Each DNS server passes the request closer to the final destination.

```text
Computer
    │
    ▼
Recursive Resolver
    │
    ▼
Root Server
    │
    ▼
TLD Server
    │
    ▼
Authoritative Server
    │
    ▼
IP Address
```

Once the IP address is found, the response travels back through the same chain.

---

# DNS Zones

A **DNS Zone** is a portion of the DNS namespace managed by a single administrator.

Example:

```text
example.com
```

Its subdomains:

- mail.example.com
- blog.example.com
- ftp.example.com

typically belong to the same DNS zone.

---

# Zone File

A **Zone File** is a text file stored on an authoritative DNS server.

It contains all DNS resource records for a zone.

Example:

```dns
$TTL 3600

@ IN SOA ns1.example.com. admin.example.com. (
    2024060401
    3600
    900
    604800
    86400
)

@       IN NS ns1.example.com.
@       IN NS ns2.example.com.
@       IN MX 10 mail.example.com.

www     IN A      192.0.2.1
mail    IN A      198.51.100.1
ftp     IN CNAME  www.example.com.
```

This file defines:

- Authoritative name servers
- Mail server
- Host IP addresses
- DNS aliases

---

# Key DNS Concepts

| Concept | Description | Example |
|----------|-------------|---------|
| Domain Name | Human-readable website name | `www.example.com` |
| IP Address | Numerical network identifier | `192.0.2.1` |
| DNS Resolver | Resolves domain names into IP addresses | Google DNS (`8.8.8.8`) |
| Root Name Server | Highest level in the DNS hierarchy | `a.root-servers.net` |
| TLD Name Server | Manages `.com`, `.org`, etc. | Verisign (.com) |
| Authoritative Name Server | Stores official DNS records | `ns1.example.com` |

---

# Common DNS Record Types

## A Record

Maps a hostname to an IPv4 address.

```dns
www.example.com. IN A 192.0.2.1
```

---

## AAAA Record

Maps a hostname to an IPv6 address.

```dns
www.example.com. IN AAAA 2001:db8::1
```

---

## CNAME Record

Creates an alias for another hostname.

```dns
blog.example.com. IN CNAME webserver.example.net.
```

---

## MX Record

Specifies mail servers for a domain.

```dns
example.com. IN MX 10 mail.example.com.
```

---

## NS Record

Specifies the authoritative name servers for a zone.

```dns
example.com. IN NS ns1.example.com.
```

---

## TXT Record

Stores arbitrary text.

Common uses include:

- SPF
- DKIM
- DMARC
- Domain verification

Example:

```dns
example.com. IN TXT "v=spf1 mx -all"
```

---

## SOA Record (Start of Authority)

Contains administrative information about a DNS zone.

Example:

```dns
example.com. IN SOA ns1.example.com. admin.example.com.
```

Information includes:

- Primary DNS server
- Administrator email
- Serial number
- Refresh interval
- Retry interval
- Expiration
- Default TTL

---

## SRV Record

Specifies the hostname and port of a service.

Example:

```dns
_sip._udp.example.com. IN SRV 10 5 5060 sip.example.com.
```

---

## PTR Record

Used for **Reverse DNS** lookups.

Maps an IP address back to a hostname.

```dns
1.2.0.192.in-addr.arpa. IN PTR www.example.com.
```

---

# What Does `IN` Mean?

The field:

```dns
IN
```

stands for **Internet**.

It specifies the DNS class.

Almost every modern DNS record uses the `IN` class because it applies to the Internet protocol suite (IP).

Other classes exist (such as `CH` or `HS`) but are rarely used today.

---

# Why DNS Matters for Web Reconnaissance

DNS provides valuable intelligence during penetration testing and OSINT.

## 1. Discover Assets

DNS records may reveal:

- Subdomains
- Mail servers
- VPN gateways
- Development environments
- Cloud infrastructure

Example:

```dns
dev.example.com. IN CNAME oldserver.example.net.
```

This could expose an outdated or vulnerable server.

---

## 2. Map Infrastructure

DNS helps identify:

- Hosting providers
- Load balancers
- CDN providers
- Mail infrastructure
- Internal naming conventions

Example:

```dns
loadbalancer.example.com. IN A 203.0.113.15
```

This may indicate a front-end load balancer protecting multiple servers.

---

## 3. Monitor Infrastructure Changes

Regular DNS monitoring can reveal new attack surfaces.

Examples include:

A newly created VPN:

```text
vpn.example.com
```

A staging environment:

```text
staging.example.com
```

Or a TXT record like:

```text
_1password=...
```

which suggests the organization uses **1Password**, potentially providing useful information for phishing or social engineering campaigns.

---

# Summary

DNS is much more than a system for translating domain names.

It provides valuable information about an organization's:

- Infrastructure
- Services
- Cloud providers
- Email systems
- Security configuration

For penetration testers and security analysts, DNS reconnaissance is often one of the first and most valuable steps in understanding a target's attack surface.