# Virtual Hosts (VHosts)

---

Once DNS directs traffic to the correct server, the **web server configuration** determines how incoming requests are handled.

Web servers such as **Apache**, **Nginx**, or **IIS** can host multiple websites or applications on a single server using **Virtual Hosting**. This mechanism allows the server to distinguish between different domains, subdomains, or websites sharing the same IP address.

---

# How Virtual Hosts Work

Virtual hosting relies on the **HTTP `Host` header**, which is included in every HTTP request sent by a browser.

The `Host` header tells the web server which website the client is trying to access.

---

## VHosts vs. Subdomains

Although often confused, **Virtual Hosts** and **subdomains** are different concepts.

### Subdomains

A subdomain is an extension of a parent domain.

Example:

```text
blog.example.com
```

where:

```text
example.com
```

is the parent domain.

Characteristics:

- Have their own DNS records.
- May point to the same or a different IP address.
- Often used to organize different services or sections of a website.

---

### Virtual Hosts (VHosts)

Virtual Hosts are **web server configurations** that allow multiple websites to be served from the same server.

A VHost may correspond to:

- A top-level domain

```text
example.com
```

- A subdomain

```text
dev.example.com
```

Each Virtual Host has its own configuration, allowing different:

- Document roots
- SSL certificates
- Redirect rules
- Security policies

---

## VHosts Without DNS Records

A Virtual Host does **not** necessarily require a DNS record.

If no public DNS entry exists, the VHost can still be accessed by manually mapping the hostname inside the local **hosts** file.

Example:

```text
/etc/hosts
```

or

```text
C:\Windows\System32\drivers\etc\hosts
```

Example:

```text
192.168.1.20    dev.example.com
```

This bypasses DNS resolution entirely.

---

## Why Discover Virtual Hosts?

Many organizations host internal or hidden applications using non-public virtual hosts.

Examples include:

- dev.example.com
- admin.example.com
- test.example.com
- portal.example.com

These hostnames may **not appear in DNS records**, making **VHost fuzzing** an effective reconnaissance technique.

---

# Apache Virtual Host Example

```apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

Although all three websites share the same server, Apache selects the correct website using the **Host** header.

---

# Server VHost Lookup Process

The following sequence occurs whenever a browser requests a website.

## 1. Browser Sends a Request

The user visits:

```text
www.inlanefreight.com
```

The browser sends an HTTP request to the server's IP address.

---

## 2. Host Header is Included

Example:

```http
GET / HTTP/1.1
Host: www.inlanefreight.com
```

The `Host` header identifies the requested website.

---

## 3. Web Server Searches for a Matching VHost

The web server compares the Host header against its Virtual Host configuration.

For example:

```
Host: dev.example.com
```

↓

Search VHost configuration

↓

```
ServerName dev.example.com
```

---

## 4. Correct Website is Served

Once a matching Virtual Host is found, the server loads files from the associated **DocumentRoot**.

Example:

```
/var/www/dev
```

The corresponding HTTP response is then returned to the browser.

---

# Types of Virtual Hosting

There are three primary Virtual Hosting methods.

---

## 1. Name-Based Virtual Hosting

The most common approach.

The server distinguishes websites solely by examining the **Host** header.

### Advantages

- Only one IP address required.
- Easy to configure.
- Cost-effective.
- Supported by virtually all modern web servers.

### Disadvantages

- Relies on the Host header.
- Certain SSL/TLS scenarios may require additional configuration.

---

## 2. IP-Based Virtual Hosting

Each website is assigned a unique IP address.

The server determines the website based on the destination IP rather than the Host header.

### Advantages

- Better isolation.
- Works independently of HTTP Host headers.
- Compatible with any protocol.

### Disadvantages

- Requires multiple IP addresses.
- Higher operational cost.
- Less scalable.

---

## 3. Port-Based Virtual Hosting

Each website listens on a different TCP port.

Example:

```
Website A → Port 80
Website B → Port 8080
```

### Advantages

- Useful when IP addresses are limited.

### Disadvantages

- Users must specify the port number.
- Less common.
- Poorer user experience.

---

# Virtual Host Discovery Tools

Manual VHost discovery is possible but inefficient.

Several tools automate the process.

| Tool | Description | Features |
|------|-------------|----------|
| **Gobuster** | Multi-purpose brute-forcing tool supporting VHost discovery. | Fast, supports multiple HTTP methods and custom wordlists. |
| **Feroxbuster** | Rust-based directory and VHost discovery tool. | Recursive scanning, wildcard detection, filtering. |
| **ffuf** | Fast web fuzzer supporting Host header fuzzing. | Highly customizable with filtering and wordlists. |

---

# Gobuster

Gobuster is one of the most commonly used tools for Virtual Host discovery.

It works by repeatedly modifying the **Host** header while sending requests to the target IP address.

Responses are then analyzed to determine which hostnames exist.

---

## Requirements

Before running Gobuster, prepare:

- Target IP address
- Wordlist of potential hostnames

Common wordlists include:

```
SecLists
```

or custom company-specific wordlists.

---

# Basic Syntax

```bash
gobuster vhost -u http://<target_IP> -w <wordlist> --append-domain
```

### Parameters

| Option | Description |
|---------|-------------|
| `-u` | Target URL or IP address |
| `-w` | Wordlist |
| `--append-domain` | Appends the base domain to every word in the wordlist |

---

## Why `--append-domain`?

In **Gobuster v3+**, this option is required for VHost enumeration.

Without it:

```
admin
```

is tested.

With it:

```
admin.example.com
```

is tested.

Older Gobuster versions automatically appended the domain.

---

# Useful Options

| Option | Description |
|---------|-------------|
| `-t` | Increase the number of threads |
| `-k` | Ignore invalid SSL/TLS certificates |
| `-o` | Save results to a file |

---

# Example

```bash
gobuster vhost \
    -u http://inlanefreight.htb:81 \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    --append-domain
```

Output:

```text
===============================================================
Gobuster v3.6
===============================================================

[+] Url:             http://inlanefreight.htb:81
[+] Threads:         10
[+] Append Domain:   true

===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================

Found: forum.inlanefreight.htb:81 Status: 200 [Size: 100]

[...]

Progress: 114441 / 114442 (100%)

===============================================================
Finished
===============================================================
```

Gobuster discovered the Virtual Host:

```text
forum.inlanefreight.htb
```

which returned **HTTP Status 200**, indicating a valid Virtual Host.

---

# Operational Security (OPSEC)

Virtual Host discovery generates a large number of HTTP requests.

This activity may trigger:

- Intrusion Detection Systems (IDS)
- Web Application Firewalls (WAF)
- Security monitoring solutions

Always ensure you have proper authorization before performing VHost enumeration against any target.