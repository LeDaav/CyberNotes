
# Attacking SNMP (Simple Network Management Protocol)

## Overview

SNMP is used to monitor and manage network devices like routers, switches, servers, and IoT devices. It operates over UDP ports 161 (standard) and 162 (traps). SNMP allows querying device info, changing configurations, and receiving event notifications (traps). The latest version, SNMPv3, adds security features like authentication and encryption, but many systems still run older versions like SNMPv1 or SNMPv2c, which lack security.

---

## Protocol Details

- **Ports:** 161 (query/control), 162 (traps)
- **Communication:** Text-based commands in ASCII
- **Functionality:** Retrieve info, set device parameters, send traps
- **Security issues:** Often unencrypted, using default community strings, or misconfigured

---

## SNMP Components

### MIB (Management Information Base)

- A hierarchical database of objects (OIDs) representing device info
- Stored in text files in ASN.1 format
- Defines object identifiers, data types, access rights, and descriptions

### OID (Object Identifier)

- Unique hierarchical address for each SNMP object
- Dot-separated numbers, longer chains are more specific

---

## SNMP Versions

### SNMPv1

- Basic management and monitoring
- No authentication or encryption
- Data sent in plain text

### SNMPv2c

- Similar security flaws as v1; community strings in plain text
- Extended functions, but no encryption

### SNMPv3

- Adds authentication (username/password)
- Supports encryption (via pre-shared keys)
- More complex to configure

---

## Default Configuration & Risks

- Default community strings: e.g., `public`, `private`
- Misconfigurations can allow:
  - Unauthorized access
  - Reading sensitive info
  - Changing device settings
  - Sending false traps

### Dangerous Settings

| Setting | Description |
| --- | --- |
| `rwuser noauth` | Full access without authentication |
| `rwcommunity <string> <IP>` | Full access regardless of source |

---

## Footprinting & Reconnaissance

### Using Nmap

Scan for SNMP services and check for SSL/TLS:

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

Sample output shows open ports, service versions, and SSL certificate info.

### Using snmpwalk

Query device info with known community string:

```bash
snmpwalk -v2c -c <community> 10.129.14.128
```

This returns system info like OS, hostname, and uptime.

### Using cURL

Interact over encrypted SNMP (if supported):

```bash
curl -k 'imaps://10.129.14.128' --user user:pass
```

(For SNMP, tools like `snmpget` or `snmpwalk` are more common than curl.)

### Using onesixtyone

Brute-force community strings with wordlists:

```bash
onesixtyone -c /path/to/wordlist.txt 10.129.14.128
```

---

## Exploitation & Data Extraction

### Using snmpwalk with known community string

```bash
snmpwalk -v2c -c public 10.129.14.128
```

This can reveal device info, user data, or other sensitive info if misconfigured.

### Using braa for OID enumeration

```bash
sudo braa public@10.129.14.128:.1.3.6.*
```

This queries all OIDs under the specified subtree, revealing detailed device info.

---

## Security Implications & Best Practices

- Default community strings (`public`, `private`) are well-known.
- Unencrypted SNMP traffic can be intercepted.
- Misconfigured SNMP can leak sensitive info or allow device control.
- Use SNMPv3 with strong authentication and encryption.
- Regularly audit SNMP configurations.
- Disable SNMP if not needed.

---

## Final Recommendations

- Set up a lab environment to experiment with SNMP configurations.
- Use tools like `snmpwalk`, `onesixtyone`, and `braa` for reconnaissance.
- Always verify SNMP security settings in production environments.
- Properly restrict SNMP access and change default community strings.

**Note:** SNMP can be a powerful management tool but also a significant security risk if misconfigured or left unprotected.