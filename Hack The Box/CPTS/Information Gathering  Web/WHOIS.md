# WHOIS Use Cases and Analysis

## Scenario 1: Phishing Investigation

An email security gateway flags a suspicious email sent to multiple employees within a company. The email claims to be from the company's bank and urges recipients to click on a link to update their account information.

A security analyst investigates the email and begins by performing a **WHOIS lookup** on the domain linked in the email.

### WHOIS Findings

- **Registration Date:** The domain was registered just a few days ago.
- **Registrant:** The registrant's information is hidden behind a privacy service.
- **Name Servers:** The name servers are associated with a known bulletproof hosting provider often used for malicious activities.

### Analysis

This combination of factors raises significant red flags:

- Recently registered domain
- Hidden registrant information
- Suspicious hosting infrastructure

These indicators strongly suggest a **phishing campaign**.

### Response

The analyst:

- Alerts the company's IT department.
- Blocks the malicious domain.
- Warns employees about the phishing attempt.

Further investigation into the hosting provider and associated IP addresses may uncover additional phishing domains or infrastructure used by the threat actor.

---

## Scenario 2: Malware Analysis

A security researcher is analyzing a new strain of malware that has infected several systems within a network.

The malware communicates with a **Command-and-Control (C2)** server to receive commands and exfiltrate stolen data.

To gain insights into the attacker's infrastructure, the researcher performs a WHOIS lookup on the C2 domain.

### WHOIS Findings

- **Registrant:** Registered using a free anonymous email service.
- **Location:** Registrant address is located in a country with a high prevalence of cybercrime.
- **Registrar:** Registered through a registrar with a history of weak abuse enforcement.

### Analysis

Based on these findings, the researcher concludes that the C2 server is likely hosted on a compromised or **bulletproof hosting** provider.

### Response

The researcher:

- Identifies the hosting provider.
- Reports the malicious infrastructure.
- Assists with infrastructure takedown efforts.

---

## Scenario 3: Threat Intelligence Report

A cybersecurity firm tracks a sophisticated threat actor targeting financial institutions.

Analysts collect WHOIS data from domains used in previous campaigns to build a comprehensive threat intelligence report.

### WHOIS Patterns Identified

#### Registration Dates

- Domains are registered in clusters.
- Registrations often occur shortly before major attacks.

#### Registrants

- Multiple aliases are used.
- Fake identities are common.

#### Name Servers

- Many domains share identical name servers.
- Indicates a common infrastructure.

#### Takedown History

- Numerous domains have already been taken down.
- Suggests previous law enforcement or security interventions.

### Outcome

These observations allow analysts to build a profile of the threat actor's:

- Tactics
- Techniques
- Procedures (TTPs)

The report also includes **Indicators of Compromise (IOCs)** derived from WHOIS data, allowing other organizations to detect and block future attacks.

---

# Using WHOIS

Before using the `whois` command, ensure it is installed on your Linux system.

## Installation

```bash
sudo apt update
sudo apt install whois -y
```

---

## Basic Usage

The simplest way to retrieve WHOIS information is:

```bash
whois facebook.com
```

Example output:

```text
Domain Name: FACEBOOK.COM
Registry Domain ID: 2320948_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrarsafe.com
Registrar URL: http://www.registrarsafe.com
Updated Date: 2024-04-24T19:06:12Z
Creation Date: 1997-03-29T05:00:00Z
Registry Expiry Date: 2033-03-30T04:00:00Z
Registrar: RegistrarSafe, LLC
Registrar IANA ID: 3237
Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
Registrar Abuse Contact Phone: +1-650-308-7004

Domain Status:
- clientDeleteProhibited
- clientTransferProhibited
- clientUpdateProhibited
- serverDeleteProhibited
- serverTransferProhibited
- serverUpdateProhibited

Name Server: A.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: C.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM

DNSSEC: unsigned

Registrant Name: Domain Admin
Registrant Organization: Meta Platforms, Inc.
```

---

# Interpreting WHOIS Output

## Domain Registration

| Field | Value |
|--------|-------|
| Registrar | RegistrarSafe, LLC |
| Creation Date | 1997-03-29 |
| Expiry Date | 2033-03-30 |

### Analysis

These details indicate:

- The domain has existed for many years.
- It is registered through a reputable registrar.
- The long expiration date suggests a stable and legitimate online presence.

---

## Domain Owner

| Field | Value |
|--------|-------|
| Organization | Meta Platforms, Inc. |
| Contact | Domain Admin |

### Analysis

This confirms that:

- **Meta Platforms, Inc.** owns the domain.
- **Domain Admin** serves as the administrative contact.

This matches expectations for the official Facebook domain.

---

## Domain Status

```
clientDeleteProhibited
clientTransferProhibited
clientUpdateProhibited
serverDeleteProhibited
serverTransferProhibited
serverUpdateProhibited
```

### Analysis

These protections prevent:

- Unauthorized deletion
- Unauthorized transfers
- Unauthorized modifications

The protections exist at both the registrar (**client**) and registry (**server**) levels, indicating strong domain security.

---

## Name Servers

```
A.NS.FACEBOOK.COM
B.NS.FACEBOOK.COM
C.NS.FACEBOOK.COM
D.NS.FACEBOOK.COM
```

### Analysis

The name servers belong to the `facebook.com` domain itself, indicating that **Meta Platforms, Inc.** manages its own DNS infrastructure.

Large organizations commonly operate their own DNS infrastructure to improve:

- Reliability
- Performance
- Security
- Operational control

---

# Key Takeaways

WHOIS records can provide valuable reconnaissance information, including:

- Domain registration dates
- Ownership information
- Registrar details
- Domain status
- Name servers
- Administrative contacts

## Security Applications

WHOIS data can help identify:

- Recently registered phishing domains
- Malicious infrastructure
- Shared attacker infrastructure
- Threat actor patterns
- Indicators of Compromise (IOCs)

## Limitations

WHOIS data alone is rarely sufficient.

Although WHOIS records provide ownership and registration details, they generally **do not reveal individual employees, internal systems, or specific vulnerabilities**.

For effective reconnaissance or threat intelligence, WHOIS should be combined with other OSINT and reconnaissance techniques to build a more complete understanding of a target's digital footprint.