
## Overview

IMAP (Internet Message Access Protocol) allows clients to access and manage emails directly on the server, supporting folder structures and synchronization across multiple clients. Unlike POP3, IMAP maintains emails on the server until explicitly deleted, enabling online management and multiple client access.

Clients connect via port 143 (unencrypted) or port 993 (SSL/TLS). Communication is text-based, using ASCII commands, and multiple commands can be sent in succession without waiting for server responses.

## Protocol Features

- Supports hierarchical folders and multiple mailboxes.
- Synchronizes email state across clients.
- Can operate in offline mode with local copies.
- Transmits data in plain text unless encrypted via SSL/TLS.

## Common Ports

| Protocol | Ports | Notes |
| --- | --- | --- |
| IMAP | 143 | Unencrypted |
| IMAP over SSL/TLS | 993 | Encrypted |
| POP3 | 110 | Unencrypted |
| POP3 over SSL/TLS | 995 | Encrypted |

## IMAP Commands

| Command | Description |
| --- | --- |
| LOGIN username password | Authenticate user |
| LIST "" * | List all mailboxes |
| CREATE "Folder" | Create mailbox |
| DELETE "Folder" | Delete mailbox |
| RENAME "Old" "New" | Rename mailbox |
| SELECT INBOX | Select mailbox for access |
| FETCH <ID> all | Retrieve email data |
| UNSELECT | Exit mailbox |
| LOGOUT | End session |

## POP3 Commands

| Command | Description |
| --- | --- |
| USER username | Identify user |
| PASS password | Authenticate user |
| STAT | Get number of emails and total size |
| LIST | List emails with size info |
| RETR id | Retrieve email by ID |
| DELE id | Delete email by ID |
| CAPA | Show server capabilities |
| RSET | Reset session state |
| QUIT | End session |

## Security Risks & Misconfigurations

- IMAP/POP3 often run unencrypted, exposing credentials and email content.
- Misconfigured servers may allow anonymous login or debugging options (`auth_debug`, `auth_verbose`), risking data leaks.
- Self-signed certificates may be used, which can be accepted insecurely.

## Footprinting & Reconnaissance

### Using Nmap

Scan for open IMAP/POP3 ports and check for SSL/TLS:

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

Sample output indicates server info, capabilities, and certificate details.

### Using cURL

Interact with IMAP over SSL:

```bash
curl -k 'imaps://10.129.14.128' --user user:password -v
```

Observe SSL handshake, server banner, and capabilities.

Interact with POP3 over SSL:

```bash
openssl s_client -connect 10.129.14.128:pop3s
```

Check certificate details and establish a secure session.

## Exploitation & Credential Testing

If credentials are known or guessed (e.g., `robin:robin`), you can attempt login:

```bash
curl -k 'imaps://target' --user robin:robin -X 'LIST "" *'
```

Successful login allows reading emails, sending messages, or further exploitation.

## Summary

IMAP and POP3 are common email protocols with many configuration options. Proper security measures, such as enforcing SSL/TLS, disabling anonymous access, and auditing configurations, are essential to prevent unauthorized access and data leaks. During assessments, port scanning, banner grabbing, and credential testing are key steps to identify vulnerabilities.