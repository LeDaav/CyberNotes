

In the previous section, we explored some tools we can use from our Linux attack host for enumeration with valid domain credentials. In this section, we will experiment with a few tools for enumerating from a Windows attack host, such as **SharpHound/BloodHound**, **PowerView/SharpView**, **Grouper2**, **Snaffler**, and some built-in tools useful for AD enumeration.

Some of the data we gather in this phase may provide more information for reporting, not just directly lead to attack paths. Depending on the assessment type, our client may be interested in all possible findings, so even issues like the ability to run BloodHound freely or certain user account attributes may be worth including in our report as either medium-risk findings or a separate appendix section. Not every issue we uncover has to be geared towards forwarding our attacks. Some of the results may be informational in nature but useful to the customer to help improve their security posture.

At this point, we are interested in other misconfigurations and permission issues that could lead to lateral and vertical movement. We are also interested in getting a bigger picture of how the domain is set up, i.e., do any trusts exist with other domains both inside and outside the current forest? We're also interested in pillaging file shares that our user has access to, as these often contain sensitive data such as credentials that can be used to further our access.

---

## TTPs

The first tool we will explore is the **ActiveDirectory PowerShell module**. When landing on a Windows host in the domain, especially one an admin uses, there is a chance you will find valuable tools and scripts on the host.

---

### ActiveDirectory PowerShell Module

The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment from the command line. It consists of 147 different cmdlets at the time of writing. We can't cover them all here, but we will look at a few that are particularly useful for enumerating AD environments.

Before we can utilize the module, we have to make sure it is imported first. The `Get-Module` cmdlet will list all available modules, their version, and potential commands for use. If the module is not loaded, run `Import-Module ActiveDirectory` to load it for use.

#### Discover Modules

```powershell
powershell

PS C:\htb> Get-Module
```

#### Load ActiveDirectory Module

```powershell
powershell

PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```

---

### Get Domain Info

```powershell
powershell

PS C:\htb> Get-ADDomain
```

This will print out helpful information like the domain SID, domain functional level, any child domains, and more.

---

### Get-ADUser (Kerberoasting Candidates)

```powershell
powershell

PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

This gets a listing of accounts that may be susceptible to a Kerberoasting attack.

---

### Checking For Trust Relationships

```powershell
powershell

PS C:\htb> Get-ADTrust -Filter *
```

This cmdlet will print out any trust relationships the domain has.

---

### Group Enumeration

```powershell
powershell

PS C:\htb> Get-ADGroup -Filter * | select name
```

---

### Detailed Group Info

```powershell
powershell

PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```

---

### Group Membership

```powershell
powershell

PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```

---

## PowerView

PowerView is a tool written in PowerShell to help us gain situational awareness within an AD environment. It provides a way to identify where users are logged in, enumerate domain information such as users, computers, groups, ACLs, trusts, hunt for file shares and passwords, perform Kerberoasting, and more.

Below is a table of some of the most useful functions PowerView offers:

|Command|Description|
|---|---|
|Export-PowerViewCSV|Append results to a CSV file|
|ConvertTo-SID|Convert a User or group name to its SID value|
|Get-DomainSPNTicket|Requests the Kerberos ticket for a specified SPN account|
|Get-Domain|Return the AD object for the current (or specified) domain|
|Get-DomainController|Return a list of the Domain Controllers for the specified domain|
|Get-DomainUser|Return all users or specific user objects in AD|
|Get-DomainComputer|Return all computers or specific computer objects in AD|
|Get-DomainGroup|Return all groups or specific group objects in AD|
|Get-DomainOU|Search for all or specific OU objects in AD|
|Find-InterestingDomainAcl|Finds object ACLs in the domain with modification rights|
|Get-DomainGroupMember|Return the members of a specific domain group|
|Get-DomainFileServer|Returns a list of servers likely functioning as file servers|
|Get-DomainDFSShare|Returns a list of all distributed file systems for the domain|
|Get-DomainGPO|Return all GPOs or specific GPO objects in AD|
|Get-DomainPolicy|Returns the default domain policy or the domain controller policy|
|Get-NetLocalGroup|Enumerates local groups on the local or a remote machine|
|Get-NetLocalGroupMember|Enumerates members of a specific local group|
|Get-NetShare|Returns open shares on the local (or a remote) machine|
|Get-NetSession|Will return session information for the local (or a remote) machine|
|Test-AdminAccess|Tests if the current user has admin access to a machine|
|Find-DomainUserLocation|Finds machines where specific users are logged in|
|Find-DomainShare|Finds reachable shares on domain machines|
|Find-InterestingDomainShareFile|Searches for files matching specific criteria on readable shares|
|Find-LocalAdminAccess|Find machines where the current user has local admin access|
|Get-DomainTrust|Returns domain trusts for the current domain or a specified domain|
|Get-ForestTrust|Returns all forest trusts for the current forest or a specified one|
|Get-DomainForeignUser|Enumerates users in groups outside of the user's domain|
|Get-DomainForeignGroupMember|Enumerates groups with users outside of the group's domain|
|Get-DomainTrustMapping|Enumerate all trusts for the current domain and any others seen|

---

### Domain User Information

```powershell
powershell

PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

---

### Recursive Group Membership

```powershell
powershell

PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

---

### Trust Enumeration

```powershell
powershell

PS C:\htb> Get-DomainTrustMapping
```

---

### Testing for Local Admin Access

```powershell
powershell

PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

---

### Finding Users With SPN Set

```powershell
powershell

PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

---

## SharpView

SharpView is a .NET port of PowerView. Many of the same functions supported by PowerView can be used with SharpView.

#### Example: Enumerate User

```powershell
powershell

PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
```

---

## Shares

Shares allow users on a domain to quickly access information relevant to their daily roles and share content with their organization. Overly permissive shares can potentially cause accidental disclosure of sensitive information. We can use PowerView to hunt for shares and then help us dig through them or use various manual commands to hunt for common strings such as files with "pass" in the name.

---

## Snaffler

Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment.

#### Snaffler Execution

```bash
bash

Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

#### Snaffler in Action

```powershell
powershell

PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```

---

## BloodHound

Bloodhound is an exceptional open-source tool that can identify attack paths within an AD environment by analyzing the relationships between objects.

#### SharpHound in Action

```powershell
powershell

PS C:\htb>  .\SharpHound.exe --help
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

After running SharpHound, upload the generated zip file to the BloodHound GUI for analysis.

---

## Analysis and Reporting

- Use the **Analysis** tab in BloodHound to run pre-built queries (e.g., "Find Computers with Unsupported Operating Systems", "Find Computers where Domain Users are Local Admin").
- Document every file transferred to and from hosts in the domain and where they were placed on disk.
- Ensure you cover your tracks and clean up anything you put in the environment at the conclusion of the engagement.

---

## Next Steps

If you are restricted with the shell you have or do not have the ability to import tools, you may need to perform actions while "Living Off The Land." This will be covered in the next section.