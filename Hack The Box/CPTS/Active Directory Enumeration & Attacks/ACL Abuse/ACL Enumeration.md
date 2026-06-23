

# Enumerating ACLs with PowerView and BloodHound

Let's explore how to enumerate ACLs using PowerView and visualize attack paths with BloodHound. We will then review scenarios and attacks leveraging ACEs to gain further access within an Active Directory environment.

---

## Enumerating ACLs with PowerView

Using PowerView to enumerate ACLs directly can generate a massive amount of data, making it impractical during time-constrained assessments. For example, running `Find-InterestingDomainAcl` produces extensive results:

```powershell
PS C:\htb> Find-InterestingDomainAcl


This outputs numerous objects with detailed ACEs, which can be overwhelming to analyze quickly.

### Targeted Enumeration Example

Instead, focus on a specific user you control, such as `wley`. First, obtain their SID:

```powershell
powershell

PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

Then, search for all objects that this user has rights over:

```powershell
powershell

PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

This command may take 1-2 minutes in large environments but yields targeted results.

### Understanding the Results

The output shows the object, rights, and ACE details. For example:

```plaintext
plaintext

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
```

You can reverse search the GUID (`00299570-246d-11d0-a768-00aa006e0529`) to find its meaning:

```powershell
powershell

PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,rightsGuid | ? {$_.rightsGuid -eq $guid}
```

This reveals the right is **Reset Password**.

### Using ResolveGUIDs for Readability

To avoid GUID lookups, use the `-ResolveGUIDs` flag:

```powershell
powershell

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

This displays human-readable rights like **User-Force-Change-Password** instead of GUIDs.

---

## Further Enumeration of Rights

Check what rights the `damundsen` user has over other objects:

```powershell
powershell

PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Suppose `damundsen` has **GenericWrite** over a group; this means they can add themselves or others to that group, potentially escalating privileges.

### Example: Group Nesting

Check if the group is nested:

```powershell
powershell

PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

If nested into a higher privilege group like **Information Technology**, adding yourself to the lower group grants access to the higher group's rights.

---

## Visualizing with BloodHound

After collecting data with PowerView or SharpHound, upload it to BloodHound for visualization.

### Viewing Outbound Control Rights

- Set `wley` as the starting node.
- Check **Outbound Control Rights** to see objects directly controlled or accessible via group membership.
- The **First Degree Object Control** shows objects like `ForceChangePassword` over `damundsen`.

### Attack Path Exploration

- Right-click on edges to view help, attack methods, and operational considerations.
- Use pre-built queries to confirm rights, e.g., **DCSync** rights over a user like `adunn`.

---