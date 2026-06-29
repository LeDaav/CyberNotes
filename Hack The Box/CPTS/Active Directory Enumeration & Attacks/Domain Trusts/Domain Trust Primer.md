
# Domain Trusts Primer

## Scenario

Many large organizations acquire new companies over time and establish trust relationships with their domains. These trusts facilitate seamless access to resources across domains but can also introduce security risks if misconfigured. A trust with a vulnerable or exploitable domain can serve as a quick route into the target environment. Trusts can also connect organizations with MSPs, clients, or other business units, potentially creating attack paths.

---

## Domain Trusts Overview

A trust links the authentication systems of two domains or forests, allowing users to access resources or perform admin tasks across domain boundaries. Trusts can be:

- **Parent-Child:** Within the same forest; child trusts parent and vice versa (two-way, transitive).
- **Cross-Link:** Between sibling domains to speed up authentication.
- **External:** Non-transitive trust between separate forests; SID filtering may be used.
- **Tree-Root:** Between a forest root and a new tree root.
- **Forest:** Transitive trust between two forest root domains.
- **ESAE:** A bastion forest for managing AD.

### Trust Characteristics

- **Transitive:** Trust extends to trusted objects' trusted objects (e.g., A trusts B, B trusts C, so A trusts C).
- **Non-Transitive:** Trust is limited to the specific pair of domains.
- **One-Way:** Users in the trusted domain can access resources in the trusting domain, but not vice versa.
- **Bidirectional:** Trust is mutual; users from both domains can access resources.

---

## Visual Analogy

- **Transitive Trust:** Like extending permission to everyone in your household to accept packages on your behalf.
- **Non-Transitive Trust:** Like only you and the delivery service can handle the package, with no extension to others.

---

## Enumerating Trust Relationships

### Using PowerShell (`Get-ADTrust`)

```powershell
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-ADTrust -Filter *
```


Sample output:

```plaintext
Direction               : BiDirectional
DisallowTransivity      : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType               : Uplevel
TrustAttributes         : 32
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType               : Uplevel
TrustDirection          : Bidirectional
```

This shows two trusts: one with `LOGISTICS.INLANEFREIGHT.LOCAL` (intra-forest) and another with `FREIGHTLOGISTICS.LOCAL` (forest trust).

### Using PowerView (`Get-DomainTrust`)

```powershell
powershell

PS C:\htb> Get-DomainTrust
```

Sample output:

```plaintext
plaintext

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
```

### Using `Get-DomainTrustMapping`

```powershell
powershell

PS C:\htb> Get-DomainTrustMapping
```

Same trust info, with additional details.

---

## Additional Enumeration

### Listing Users in a Trusted Domain

```powershell
powershell

PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | Select-Object SamAccountName
```

Sample output:

```plaintext
samaccountname
--------------
htb-student_adm
Administrator
Guest
lab_adm
krbtgt
```

### Using `netdom` to Query Trusts

```cmd
cmd

C:\htb> netdom query /domain:inlanefreight.local trust
```

Output:

```plaintext
<->       LOGISTICS.INLANEFREIGHT.LOCAL
<->       FREIGHTLOGISTICS.LOCAL
```

### Querying Domain Controllers and Workstations

```cmd
C:\htb> netdom query /domain:inlanefreight.local dc
C:\htb> netdom query /domain:inlanefreight.local workstation
```

---

## Visualizing Trusts with BloodHound

- Use the **Map Domain Trusts** pre-built query.
- Visualize trust relationships, trust direction, and type.
- Identify potential attack paths across trusts.

---

## Moving Forward

Understanding trust relationships is crucial for assessing lateral movement and privilege escalation opportunities. Trusts, especially transitive and bidirectional ones, can be exploited if misconfigured. Always verify scope with the client before performing trust-related enumeration or attacks.

**Note:** Trust relationships often go unnoticed and can be a significant attack vector if not properly managed or monitored.