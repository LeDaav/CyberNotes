
# Access Control List (ACL) Overview

In an Active Directory (AD) environment, not all users and computers have access to all objects and files. Permissions are controlled through Access Control Lists (ACLs). A slight misconfiguration of an ACL can lead to permission leaks, posing a serious security threat to the domain.

---

## ACL Overview

In their simplest form, ACLs are lists that define:
- Who has access to which asset/resource
- The level of access granted

The settings within an ACL are called **Access Control Entries (ACEs)**. Each ACE maps to a user, group, or process (security principal) and specifies the rights granted to that principal. Every object has an ACL, which can contain multiple ACEs, allowing multiple principals to access the object. ACLs can also be used for auditing access within AD.

### Types of ACLs

- **Discretionary Access Control List (DACL):** Defines which security principals are granted or denied access to an object. Made up of ACEs that either allow or deny access.  
  - If no DACL exists, all access is granted.  
  - If a DACL exists but has no ACEs, access is denied to everyone.

- **System Access Control List (SACL):** Used to log access attempts to secured objects, enabling auditing.

---

## Viewing ACLs

### User Account Example

The ACL for a user account (e.g., `forend`) can be viewed in Active Directory Users and Computers (ADUC). The permissions are shown as ACE entries, such as Full Control or Change Password, granted to various users or groups.

### Viewing Permissions in ADUC

- The **Permissions** tab shows the ACL (DACL).
- The **Auditing** tab shows the SACL.

---

## Access Control Entries (ACEs)

An ACE contains four main components:

| Component | Description |
| --- | --- |
| SID | Security Identifier of the user/group/principal |
| ACE Type | Denotes whether access is allowed, denied, or audited |
| Inheritance Flags | Whether the ACE applies to child objects |
| Access Mask | 32-bit value defining specific rights granted |

### Types of ACEs

| Type | Description |
| --- | --- |
| Access Denied ACE | Explicitly denies access to a user or group |
| Access Allowed ACE | Explicitly grants access to a user or group |
| System Audit ACE | Records access attempts in logs |

---

## Why Are ACEs Important?

Attackers leverage ACE entries to gain access or establish persistence. These permissions often go unnoticed because they are not detected by vulnerability scans and can remain unchecked for years, especially in large environments.

### Commonly Abused Permissions

- **ForceChangePassword:** Reset a user’s password without knowing it.
- **Add-DomainGroupMember:** Add users to groups.
- **GenericAll:** Full control over an object.
- **GenericWrite:** Write to non-protected attributes, e.g., assign SPNs or modify group membership.
- **WriteOwner:** Change ownership of objects.
- **WriteDACL:** Modify ACLs.
- **AllExtendedRights:** Various high-privilege rights.
- **AddSelf:** Add oneself to groups.

---

## ACL Attacks in the Wild

ACL abuse can be used for:
- Lateral movement
- Privilege escalation
- Persistence

### Common Attack Scenarios

| Attack | Description |
| --- | --- |
| Abusing forgot password permissions | Resetting passwords of privileged accounts via help desk permissions. |
| Abusing group membership management | Adding controlled accounts to privileged groups. |
| Excessive user rights | Exploiting unintended rights granted to users, computers, or groups. |

**Note:** Some ACL attacks are destructive, such as changing passwords or modifying objects. Always seek client approval before performing such actions and document all changes thoroughly, reverting any modifications afterward.

---

## Summary

ACL misconfigurations are a silent threat in Active Directory environments. Penetration testers and attackers alike can abuse permissions to escalate privileges, move laterally, or maintain persistence. Proper enumeration, monitoring, and management of ACLs are essential for maintaining a secure AD environment.
