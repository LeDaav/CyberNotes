## Unconstrained Delegation

`Unconstrained Delegation` is a privilege that can be granted to User Accounts or Computer Accounts in an Active Directory environment, allowing a service to authenticate to another resource on behalf of `any` user. This might be necessary when, for example, a web server requires access to a database server to make changes on a user's behalf.

![IIS Properties window showing delegation settings. "Trust this computer for delegation to any service (Kerberos only)" is selected. No services listed.](https://academy.hackthebox.com/storage/modules/233/image49.png)

#### Attack Steps:

- The attacker identifies systems on which Unconstrained Delegation is enabled for service accounts. ![PowerShell output showing details of a computer object with delegation enabled. Includes name, distinguished name, service principal names, and SID.](https://academy.hackthebox.com/storage/modules/233/image19.png)
- The attacker gains access to a system with Unconstrained Delegation enabled.
- The attacker extracts Ticket Granting Ticket (TGT) tickets from the memory of the compromised system using tools such as `Mimikatz`. ![Rubeus tool output showing TGT request for Administrator using RC4 hash, with successful request and base64 ticket.](https://academy.hackthebox.com/storage/modules/233/image3.png)

#### Kerberos Authentication With Unconstrained Delegation

When Unconstrained Delegation is enabled, the main difference in Kerberos Authentication is that when a user requests a TGS ticket for a remote service, the Domain Controller will embed the user's TGT into the service ticket. When connecting to the remote service, the user will present not only the TGS ticket but also their own TGT. When the service needs to authenticate to another service on behalf of the user, it will present the user's TGT ticket, which the service received with the TGS ticket.

![Diagram showing Kerberos unconstrained delegation process: client requests TGT, receives TGT, requests TGS for server, receives TGS, and presents TGS with TGT to server with unconstrained delegation.](https://academy.hackthebox.com/storage/modules/233/image51.png)

#### Unconstrained Delegation Attack Detection Opportunities

PowerShell commands and LDAP search filters used for Unconstrained Delegation discovery can be detected by monitoring PowerShell script block logging (`Event ID 4104`) and LDAP request logging.

The main goal of an Unconstrained Delegation attack is to retrieve and reuse TGT tickets, so Pass-the-Ticket detection can be used as well.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Unconstrained Delegation Attacks With Splunk

Now let's explore how we can identify Unconstrained Delegation attacks, using Splunk.

**Timeframe**: `earliest=1690544538 latest=1690544540`

  Detecting Unconstrained Delegation/Constrained Delegation Attacks

```shell-session
index=main earliest=1690544538 latest=1690544540 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" 
| table _time, ComputerName, EventCode, Message
```

![Log analysis tool showing a search query for EventCode 4104 with one event. Details include time, computer name, event code, and message about creating scriptblock text.](https://academy.hackthebox.com/storage/modules/233/20.png)

## Constrained Delegation

`Constrained Delegation` is a feature in Active Directory that allows services to delegate user credentials only to specified resources, reducing the risk associated with Unconstrained Delegation. Any user or computer accounts that have service principal names (SPNs) set in their `msDS-AllowedToDelegateTo` property can impersonate any user in the domain to those specific SPNs.

![Backup Backup Properties window showing delegation settings. "Trust this user for delegation to specified services only" is selected, with services listed: CIFS and LDAP.](https://academy.hackthebox.com/storage/modules/233/image26.png)

#### Attack Steps:

- The attacker identifies systems where Constrained Delegation is enabled and determines the resources to which they are allowed to delegate. ![PowerShell output showing Get-ADObject command for delegation. Displays details of a user object, including distinguished name, name, object class, and object GUID.](https://academy.hackthebox.com/storage/modules/233/image35.png)
- The attacker gains access to the TGT of the principal (user or computer). The TGT can be extracted from memory (Rubeus dump) or requested with the principal's hash. ![Rubeus tool output showing TGT request for user Backup in lab.internal.local using RC4 hash. Request successful with base64 ticket output.](https://academy.hackthebox.com/storage/modules/233/image64.png)
- The attacker uses the S4U technique to impersonate a high-privileged account to the targeted service (requesting a TGS ticket). ![Rubeus tool output showing S4U request for user Backup in lab.internal.local, impersonating WELDON_EVANS. Request successful with TGS obtained and base64 ticket output.](https://academy.hackthebox.com/storage/modules/233/image48.png)
- The attacker injects the requested ticket and accesses targeted services as the impersonated user. ![Command Prompt showing cached Kerberos ticket for WELDON_EVANS on CIFS service, user identity as jenny_hickman, and directory listing of dc.lab.internal.local C$ drive.](https://academy.hackthebox.com/storage/modules/233/image60.png)

#### Kerberos Protocol Extensions - Service For User

`Service for User to Self (S4U2self)` and `Service for User to Proxy (S4U2proxy)` allow a service to request a ticket from the Key Distribution Center (KDC) on behalf of a user. S4U2self allows a service to obtain a TGS for itself on behalf of a user, while S4U2proxy allows the service to obtain a TGS on behalf of a user for a second service.

S4U2self was designed to enable a user to request a TGS ticket when another method of authentication was used instead of Kerberos. Importantly, this TGS ticket can be requested on behalf of any user, for example, an Administrator.

![Diagram showing non-Kerberos authentication process: User authenticates to Service A, then Service A requests and receives a TGS ticket for Administrator from KDC.](https://academy.hackthebox.com/storage/modules/233/image29.png)

S4U2proxy was designed to take a forwardable ticket and use it to request a TGS ticket to any SPN specified in the `msds-allowedtodelegateto` options for the user specified in the S4U2self part.

With a combination of S4U2self and S4U2proxy, an attacker can impersonate any user to service principal names (SPNs) set in `msDS-AllowedToDelegateTo` properties.

#### Constrained Delegation Attack Detection Opportunities

Similar to Unconstrained Delegation, it is possible to detect PowerShell commands and LDAP requests aimed at discovering vulnerable Constrained Delegation users and computers.

To request a TGT ticket for a principal, as well as a TGS ticket using the S4U technique, Rubeus makes connections to the Domain Controller. This activity can be detected as an unusual process network connection to TCP/UDP port `88` (Kerberos).

## Detecting Constrained Delegation Attacks With Splunk

Now let's explore how we can identify Constrained Delegation attacks, using Splunk.

#### Detecting Constrained Delegation Attacks - Leveraging PowerShell Logs

**Timeframe**: `earliest=1690544553 latest=1690562556`

  Detecting Unconstrained Delegation/Constrained Delegation Attacks

```shell-session
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*" 
| table _time, ComputerName, EventCode, Message
```

![Log analysis tool showing a search query for EventCode 4104 with two events. Details include time, computer name, event code, and message about creating scriptblock text.](https://academy.hackthebox.com/storage/modules/233/21.png)

#### Detecting Constrained Delegation Attacks - Leveraging Sysmon Logs

**Timeframe**: `earliest=1690562367 latest=1690562556`

  Detecting Unconstrained Delegation/Constrained Delegation Attacks

```shell-session
index=main earliest=1690562367 latest=1690562556 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

![Log analysis tool showing a search query with three events. Details include time, computer, destination IP and port, image, and process information related to Rubeus.exe.](https://academy.hackthebox.com/storage/modules/233/22.png)