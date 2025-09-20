
## DCSync

`DCSync` is a technique exploited by attackers to extract password hashes from Active Directory Domain Controllers (DCs). This method capitalizes on the `Replication Directory Changes` permission typically granted to domain controllers, enabling them to read all object attributes, including password hashes. Members of the Administrators, Domain Admins, and Enterprise Admin groups, or computer accounts on the domain controller, have the capability to execute DCSync to extract password data from Active Directory. This data may encompass both current and historical hashes of potentially valuable accounts, such as KRBTGT and Administrators.

#### Attack Steps:

- The attacker secures administrative access to a domain-joined system or escalates privileges to acquire the requisite rights to request replication data.
- Utilizing tools such as Mimikatz, the attacker requests domain replication data by using the DRSGetNCChanges interface, effectively mimicking a legitimate domain controller. ![Mimikatz output showing DCSync for krbtgt account in lab.internal.local. Includes SAM account details, credentials, and Kerberos keys.](https://academy.hackthebox.com/storage/modules/233/image73.png)
- The attacker may then craft Golden Tickets, Silver Tickets, or opt to employ Pass-the-Hash/Overpass-the-Hash attacks.

#### DCSync Detection Opportunities

`DS-Replication-Get-Changes` operations can be recorded with `Event ID 4662`. However, an additional `Audit Policy Configuration` is needed since it is not enabled by default (Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/DS Access).

![Event Properties for Event 4662 in Microsoft Windows security auditing. Shows object access by SYSTEM on DC01S, with control access properties and audit success.](https://academy.hackthebox.com/storage/modules/233/image72.png)

Seek out events containing the property `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`, corresponding to `DS-Replication-Get-Changes`, as Event `4662` solely consists of GUIDs.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting DCSync With Splunk

Now let's explore how we can identify DCSync, using Splunk.

**Timeframe**: `earliest=1690544278 latest=1690544280`

  Detecting DCSync/DCShadow

```shell-session
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

![Log analysis tool showing a search query for EventCode 4662 with three events. Details include time, user, object file name, object server, and property related to replicating directory changes.](https://academy.hackthebox.com/storage/modules/233/23.png)

## DCShadow

`DCShadow` is an advanced tactic employed by attackers to enact unauthorized alterations to Active Directory objects, encompassing the creation or modification of objects without producing standard security logs. The assault harnesses the `Directory Replicator (Replicating Directory Changes)` permission, customarily granted to domain controllers for replication tasks. DCShadow is a clandestine technique enabling attackers to manipulate Active Directory data and establish persistence within the network. Registration of a rogue DC necessitates the creation of new server and `nTDSDSA` objects in the Configuration partition of the AD schema, which demands Administrator privileges (either Domain or local to the DC) or the `KRBTGT` hash.

#### Attack Steps:

- The attacker secures administrative access to a domain-joined system or escalates privileges to acquire the necessary rights to request replication data.
- The attacker registers a rogue domain controller within the domain, leveraging the `Directory Replicator` permission, and executes changes to AD objects, such as modifying user groups to Domain Administrator groups. ![Mimikatz output showing token information for JENNY_HICKMAN and DCShadow operation. Includes domain info, server info, and object details with primaryGroupID attribute.](https://academy.hackthebox.com/storage/modules/233/image43.png)
- The rogue domain controller initiates replication with the legitimate domain controllers, disseminating the changes throughout the domain. ![Mimikatz output showing DCShadow push operation. Includes domain and server info, performing registration, push, and unregistration steps. Sync completed for DC-lab.internal.local.](https://academy.hackthebox.com/storage/modules/233/image42.png)

#### DCShadow Detection Opportunities

To emulate a Domain Controller, DCShadow must implement specific modifications in Active Directory:

- `Add a new nTDSDSA object`
- `Append a global catalog ServicePrincipalName to the computer object`

`Event ID 4742 (Computer account was changed)` logs changes related to computer objects, including `ServicePrincipalName`.

## Detecting DCShadow With Splunk

Now let's explore how we can identify DCShadow, using Splunk.

**Timeframe**: `earliest=1690623888 latest=1690623890`

  Detecting DCSync/DCShadow

```shell-session
index=main earliest=1690623888 latest=1690623890 EventCode=4742 
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)" 
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn 
| search gcspn=*
```

![Log analysis tool showing a search query for EventCode 4742 with two events. Details include time, computer name, security ID, account name, user, and gcspn.](https://academy.hackthebox.com/storage/modules/233/24_.png)