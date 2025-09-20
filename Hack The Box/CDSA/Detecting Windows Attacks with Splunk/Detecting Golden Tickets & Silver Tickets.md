
## Golden Ticket

A `Golden Ticket` attack is a potent method where an attacker forges a Ticket Granting Ticket (TGT) to gain unauthorized access to a Windows Active Directory domain as a domain administrator. The attacker creates a TGT with arbitrary user credentials and then uses this forged ticket to impersonate a domain administrator, thereby gaining full control over the domain. The Golden Ticket attack is stealthy and persistent, as the forged ticket has a long validity period and remains valid until it expires or is revoked.

#### Attack Steps:

- The attacker extracts the NTLM hash of the KRBTGT account using a `DCSync` attack (alternatively, they can use `NTDS.dit` and `LSASS process dumps` on the Domain Controller). ![SAM account details for krbtgt, including username, account type, security ID, credentials, and Kerberos keys.](https://academy.hackthebox.com/storage/modules/233/image74.png)
- Armed with the `KRBTGT` hash, the attacker forges a TGT for an arbitrary user account, assigning it domain administrator privileges. ![Mimikatz and Command Prompt output showing a golden ticket creation for EvilAdmin in lab.internal.local, with ticket details and cached tickets.](https://academy.hackthebox.com/storage/modules/233/image17.png)
- The attacker injects the forged TGT in the same manner as a Pass-the-Ticket attack.

#### Golden Ticket Detection Opportunities

Detecting Golden Ticket attacks can be challenging, as the TGT can be forged offline by an attacker, leaving virtually no traces of `Mimikatz` execution. One option is to monitor common methods of extracting the `KRBTGT` hash:

- `DCSync attack`
- `NTDS.dit file access`
- `LSASS memory read on the domain controller (Sysmon Event ID 10)`

From another standpoint, a Golden Ticket is just another ticket for Pass-the-Ticket detection.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Golden Tickets With Splunk (Yet Another Ticket To Be Passed Approach)

Now let's explore how we can identify Golden Tickets, using Splunk.

**Timeframe**: `earliest=1690451977 latest=1690452262`

  Detecting Golden Tickets/Silver Tickets

```shell-session
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

![Log analysis tool showing a search query for security events with one result. Details include time, computer name, username, source IP, service name, and category.](https://academy.hackthebox.com/storage/modules/233/17.png)

## Silver Ticket

Adversaries who possess the password hash of a target service account (e.g., `SharePoint`, `MSSQL`) may forge Kerberos Ticket Granting Service (TGS) tickets, also known as `Silver Tickets`. Silver tickets can be used to impersonate any user, but they are more limited in scope than Golden Tickets, as they only allow adversaries to access a specific resource (e.g., `MSSQL`) and the system hosting the resource.

#### Attack Steps:

- The attacker extracts the NTLM hash of the targeted service account (or the computer account for `CIFS` access) using tools like `Mimikatz` or other credential dumping techniques.
- Generate a Silver Ticket: Using the extracted NTLM hash, the attacker employs tools like `Mimikatz` to create a forged TGS ticket for the specified service. ![Mimikatz output showing golden ticket creation for DarthKittius in lab.internal.local, targeting CIFS service, with ticket details and successful submission.](https://academy.hackthebox.com/storage/modules/233/image37.png)
- The attacker injects the forged TGT in the same manner as a Pass-the-Ticket attack. ![Command Prompt showing cached Kerberos ticket for DarthKittius on CIFS service and directory listing of iis.lab.internal.local C$ drive.](https://academy.hackthebox.com/storage/modules/233/image77.png)

#### Silver Ticket Detection Opportunities

Detecting forged service tickets (TGS) can be challenging, as there are no simple indicators of attack. In both Golden Ticket and Silver Ticket attacks, arbitrary users can be used, `including non-existent ones`. `Event ID 4720 (A user account was created)` can help identify newly created users. Subsequently, we can compare this user list with logged-in users.

Because there is no validation for user permissions, users can be granted administrative permissions. `Event ID 4672 (Special Logon)` can be employed to detect anomalously assigned privileges.

## Detecting Silver Tickets With Splunk

Now let's explore how we can identify Silver Tickets, using Splunk.

#### Detecting Silver Tickets With Splunk Through User Correlation

Let's first create a list of users (`users.csv`) leveraging `Event ID 4720 (A user account was created)` as follows.

  Detecting Golden Tickets/Silver Tickets

```shell-session
index=main latest=1690448444 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

**Note**: `users.csv` can be downloaded from the `Resources` section of this module (upper right corner) and uploaded to Splunk by clicking `Settings` -> `Lookups` -> `Lookup table files` -> `New Lookup Table File`.

Let's now compare the list above with logged-in users as follows.

**Timeframe**: `latest=1690545656`

  Detecting Golden Tickets/Silver Tickets

````shell-session
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h = 1690451977
| where firstTime > last24h
```| eval last24h=relative_time(now(),"-24h@h")```
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
````

![Log analysis tool showing a search query for EventCode 4624 with 19,316 events. Details include user, first time, computer name, and event code.](https://academy.hackthebox.com/storage/modules/233/18.png)

**Search Breakdown**:

- `index=main latest=1690545656 EventCode=4624`: This command filters events from the `main` index that occur before a specified timestamp and have an `EventCode` of `4624`, indicating a successful login.
- `| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user`: This command calculates the earliest login time for each user, groups them by the `user` field, and creates a table with columns `firstTime`, `ComputerName`, and `EventCode`.
- `| eval last24h = 1690451977`: This command defines a variable `last24h` and assigns it a specific `timestamp` value. This value represents a time threshold for filtering the results.
- `| where firstTime > last24h`: This command filters the results to include only logins that occurred after the time threshold defined in `last24h`.
- `| eval last24h=relative_time(now(),"-24h@h")`: This command (commented out) would redefine the `last24h` variable to be exactly 24 hours before the current time. Note that this line is commented out with backticks, so it will not be executed in this search.
- `| convert ctime(firstTime)`: This command converts the `firstTime` field from epoch time to a human-readable format.
- `| convert ctime(last24h)`: This command converts the `last24h` field from epoch time to a human-readable format.
- `| lookup users.csv user as user OUTPUT EventCode as Events`: This command performs a `lookup` using the `users.csv` file, matches the `user` field from the search results with the `user` field in the CSV file, and outputs the `EventCode` column from the CSV file as a new field called `Events`.
- `| where isnull(Events)`: This command filters the results to include only those where the `Events` field is null. This indicates that the user was not found in the `users.csv` file.

#### Detecting Silver Tickets With Splunk By Targeting Special Privileges Assigned To New Logon

**Timeframe**: `latest=1690545656`

  Detecting Golden Tickets/Silver Tickets

````shell-session
index=main latest=1690545656 EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = 1690451977 
```| eval last24h=relative_time(now(),"-24h@h") ```
| where firstTime > last24h 
| table firstTime, ComputerName, Account_Name 
| convert ctime(firstTime)
````