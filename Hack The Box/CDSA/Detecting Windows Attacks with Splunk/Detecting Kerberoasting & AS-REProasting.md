
## Kerberoasting

`Kerberoasting` is a technique targeting service accounts in Active Directory environments to extract and crack their password hashes. The attack exploits the way Kerberos service tickets are encrypted and the use of weak or easily crackable passwords for service accounts. Once an attacker successfully cracks the password hashes, they can gain unauthorized access to the targeted service accounts and potentially move laterally within the network.

An example of a Kerberoasting attack is using the [Rubeus](https://github.com/GhostPack/Rubeus) `kerberoast` module.

![PowerShell window running Rubeus.exe for Kerberoasting. Version 1.6.1 identifies one Kerberoastable user: "iis_svc" with service principal name "HTTP/iis.lab.internal.local." Displays hash and account details.](https://academy.hackthebox.com/storage/modules/233/image76.png)

#### Attack Steps:

- `Identify Target Service Accounts`: The attacker enumerates Active Directory to identify service accounts with `Service Principal Names (SPNs)` set. Service accounts are often associated with services running on the network, such as SQL Server, Exchange, or other applications. The following is a code snippet from `Rubeus` that is related to this step. ![Code snippet in C# for parsing dates and creating a user search filter. It tries to convert "pwdSetAfter" and "pwdSetBefore" to DateTime using "MM-dd-yyyy" format. If parsing fails, it outputs an error message. Constructs a search filter with "samAccountType" and "servicePrincipalName."](https://academy.hackthebox.com/storage/modules/233/image2.png)
- `Request TGS Tickets`: The attacker uses the identified service accounts to request `Ticket Granting Service (TGS)` tickets from the `Key Distribution Center (KDC)`. These TGS tickets contain encrypted service account password hashes. The following is a code snippet from `Rubeus` that is related to this step. ![C# code snippet checking if a TGT is supplied. It verifies supported encryption types for RC4 and AES. If conditions are met, it retrieves a service ticket using GetTGSRepHash. If retrieval fails, it retries with enterprise principal name.](https://academy.hackthebox.com/storage/modules/233/image87.png)
- `Offline Brute-Force Attack`: The attacker employs offline brute-force techniques, utilizing password cracking tools like `Hashcat` or `John the Ripper`, to attempt to crack the encrypted password hashes.

#### Benign Service Access Process & Related Events

When a user connects to an `MSSQL (Microsoft SQL Server)` database using a service account with an `SPN`, the following steps occur in the Kerberos authentication process:

- `TGT Request`: The user (client) initiates the authentication process by requesting a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC), typically part of the Active Directory domain controller.
- `TGT Issue`: The KDC verifies the user's identity (usually through a password hash) and issues a TGT encrypted with the user's secret key. The TGT is valid for a specific period and allows the user to request service tickets without needing to re-authenticate.
- `Service Ticket Request`: The client sends a service ticket request (TGS-REQ) to the KDC for the MSSQL server's SPN using the TGT obtained in the previous step.
- `Service Ticket Issue`: The KDC validates the client's TGT and, if successful, issues a service ticket (TGS) encrypted with the service account's secret key, containing the client's identity and a session key. The client then receives the TGS.
- `Client Connection`: The client connects to the MSSQL server and sends the TGS to the server as part of the authentication process.
- `MSSQL Server Validates the TGS`: The MSSQL server decrypts the TGS using its own secret key to obtain the session key and client identity. If the TGS is valid and the session key is correct, the MSSQL server accepts the client's connection and grants access to the requested resources. ![Diagram of Kerberos authentication process. Steps: 1. Request TGT with NTLM hash. 2. Receive TGT. 3. Request TGS for server. 4. Receive TGS encrypted with server account. 5. Present TGS. Optional PAC validation request.](https://academy.hackthebox.com/storage/modules/233/image25.png)

Note that the steps mentioned above can also be observed during network traffic analysis:

![Network traffic capture showing TGT, TGS, and Auth processes. IPs involved: 10.0.10.20, 10.0.10.100, 10.0.10.21. Protocols include TCP, KRB5, and HTTP. Various packet details and sequences are displayed.](https://academy.hackthebox.com/storage/modules/233/image8.png)

During the Kerberos authentication process, several security-related events are generated in the Windows Event Log when a user connects to an MSSQL server:

- `Event ID 4768 (Kerberos TGT Request)`: Occurs when the client workstation requests a TGT from the KDC, generating this event in the Security log on the domain controller.
- `Event ID 4769 (Kerberos Service Ticket Request)`: Generated after the client receives the TGT and requests a TGS for the MSSQL server's SPN.
- `Event ID 4624 (Logon)`: Logged in the Security log on the MSSQL server, indicating a successful logon once the client initiates a connection to the MSSQL server and logs in using the service account with the SPN to establish the connection. ![Log entries showing Kerberos authentication events. Timestamps: 2021-03-11T22:36:38-39Z. User: iis_svc. Events: TGT and service ticket requests, successful logon, and logon attempt with explicit credentials. IPs: 10.0.10.100, 10.0.10.21.](https://academy.hackthebox.com/storage/modules/233/image66.png)

#### Kerberoasting Detection Opportunities

Since the initial phase of Kerberoasting involves identifying target service accounts, monitoring LDAP activity, as explained in the domain reconnaissance section, can help in identifying suspicious LDAP queries.

An alternative approach focuses on the difference between benign service access and a Kerberoasting attack. In both scenarios, TGS tickets for the service will be requested, but only in the case of benign service access will the user connect to the server and present the TGS ticket.

![Diagram of Kerberos authentication process. Steps: 1. Request TGT with NTLM hash. 2. Receive TGT. 3. Request TGS for server. 4. Receive TGS encrypted with server account hash. 5. Present TGS. Optional PAC validation request.](https://academy.hackthebox.com/storage/modules/233/image18.png)

Detection logic entails finding all events for TGS requests and logon events from the same user, then identifying instances where a TGS request is present without a subsequent logon event. In the case of IIS service access using a service account with an SPN, an additional `4648 (A logon was attempted using explicit credentials)` event will be generated as a logon event.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Kerberoasting With Splunk

Now let's explore how we can identify Kerberoasting, using Splunk.

#### Benign TGS Requests

First, let's see some benign TGS requests in Splunk.

**Timeframe**: `earliest=1690388417 latest=1690388630`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) 
| dedup RecordNumber 
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
```

![Splunk search results for EventCodes 4648 and 4769. Two events on 2023-07-26 at 16:23:15. User "TAYLOR_BENTON" attempted logon with explicit credentials and requested a Kerberos service ticket. Source IP: 10.10.0.101, service name: iis_svc.](https://academy.hackthebox.com/storage/modules/233/7.png)

**Search Breakdown**:

- `index=main earliest=1690388417 latest=1690388630`: This filters the search to only include events from the main index that occurred between the specified earliest and latest epoch timestamps.
- `EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: This further filters the search to only include events with an `EventCode` of `4648` `or` an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: This removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: This extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information`: This displays the specified fields in tabular format.

#### Detecting Kerberoasting - SPN Querying

**Timeframe**: `earliest=1690448444 latest=1690454437`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

![Splunk search results for WinEventLog:SilkService-Log. Four events on 2023-07-27. Computer: BLUE.corp.local. Process: rundll32. Distinguished Name: DC=corp,DC=local. Search filter includes samAccountType and servicePrincipalName conditions.](https://academy.hackthebox.com/storage/modules/233/8.png)

#### Detecting Kerberoasting - TGS Requests

**Timeframe**: `earliest=1690450374 latest=1690450483`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

![Splunk search results for EventCodes 4648 and 4769 with service name iis_svc. One event on 2023-07-27 at 09:34:00. Username: JOLENE_MCGEE. Event: 4769. Service name: iis_svc.](https://academy.hackthebox.com/storage/modules/233/9.png)

**Search Breakdown**:

- `index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with an `EventCode` of `4648` or an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: Removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: Extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| bin span=2m _time`: Bins the events into 2-minute intervals based on the `_time` field.
- `| search username!=*$`: Filters out events where the `username` field ends with a `$`.
- `| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username`: Groups the events by the `_time` and `username` fields, and creates new fields that contain the `unique` values of the `EventCode`, `service_name`, `Additional_Information`, and `Target_Server_Name` fields within each group.
- `| where !match(Events,"4648")`: Filters out events that have the value `4648` in the Events field.

#### Detecting Kerberoasting Using Transactions - TGS Requests

**Timeframe**: `earliest=1690450374 latest=1690450483`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$ 
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769) 
| where closed_txn=0 AND EventCode = 4769
| table _time, EventCode, service_name, username
```

![Splunk search results for EventCodes 4648 and 4769 with service name iis_svc. One event on 2023-07-27 at 09:34:28. Username: JOLENE_MCGEE. EventCode: 4769. Service name: iis_svc.](https://academy.hackthebox.com/storage/modules/233/10.png)

**Search Breakdown**:

This Splunk search query is different from the previous query primarily due to the use of the `transaction` command, which groups events into transactions based on specified fields and criteria.

- `index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with an `EventCode` of `4648` or an `EventCode` of `4769` with a `service_name` of `iis_svc`.
- `| dedup RecordNumber`: Removes duplicate events based on the `RecordNumber` field.
- `| rex field=user "(?<username>[^@]+)"`: Extracts the `username` portion of the `user` field using a regular expression and stores it in a new field called `username`.
- `| search username!=*$`: Filters out events where the `username` field ends with a `$`.
- `| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)`: Groups events into `transactions` based on the `username` field. The `keepevicted=true` option includes events that do not meet the transaction criteria. The `maxspan=5s` option sets the maximum time duration of a transaction to 5 seconds. The `endswith=(EventCode=4648)` and `startswith=(EventCode=4769)` options specify that transactions should start with an event with `EventCode 4769` and end with an event with `EventCode 4648`.
- `| where closed_txn=0 AND EventCode = 4769`: Filters the results to only include transactions that are not closed (`closed_txn=0`) and have an `EventCode` of `4769`.
- `| table _time, EventCode, service_name, username`: Displays the remaining events in tabular format with the specified fields.

This query focuses on identifying events with an `EventCode` of `4769` that are part of an incomplete transaction (i.e., they did not end with an event with `EventCode 4648` within the `5`-second window).

## AS-REPRoasting

`ASREPRoasting` is a technique used in Active Directory environments to target user accounts without pre-authentication enabled. In Kerberos, pre-authentication is a security feature requiring users to prove their identity before the TGT is issued. However, certain user accounts, such as those with unconstrained delegation, do not have pre-authentication enabled, making them susceptible to ASREPRoasting attacks.

![PowerShell window running Rubeus.exe for AS-REP roasting. Version 1.6.1 targets domain "lab.internal.local." User: KEN_MORTON. AS-REP without preauth is successful. Displays AS-REP hash.](https://academy.hackthebox.com/storage/modules/233/image40.png)

#### Attack Steps:

- `Identify Target User Accounts`: The attacker identifies user accounts without pre-authentication enabled. The following is a code snippet from `Rubeus` that is related to this step. ![C# code snippet for setting a domain search filter. It constructs userSearchFilter based on userName and ldapFilter. Handles exceptions by displaying an error message if setting the filter fails.](https://academy.hackthebox.com/storage/modules/233/image13.png)
- `Request AS-REQ Service Tickets`: The attacker initiates an AS-REQ service ticket request for each identified target user account. The following is a code snippet from `Rubeus` that is related to this step. ![C# code snippet for finding users for AS-REP roasting. Searches for users; if none found, outputs a message. For each user, retrieves samAccountName and distinguishedName, then calls GetASRepHash.](https://academy.hackthebox.com/storage/modules/233/image24.png)
- `Offline Brute-Force Attack`: The attacker captures the encrypted TGTs and employs offline brute-force techniques to attempt to crack the password hashes.

#### Kerberos Pre-Authentication

`Kerberos pre-authentication` is an additional security mechanism in the Kerberos authentication protocol enhancing user credentials protection during the authentication process. When a user tries to access a network resource or service, the client sends an authentication request AS-REQ to the KDC.

If pre-authentication is enabled, this request also contains an encrypted timestamp (`pA-ENC-TIMESTAMP`). The KDC attempts to decrypt this timestamp using the user password hash and, if successful, issues a TGT to the user.

![Network packet capture showing Kerberos AS-REQ from 10.0.10.101 to 10.0.10.20. Includes PA-DATA items: PA-ENC-TIMESTAMP and PA-PAC-REQUEST. CName: JENNY_HICKMAN, realm: LAB.INTERNAL.LOCAL.](https://academy.hackthebox.com/storage/modules/233/image79.png)

When pre-authentication is disabled, there is no timestamp validation by the KDC, allowing users to request a TGT ticket without knowing the user password.

![Network packet capture showing Kerberos AS-REQ from 10.0.10.101 to 10.0.10.20. Includes PA-DATA item: PA-PAC-REQUEST. CName: JENNY_HICKMAN, realm: LAB.INTERNAL.LOCAL.](https://academy.hackthebox.com/storage/modules/233/image78.png)

#### AS-REPRoasting Detection Opportunities

Similar to Kerberoasting, the initial phase of AS-REPRoasting involves identifying user accounts with unconstrained delegation enabled or accounts without pre-authentication, which can be detected by LDAP monitoring.

Kerberos authentication `Event ID 4768 (TGT Request)` contains a `PreAuthType` attribute in the additional information part of the event indicating whether pre-authentication is enabled for an account.

## Detecting AS-REPRoasting With Splunk

Now let's explore how we can identify AS-REPRoasting, using Splunk.

#### Detecting AS-REPRoasting - Querying Accounts With Pre-Auth Disabled

**Timeframe**: `earliest=1690392745 latest=1690393283`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

![Splunk search results for WinEventLog:SilkService-Log. Two events on 2023-07-26 at 17:41:12. Computer: BLUE.corp.local. Process: Rubeus. Distinguished Name: DC=corp,DC=local. Search filter includes samAccountType and userAccountControl conditions.](https://academy.hackthebox.com/storage/modules/233/11.png)

#### Detecting AS-REPRoasting - TGT Requests For Accounts With Pre-Auth Disabled

**Timeframe**: `earliest=1690392745 latest=1690393283`

  Detecting Kerberoasting/AS-REProasting

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

![Splunk search results for WinEventLog:Security with EventCode 4768. Shows 320 events on 2023-07-26 at 17:41:20-21. Source IP: 10.0.10.101. Users include TAMI_DANIEL and CELIA_RAMIREZ. Pre-Authentication Type: 0. Ticket Options: 0x40810010. Ticket Encryption Type: 0x17.](https://academy.hackthebox.com/storage/modules/233/12.png)

**Search Breakdown**:

- `index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps. It further filters the search to only include events with a source of `WinEventLog:Security`, an `EventCode` of `4768`, and a `Pre_Authentication_Type` of `0`.
- `| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"`: Uses a regular expression to extract the `src_ip` (source IP address) field. The expression matches an optional `"::ffff:"` prefix followed by an IP address in dotted decimal notation. This step handles IPv4-mapped IPv6 addresses by extracting the IPv4 portion.
- `| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type`: Displays the remaining events in tabular format with the specified fields.