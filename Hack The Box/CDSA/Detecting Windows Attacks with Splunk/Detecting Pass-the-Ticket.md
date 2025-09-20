
## Pass-the-Ticket

`Pass-the-Ticket (PtT)` is a lateral movement technique used by attackers to move laterally within a network by abusing Kerberos TGT (Ticket Granting Ticket) and TGS (Ticket Granting Service) tickets. Instead of using NTLM hashes, PtT leverages Kerberos tickets to authenticate to other systems and access network resources without needing to know the users' passwords. This technique allows attackers to move laterally and gain unauthorized access across multiple systems.

#### Attack Steps:

- The attacker gains administrative access to a system, either through an initial compromise or privilege escalation.
- The attacker uses tools such as `Mimikatz` or `Rubeus` to extract valid TGT or TGS tickets from the compromised system's memory. ![Rubeus.exe output monitoring for new TGTs every 30 seconds. Found TGT for user Administrator@LAB.INTERNAL.LOCAL. StartTime: 3/14/2021 7:41:45 PM. EndTime: 3/15/2021 5:41:45 AM. Flags include name_canonicalize and pre_authent. Displays Base64EncodedTicket.](https://academy.hackthebox.com/storage/modules/233/image9.png)
- The attacker submits the extracted ticket for the current logon session. The attacker can now authenticate to other systems and network resources without needing plaintext passwords. ![Command line running Rubeus.exe with the "ptt" command to pass a ticket. The ticket is a long Base64-encoded string.](https://academy.hackthebox.com/storage/modules/233/image41.png) ![Command line output from klist showing cached Kerberos ticket. Client: Administrator@LAB.INTERNAL.LOCAL. Server: krbtgt/LAB.INTERNAL.LOCAL. Encryption: AES-256-CTS-HMAC-SHA1-96. Ticket flags: forwardable, renewable, initial, pre_authent, name_canonicalize. Start: 3/14/2021 19:41:45. End: 3/15/2021 5:41:45.](https://academy.hackthebox.com/storage/modules/233/image10.png)

#### Kerberos Authentication Process

`Kerberos` is a network authentication protocol used to securely authenticate users and services within a Windows Active Directory (AD) environment. The following steps occur in the Kerberos authentication process:

- The user (client) initiates the authentication process by requesting a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC), typically part of the Active Directory domain controller.
- The KDC verifies the user's identity (usually through a password) and issues a TGT encrypted with the user's secret key. The TGT is valid for a specific period and allows the user to request service tickets without needing to re-authenticate.
- The client sends a service ticket request (TGS-REQ) to the KDC for the service using the TGT obtained in the previous step.
- The KDC validates the client's TGT and, if successful, issues a service ticket (TGS) encrypted with the service account's secret key and containing the client's identity and a session key. The client then receives the service ticket (TGS) from the KDC.
- The client connects to the server and sends the TGS to the server as part of the authentication process.

![Diagram of Kerberos authentication process. Steps: 1. Request TGT with NTLM hash. 2. Receive TGT. 3. Request TGS for server. 4. Receive TGS encrypted with server account hash. 5. Present TGS. Optional PAC validation request.](https://academy.hackthebox.com/storage/modules/233/image25.png)

#### Related Windows Security Events

During user access to network resources, several Windows Event Logs are generated to record the logon process and related activities.

- `Event ID 4648 (Explicit Credential Logon Attempt)`: This event is logged when explicit credentials (e.g., username and password) are provided during logon.
- `Event ID 4624 (Logon)`: This event indicates that a user has successfully logged on to the system.
- `Event ID 4672 (Special Logon)`: This event is logged when a user's logon includes special privileges, such as running applications as an administrator.
- `Event ID 4768 (Kerberos TGT Request)`: This event is logged when a client requests a Ticket Granting Ticket (TGT) during the Kerberos authentication process.
- `Event ID 4769 (Kerberos Service Ticket Request)`: When a client requests a Service Ticket (TGS Ticket) to access a remote service during the Kerberos authentication process, Event ID 4769 is generated.

![Log entries from 2023-07-28 at 10:42:57. Events include logon attempts with explicit credentials, successful logons, special privileges assigned, and Kerberos ticket requests. User: RAUL_LYNN. Computers: BLUE.corp.local, DC01.corp.local. Source IPs: 127.0.0.1, ::ffff:10.0.10.101.](https://academy.hackthebox.com/storage/modules/233/image14.png)

#### Pass-the-Ticket Detection Opportunities

Detecting Pass-the-Ticket attacks can be challenging, as attackers are leveraging valid Kerberos tickets instead of traditional credential hashes. The key distinction is that when the Pass-the-Ticket attack is executed, the Kerberos Authentication process will be partial. For example, an attacker imports a TGT ticket into a logon session and requests a TGS ticket for a remote service. From the Domain Controller perspective, the imported TGT was never requested before from the attacker’s system, so there won't be an associated Event ID 4768.

![Diagram of Kerberos authentication process. Steps: 1. Request TGT with NTLM hash. 2. Receive TGT. 3. Request TGS for server. 4. Receive TGS encrypted with server account hash. 5. Present TGS. Optional PAC validation request. Import TGT indicated.](https://academy.hackthebox.com/storage/modules/233/image61.png)

This approach can be converted into the following Splunk detection: Look for `Event ID 4769 (Kerberos Service Ticket Request)` `or` `Event ID 4770 (Kerberos Service Ticket was renewed)` without a prior `Event ID 4768 (Kerberos TGT Request)` from the same system within a specific time window.

Another approach is looking for mismatches between Service and Host IDs (in `Event ID 4769`) and the actual Source and Destination IPs (in `Event ID 3`). Note that there will be several legitimate mismatches, but unusual hostnames or services should be investigated further.

Also, in cases where an attacker imports a TGS ticket into the logon session, it is important to review `Event ID 4771 (Kerberos Pre-Authentication Failed)` for mismatches between Pre-Authentication type and Failure Code. For example, `Pre-Authentication type 2 (Encrypted Timestamp)` with `Failure Code 0x18 (Pre-authentication information was invalid)` would indicate that the client sent a Kerberos AS-REQ with a pre-authentication encrypted timestamp, but the KDC couldn’t decrypt it.

It is essential to understand that these detection opportunities should be enhanced with behavior-based detection. In other words, context is vital. Looking for Event IDs `4769`, `4770`, or `4771` alone will likely generate many false positives. Correlate the event logs with user and system behavior patterns, and consider whether there are any suspicious activities associated with the user or system involved in the logs.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Pass-the-Ticket With Splunk

Now let's explore how we can identify Pass-the-Ticket, using Splunk.

**Timeframe**: `earliest=1690451665 latest=1690451745`

  Detecting Pass-the-Ticket

```shell-session
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

![Splunk search results for WinEventLog:Security with EventCodes 4768, 4769, 4770. Two events on 2023-07-27. Computer: DC01.corp.local. Users: Administrator and another user. Source IP: 10.10.0.100. Service name: krbtgt. Category: Kerberos Service Ticket Operations.](https://academy.hackthebox.com/storage/modules/233/15_.png)

**Search Breakdown**:

- `index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)`: This command filters events from the `main` index that fall within the specified time range. It selects events from the `WinEventLog:Security` source, where the `user` field does not end with a dollar (`$`) and the `EventCode` is one of `4768`, `4769`, or `4770`.
- `| rex field=user "(?<username>[^@]+)"`: This command extracts the `username` from the `user` field using a regular expression. It assigns the extracted value to a new field called `username`.
- `| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"`: This command extracts the IPv4 address from the `src_ip` field, even if it's originally recorded as an IPv6 address. It assigns the extracted value to a new field called `src_ip_4`.
- `| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)`: This command groups events into transactions based on the `username` and `src_ip_4` fields. A transaction begins with an event that has an `EventCode` of `4768`. The `maxspan=10h` parameter sets a maximum duration of `10` hours for a transaction. The `keepevicted=true` parameter ensures that open transactions without an ending event are included in the results.
- `| where closed_txn=0`: This command filters the results to include only open transactions, which do not have an ending event.
- `| search NOT user="*$@*"`: This command filters out results where the `user` field ends with an asterisk (`*`) and contains an at sign (`@`).
- `| table _time, ComputerName, username, src_ip_4, service_name, category`: This command displays the specified fields in a table format.