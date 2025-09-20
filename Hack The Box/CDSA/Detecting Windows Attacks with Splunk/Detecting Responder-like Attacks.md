
## LLMNR/NBT-NS/mDNS Poisoning

`LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning`, also referred to as NBNS spoofing, are network-level attacks that exploit inefficiencies in these name resolution protocols. Both `LLMNR` and `NBT-NS` are used to resolve hostnames to IP addresses on local networks when the fully qualified domain name (FQDN) resolution fails. However, their lack of built-in security mechanisms renders them susceptible to spoofing and poisoning attacks.

Typically, attackers employ the [Responder](https://github.com/lgandx/Responder) tool to execute LLMNR, NBT-NS, or mDNS poisoning.

#### Attack Steps:

- A victim device sends a name resolution query for a mistyped hostname (e.g., `fileshrae`).
- DNS fails to resolve the mistyped hostname.
- The victim device sends a name resolution query for the mistyped hostname using LLMNR/NBT-NS.
- The attacker's host responds to the LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic, pretending to know the identity of the requested host. This effectively poisons the service, directing the victim to communicate with the adversary-controlled system.

![Diagram showing a DNS resolution process. A computer tries to resolve "\fileshare" using DNS, fails with "Unknown hostname," then uses LLMNR/NBT-NS/mDNS. Another computer responds with its own IP.](https://academy.hackthebox.com/storage/modules/233/image68.png)

The result of a successful attack is the acquisition of the victim's NetNTLM hash, which can be either cracked or relayed in an attempt to gain access to systems where these credentials are valid.

#### Responder Detection Opportunities

Detecting LLMNR, NBT-NS, and mDNS poisoning can be challenging. However, organizations can mitigate the risk by implementing the following measures:

- Deploy network monitoring solutions to detect unusual LLMNR and NBT-NS traffic patterns, such as an elevated volume of name resolution requests from a single source.
- Employ a honeypot approach - name resolution for non-existent hosts should fail. If an attacker is present and spoofing LLMNR/NBT-NS/mDNS responses, name resolution will succeed. [https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/)

![PowerShell script for detecting LLMNR/NBT-NS spoofing. It logs requests to false hostnames and detects spoofing by IP address "10.0.10.5" with request "COPY-NY-DC-02."](https://academy.hackthebox.com/storage/modules/233/image22.png)

A PowerShell script similar to the above can be automated to run as a scheduled task to aid in detection. Logging this activity might pose a challenge, but the `New-EventLog` PowerShell cmdlet can be used.

  Detecting Responder-like Attacks

```powershell-session
PS C:\Users\Administrator> New-EventLog -LogName Application -Source LLMNRDetection
```

To create an event, the `Write-EventLog` cmdlet should be used:

  Detecting Responder-like Attacks

```powershell-session
PS C:\Users\Administrator> Write-EventLog -LogName Application -Source LLMNRDetection -EventId 19001 -Message $msg -EntryType Warning
```

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Responder-like Attacks With Splunk

Now let's explore how we can identify the Responder-like attacks previously discussed, using Splunk and logs from a PowerShell script similar to the one above.

**Timeframe**: `earliest=1690290078 latest=1690291207`

  Detecting Responder-like Attacks

```shell-session
index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

![Splunk search interface showing a query for LLMNR detection. Results include a timestamp, computer name "BLUE.corp.local," source "LLMNRDetection," and message indicating LLMNR server IPs "::1" and "10.10.0.221."](https://academy.hackthebox.com/storage/modules/233/4.png)

---

[Sysmon Event ID 22](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022) can also be utilized to track DNS queries associated with non-existent/mistyped file shares.

**Timeframe**: `earliest=1690290078 latest=1690291207`

  Detecting Responder-like Attacks

```shell-session
index=main earliest=1690290078 latest=1690291207 EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

![Log entry showing three events. Highlighted entry: timestamp "2023-07-25 13:01:52," computer "BLUE.corp.local," user "NETWORK SERVICE," image "C:\Windows\System32\svchost.exe," query name "myfileshar3," query results "::1; ::ffff:10.10.0.221;".](https://academy.hackthebox.com/storage/modules/233/89.png)

---

Additionally, remember that [Event 4648](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648) can be used to detect explicit logons to rogue file shares which attackers might use to gather legitimate user credentials.

**Timeframe**: `earliest=1690290814 latest=1690291207`

  Detecting Responder-like Attacks

```shell-session
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

![Splunk search interface showing a query for EventCode 4648. Result: timestamp "2023-07-25 13:13:50," source "WinEventLog:Security," user "Administrator," target server "ILUA.LOCAL." Message details a logon attempt using explicit credentials by "CORP\JOLENE_MCGEE."](https://academy.hackthebox.com/storage/modules/233/6.png)