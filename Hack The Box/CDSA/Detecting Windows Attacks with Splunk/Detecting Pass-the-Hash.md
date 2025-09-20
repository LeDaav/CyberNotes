[]()
## Pass-the-Hash

`Pass-the-Hash` is a technique utilized by attackers to authenticate to a networked system using the `NTLM` hash of a user's password instead of the plaintext password. The attack capitalizes on the way Windows stores password hashes in memory, enabling adversaries with administrative access to capture the hash and reuse it for lateral movement within the network.

#### Attack Steps:

- The attacker employs tools such as `Mimikatz` to extract the `NTLM` hash of a user currently logged onto the compromised system. Note that local administrator privileges are required on the system to extract the user's hash. ![Mimikatz output showing logon passwords. Authentication IDs: 2560900 and 911055. Usernames: SYSTEM and JERRI_BALLARD. Domain: corp.local. NTLM hash for Administrator: fc525c9683e8fe067095ba2ddc971889.](https://academy.hackthebox.com/storage/modules/233/image65.png)
- Armed with the `NTLM` hash, the attacker can authenticate as the targeted user on other systems or network resources without needing to know the actual password. ![Mimikatz 2.2.0 output showing impersonation and pass-the-hash attack. User: Administrator. NTLM hash: fc525c9683e8fe067095ba2ddc971889. Domain: corp.local. Process ID: 1788. LSA process is now read/write.](https://academy.hackthebox.com/storage/modules/233/image52.png)
- Utilizing the authenticated session, the attacker can move laterally within the network, gaining unauthorized access to other systems and resources. ![Command prompt showing directory listing of \dc01\c$. Folders include PerfLogs, Program Files, and Windows. Command whoami returns "nt authority\system."](https://academy.hackthebox.com/storage/modules/233/image62.png)

#### Windows Access Tokens & Alternate Credentials

An `access token` is a data structure that defines the security context of a process or thread. It contains information about the associated user account's identity and privileges. When a user logs on, the system verifies the user's password by comparing it with information stored in a security database. If the password is authenticated, the system generates an access token. Subsequently, any process executed on behalf of that user possesses a copy of this access token. (**Source**: [https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens))

`Alternate Credentials` provide a way to supply different login credentials (username and password) for specific actions or processes without altering the user's primary login session. This permits a user or process to execute certain commands or access resources as a different user without logging out or switching user accounts. The `runas` command is a Windows command-line tool that allows users to execute commands as another user. When the `runas` command is executed, a new access token is generated, which can be verified with the `whoami` command.

![Two command prompt windows. First attempts to run as "lab.internal.local\Administrator" but access is denied for \10.0.10.20\c. Second window, running as "labs\administrator," successfully lists directories on \10.0.10.20\c, including PerfLogs and Windows.](https://academy.hackthebox.com/storage/modules/233/image15.png)

The `runas` command also contains an interesting flag `/netonly`. This flag indicates that the specified user information is for remote access only. Even though the `whoami` command returns the original username, the spawned `cmd.exe` can still access the Domain Controller root folder.

![Two command prompt windows. First attempts to run as "lab.internal.local\Administrator" with /netonly. Second window, running as "labs\jenny_hickman," successfully lists directories on \10.0.10.20\c$, including PerfLogs and Windows.](https://academy.hackthebox.com/storage/modules/233/image5.png)

Each `access token` references a `LogonSession` generated at user logon. This `LogonSession` security structure contains such information as Username, Domain, and AuthenticationID (`NTHash/LMHash`), and is used when the process attempts to access remote resources. When the `netonly` flag is used, the process has the same `access token` but a different `LogonSession`.

![Diagram showing process access token flow. Includes username, groups, privileges, and LogonSession. LogonSession details: username, domain, AuthenticationID (NTHash, LMHash). Used by lsass.exe to access remote resources.](https://academy.hackthebox.com/storage/modules/233/image34.png)

#### Pass-the-Hash Detection Opportunities

From the Windows Event Log perspective, the following logs are generated when the `runas` command is executed:

- When `runas` command is executed without the `/netonly` flag - `Event ID 4624 (Logon)` with `LogonType 2 (interactive)`. ![Log entries from 2021-03-13 showing various security events. Includes successful logons, logon attempts with explicit credentials, Kerberos ticket requests, and domain controller credential validations. Users include SYSTEM, Administrator, and JENNY_HICKMAN.](https://academy.hackthebox.com/storage/modules/233/image38.png)
- When `runas` command is executed with the `/netonly` flag - `Event ID 4624 (Logon)` with `LogonType 9 (NewCredentials)`. ![Log entries from 2021-03-13 showing security events. Includes successful logons, logoffs, logon attempts with explicit credentials, and domain controller credential validations. Users include JENNY_HICKMAN, Administrator, and KEN_MORTON.](https://academy.hackthebox.com/storage/modules/233/image32.png)

Simple detection would involve looking for `Event ID 4624` and `LogonType 9`, but as mentioned before, there could be some false positives related to `runas` usage.

The main difference between `runas` with the `netonly` flag and the `Pass-the-Hash` attack is that in the latter case, `Mimikatz` will access the `LSASS` process memory to change `LogonSession` credential materials. Thus, initial detection can be enhanced by correlating `User Logon with NewCredentials` events with `Sysmon Process Access Event Code 10`.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Pass-the-Hash With Splunk

Now let's explore how we can identify Pass-the-Hash, using Splunk.

Before we move on to reviewing the searches, please consult [this](https://blog.netwrix.com/2021/11/30/how-to-detect-pass-the-hash-attacks) source to gain a better understanding of where the search part `Logon_Process=seclogo` originated from.

**Timeframe**: `earliest=1690450689 latest=1690451116`

  Detecting Pass-the-Hash

```shell-session
index=main earliest=1690450708 latest=1690451116 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

![Splunk search result for WinEventLog:Security. One event on 2023-07-27 at 09:42:52. Computer: ORANGE.corp.local. EventCode: 4624. User: SYSTEM. Network Account: RAUL_LYNN. Logon Type: 9. Logon Process: seclogo.](https://academy.hackthebox.com/storage/modules/233/13.png)

---

As already mentioned, we can enhance the search above by adding LSASS memory access to the mix as follows.

  Detecting Pass-the-Hash

```shell-session
index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

![Splunk search result for Sysmon and Security logs. One event on 2023-07-27 at 09:42:52. Computer: ORANGE.corp.local. Source Image: C:\Windows\system32\rundll32.exe. Source Process ID: 4596. Network Account: RAUL_LYNN. Logon Type: 9. Logon Process: seclogo.](https://academy.hackthebox.com/storage/modules/233/14.png)

**Search Breakdown**:

- `index=main earliest=1690450689 latest=1690451116`: Filters the search to only include events from the `main` index that occurred between the specified earliest and latest epoch timestamps.
- `(source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe")`: Filters the search to only include `Sysmon` operational log events with an `EventCode` of `10` (Process Access). It further narrows down the results to events where the `TargetImage` is `C:\Windows\system32\lsass.exe` (indicating that the `lsass.exe` process is being accessed) and the `SourceImage` is not a known legitimate process from the Windows Defender directory.
- `OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)`: Filters the search to also include Security event log events with an `EventCode` of `4624` (Logon), `Logon_Type` of `9` (NewCredentials), and `Logon_Process` of `seclogo`.
- `| sort _time, RecordNumber`: Sorts the events based on the `_time` field and then the `RecordNumber` field.
- `| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)`: Groups related events based on the `host` field, with a maximum time span of `1` minute between the start and end events. This command is used to associate process access events targeting `lsass.exe` with remote logon events.
- `| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process`: Aggregates the events based on the specified fields, counting the number of occurrences for each combination of field values.
- `| fields - count`: Removes the `count` field from the results.