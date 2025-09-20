
## Overpass-the-Hash

Adversaries may utilize the `Overpass-the-Hash` technique to obtain Kerberos TGTs by leveraging stolen password hashes to move laterally within an environment or to bypass typical system access controls. Overpass-the-Hash (also known as `Pass-the-Key`) allows authentication to occur via Kerberos rather than NTLM. Both NTLM hashes or AES keys can serve as a basis for requesting a Kerberos TGT.

#### Attack Steps:

- The attacker employs tools such as Mimikatz to extract the NTLM hash of a user who is currently logged in to the compromised system. The attacker must have at least local administrator privileges on the system to be able to extract the hash of the user. ![Mimikatz output showing authentication details, usernames, domains, and NTLM hashes for SYSTEM and Administrator accounts.](https://academy.hackthebox.com/storage/modules/233/image65.png)
- The attacker uses a tool such as Rubeus to craft a raw AS-REQ request for a specified user to request a TGT ticket. This step does not require elevated privileges on the host to request the TGT, which makes it a stealthier approach than the Mimikatz Pass-the-Hash attack. ![Rubeus tool output showing TGT request for Administrator using RC4 hash, with successful request and base64 ticket.](https://academy.hackthebox.com/storage/modules/233/image3.png)
- Analogous to the Pass-the-Ticket technique, the attacker submits the requested ticket for the current logon session.

#### Overpass-the-Hash Detection Opportunities

`Mimikatz`'s Overpass-the-Hash attack leaves the same artifacts as the Pass-the-Hash attack, and can be detected using the same strategies.

`Rubeus`, however, presents a somewhat different scenario. Unless the requested TGT is used on another host, Pass-the-Ticket detection mechanisms may not be effective, as Rubeus sends an AS-REQ request directly to the Domain Controller (DC), generating `Event ID 4768 (Kerberos TGT Request)`. However, communication with the DC (`TCP/UDP port 88`) from an unusual process can serve as an indicator of a potential Overpass-the-Hash attack.

Let's now navigate to the bottom of this section and click on "Click here to spawn the target system!". Then, access the Splunk interface at http://[Target IP]:8000 and launch the Search & Reporting Splunk application. The vast majority of searches covered from this point up to end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

## Detecting Overpass-the-Hash With Splunk (Targeting Rubeus)

Now let's explore how we can identify Overpass-the-Hash, using Splunk.

**Timeframe**: `earliest=1690443407 latest=1690443544`

  Detecting Overpass-the-Hash

```shell-session
index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

![Search query in a log analysis tool showing one event with details: time, computer, destination IP and port, image, and process.](https://academy.hackthebox.com/storage/modules/233/16.png)