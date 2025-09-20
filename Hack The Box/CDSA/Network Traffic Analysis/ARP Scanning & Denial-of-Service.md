
We might discern additional aberrant behaviors within the ARP requests and replies. It is common knowledge that poisoning and spoofing form the core of most ARP-based `denial-of-service (DoS)` and `man-in-the-middle (MITM)` attacks. However, adversaries could also exploit ARP for information gathering. Thankfully, we possess the skills to detect and evaluate these tactics following similar procedures.

## ARP Scanning Signs

Some typical red flags indicative of ARP scanning are:

1. `Broadcast ARP requests sent to sequential IP addresses (.1,.2,.3,...)`
    
2. `Broadcast ARP requests sent to non-existent hosts`
    
3. `Potentially, an unusual volume of ARP traffic originating from a malicious or compromised host`
    

## Finding ARP Scanning

Without delay, if we were to open the related traffic capture file (`ARP_Scan.pcapng`) in Wireshark and apply the filter `arp.opcode`, we might observe the following:

![Wireshark capture showing ARP requests. Sources include ASUSTeK_c_8a:a6:a8 and PcsCompu_53:0c:ba, all to Broadcast. Requests ask 'Who has' various IPs, with responses indicating MAC addresses.](https://academy.hackthebox.com/storage/modules/229/ARP_Scan_1.png)

It's possible to detect that indeed ARP requests are being propagated by a single host to all IP addresses in a sequential manner. This pattern is symptomatic of ARP scanning and is a common feature of widely-used scanners such as `Nmap`.

Furthermore, we may discern that active hosts respond to these requests via their ARP replies. This could signal the successful execution of the information-gathering tactic by the attacker.

---

## Identifying Denial-of-Service

An attacker can exploit ARP scanning to compile a list of live hosts. Upon acquiring this list, the attacker might alter their strategy to deny service to all these machines. Essentially, they will strive to contaminate an entire subnet and manipulate as many ARP caches as possible. This strategy is also plausible for an attacker seeking to establish a man-in-the-middle position.

![Wireshark capture showing ARP requests and replies. Source: PcsCompu_53:0c:ba, Destination: Netgear_e2:d5:c3 and Broadcast. Info includes IP addresses 192.168.10.6 to 192.168.10.10 with MAC 08:00:27:53:0c:ba, and duplicate IP detection for 192.168.10.1.](https://academy.hackthebox.com/storage/modules/229/ARP_DoS_1.png)

Promptly, we might note that the attacker's ARP traffic may shift its focus towards declaring new physical addresses for all live IP addresses. The intent here is to corrupt the router's ARP cache.

Conversely, we may witness the duplicate allocation of `192.168.10.1` to client devices. This indicates that the attacker is attempting to corrupt the ARP cache of these victim devices with the intention of obstructing traffic in both directions.

![Wireshark capture showing ARP reply. Source: PcsCompu_53:0c:ba, Destination: Netgear_e2:d5:c3. Sender IP: 192.168.10.1, Target IP: 192.168.10.1. Duplicate IP detected for 192.168.10.1, also used by 2c:30:33:e2:d5:c3.](https://academy.hackthebox.com/storage/modules/229/ARP_DoS_2.png)

## Responding To ARP Attacks

Upon identifying any of these ARP-related anomalies, we might question the suitable course of action to counter these threats. Here are a couple of possibilities:

1. `Tracing and Identification`: First and foremost, the attacker's machine is a physical entity located somewhere. If we manage to locate it, we could potentially halt its activities. On occasions, we might discover that the machine orchestrating the attack is itself compromised and under remote control.
    
2. `Containment`: To stymie any further exfiltration of information by the attacker, we might contemplate disconnecting or isolating the impacted area at the switch or router level. This action could effectively terminate a DoS or MITM attack at its source.
    

Link layer attacks often fly under the radar. While they may seem insignificant to identify and investigate, their detection could be pivotal in preventing the exfiltration of data from higher layers of the OSI model.