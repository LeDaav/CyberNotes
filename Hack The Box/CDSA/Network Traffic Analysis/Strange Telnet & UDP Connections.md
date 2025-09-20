
When we look for strange traffic, we should always consider telnet and UDP traffic. After all, these can be overlooked, but can especially revealing during our traffic analysis efforts.

---

## Telnet

![Diagram of Telnet operation showing terminal and application communication via Internet, using Telnet client and server with network virtual terminal.](https://academy.hackthebox.com/storage/modules/229/Internet.png)

Telnet is a network protocol that allows a bidirectional interactive communication session between two devices over a network. This protocol was developed in the 1970s and was defined in RFC 854. As of recent years, its usage has decreased significantly as opposed to SSH.

In many older cases, such as our Windows NT like machines, they may still utilize telnet to provide remote command and control to microsoft terminal services.

However, we should always watch for weird and strange telnet communications as it can also be used by attackers for malicious purposes such as data exfiltration and tunneling.

## Finding Traditional Telnet Traffic Port 23

**Related PCAP File(s)**:

- `telnet_tunneling_23.pcapng`

Suppose we were to open Wireshark, we might notice some telnet communications originating from Port 23. In this case, we can always inspect this traffic further.

![Wireshark capture showing TCP and Telnet traffic between 192.168.10.5 and 192.168.10.7, with sequence and acknowledgment details.](https://academy.hackthebox.com/storage/modules/229/1-telnet.png)

Fortunately for us, telnet traffic tends to be decrypted and easily inspectable, but like ICMP, DNS, and other tunneling methods, attackers may encrypt, encode, or obfuscate this text. So we should always be careful.

![Network packet details showing Telnet data from 192.168.10.5 to 192.168.10.7, indicating unencrypted Telnet communication.](https://academy.hackthebox.com/storage/modules/229/2-telnet.png)

## Unrecognized TCP Telnet in Wireshark

**Related PCAP File(s)**:

- `telnet_tunneling_9999.pcapng`

Telnet is just a communication protocol, and as such can be easily switched to another port by an attacker. Keeping an eye on these strange port communications can allow us to find potentially malicious actions. Lets take the following for instance.

![Wireshark capture showing TCP traffic between 192.168.10.5 and 192.168.10.7, with sequence and acknowledgment details.](https://academy.hackthebox.com/storage/modules/229/3-telnet.png)

We may see a ton of communications from one client on port 9999. We can dive into this a little further by looking at the contents of these communications.

![Hex dump showing data with ASCII translation, including the text 'Telnet' followed by exclamation marks.](https://academy.hackthebox.com/storage/modules/229/4-telnet.png)

If we noticed something like above, we would want to follow this TCP stream.

![Wireshark TCP stream showing Telnet data with message: 'telnet!!!!!!!! exfil this why do we exfil? HTB{telnet tunnel pls and thank you}'.](https://academy.hackthebox.com/storage/modules/229/5-telnet.png)

Doing so can allow us to inspect potentially malicious actions.

---

## Telnet Protocol through IPv6

**Related PCAP File(s)**:

- `telnet_tunneling_ipv6.pcapng`

After all, unless our local network is configured to utilize IPv6, observing IPv6 traffic can be an indicator of bad actions within our environment. We might notice the usage of IPv6 addresses for telnet like the following.

![Wireshark capture showing Telnet and TCP traffic between IPv6 addresses, with sequence and acknowledgment details, including ICMPv6 neighbor solicitation and advertisement.](https://academy.hackthebox.com/storage/modules/229/6-telnet.png)

We can narrow down our filter in Wireshark to only show telnet traffic from these addresses with the following filter.

- `((ipv6.src_host == fe80::c9c8:ed3:1b10:f10b) or (ipv6.dst_host == fe80::c9c8:ed3:1b10:f10b)) and telnet`

![Wireshark capture showing Telnet traffic between IPv6 addresses, with consistent Telnet data packets.](https://academy.hackthebox.com/storage/modules/229/7-telnet.png)

Likewise, we can inspect the contents of these packets through their data field, or by following the TCP stream.

![Network packet details showing Telnet data from IPv6 address fe80::c9c8:ed3:1b10:f10b to fe80::46a8:5bff:fe95:682a, indicating Telnet tunneling capability.](https://academy.hackthebox.com/storage/modules/229/8-telnet.png)

## Watching UDP Communications

**Related PCAP File(s)**:

- `udp_tunneling.pcapng`

On the other hand, attackers might opt to use UDP connections over TCP in their exfiltration efforts.

![Diagram comparing TCP and UDP communication. TCP shows a three-way handshake with SYN, SYN-ACK, and ACK. UDP shows a simple request and multiple responses.](https://academy.hackthebox.com/storage/modules/229/udp-tcp.jpg)

One of the biggest distinguishing aspects between TCP and UDP is that UDP is connectionless and provides fast transmission. Let's take the following traffic for instance.

![Wireshark capture showing UDP traffic from 192.168.10.5 to 192.168.10.7, with consistent packet lengths and port numbers.](https://academy.hackthebox.com/storage/modules/229/1-udp.png)

We will notice that instead of a SYN, SYN/ACK, ACK sequence, the communications are immediately sent over to the recipient. Like TCP, we can follow UDP traffic in Wireshark, and inspect its contents.

![Wireshark UDP stream showing alphabet and numbers, with a message about UDP's suitability for exfiltration due to less monitoring compared to TCP.](https://academy.hackthebox.com/storage/modules/229/2-udp.png)

## Common Uses of UDP

UDP although less reliable than TCP provides quicker connections through its connectionless state. As such, we might find legitimate traffic that uses UDP like the following:

|**Step**|**Description**|
|---|---|
|`1. Real-time Applications`|Applications like streaming media, online gaming, real-time voice and video communications|
|`2. DNS (Domain Name System)`|DNS queries and responses use UDP|
|`3. DHCP (Dynamic Host Configuration Protocol)`|DHCP uses UDP to assign IP addresses and configuration information to network devices.|
|`4. SNMP (Simple Network Management Protocol)`|SNMP uses UDP for network monitoring and management|
|`5. TFTP (Trivial File Transfer Protocol)`|TFTP uses UDP for simple file transfers, commonly used by older Windows systems and others.|