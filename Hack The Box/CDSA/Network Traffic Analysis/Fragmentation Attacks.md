
When we begin to look for network anomalies, we should always consider the IP layer. Simply put, the IP layer functions in its ability to transfer packets from one hop to another. This layer uses source and destination IP addresses for inter-host communications. When we examine this traffic, we can identify the IP addresses as they exist within the IP header of the packet.

However, it is essential to note that this layer has no mechanisms to identify when packets are lost, dropped, or otherwise tampered with. Instead, we need to recognize that these mishaps are handled by the transport or application layers for this data. To dissect these packets, we can explore some of their fields:

1. `Length - IP header length`: This field contains the overall length of the IP header.
2. `Total Length - IP Datagram/Packet Length`: This field specifies the entire length of the IP packet, including any relevant data.
3. `Fragment Offset`: In many cases when a packet is large enough to be divided, the fragmentation offset will be set to provide instructions to reassemble the packet upon delivery to the destination host.
4. `Source and Destination IP Addresses`: These fields contain the origination (source) and destination IP addresses for the two communicating hosts.

![Diagram of an IPv4 header showing fields: Version, Length, Type of Service, Total Length, Identifier, Flags, Fragmented Offset, Time to Live, Protocol, Header Checksum, Source IP Address, Destination IP Address, Options and Padding.](https://academy.hackthebox.com/storage/modules/229/IPheader.jpg)

## Commonly Abused Fields

Innately, attackers might craft these packets to cause communication issues. Traditionally, an attacker might attempt to evade IDS controls through packet malformation or modification. As such, diving into each one of these fields and understanding how we can detect their misuse will equip us with the tools to succeed in our traffic analysis efforts.

## Abuse of Fragmentation

Fragmentation serves as a means for our legitimate hosts to communicate large data sets to one another by splitting the packets and reassembling them upon delivery. This is commonly achieved through setting a maximum transmission unit (MTU). The MTU is used as the standard to divide these large packets into equal sizes to accommodate the entire transmission. It is worth noting that the last packet will likely be smaller. This field gives instructions to the destination host on how it can reassemble these packets in logical order.

Commonly, attackers might abuse this field for the following purposes:

1. `IPS/IDS Evasion` - Let's say for instance that our intrusion detection controls do not reassemble fragmented packets. Well, for short, an attacker could split their nmap or other enumeration techniques to be fragmented, and as such it could bypass these controls and be reassembled at the destination.
    
2. `Firewall Evasion` - Through fragmentation, an attacker could likewise evade a firewall's controls through fragmentation. Once again, if the firewall does not reassemble these packets before delivery to the destination host, the attacker's enumeration attempt might succeed.
    
3. `Firewall/IPS/IDS Resource Exhaustion` - Suppose an attacker were to craft their attack to fragment packets to a very small MTU (10, 15, 20, and so on), the network control might not reassemble these packets due to resource constraints, and the attacker might succeed in their enumeration efforts.
    
4. `Denial of Service` - For old hosts, an attacker might utilize fragmentation to send IP packets exceeding 65535 bytes through ping or other commands. In doing so, the destination host will reassemble this malicious packet and experience countless different issues. As such, the resultant condition is successful denial-of-service from the attacker.
    

If our network mechanism were to perform correctly. It should do the following:

- `Delayed Reassembly` - The IDS/IPS/Firewall should act the same as the destination host, in the sense that it waits for all fragments to arrive to reconstruct the transmission to perform packet inspection.

## Finding Irregularities in Fragment Offsets

In order to better understand the abovementioned mechanics, we can open the related traffic capture file in Wireshark.

  Fragmentation Attacks

```shell-session
LeDaav@htb[/htb]$ wireshark nmap_frag_fw_bypass.pcapng
```

For starters, we might notice several ICMP requests going to one host from another, this is indicative of the starting requests from a traditional Nmap scan. This is the beginning of the host discovery process. An attacker might run a command like this.

#### Attacker's Enumeration

  Fragmentation Attacks

```shell-session
LeDaav@htb[/htb]$ nmap <host ip>
```

In doing so, they will generate the following.

![Wireshark capture showing ICMP echo (ping) requests and replies between 192.168.10.5 and 192.168.10.1. Includes DNS queries and fragmented IP protocol entries.](https://academy.hackthebox.com/storage/modules/229/1-frag.png)

Secondarily, an attacker might define a maximum transmission unit size like this in order to fragment their port scanning packets.

  Fragmentation Attacks

```shell-session
LeDaav@htb[/htb]$ nmap -f 10 <host ip>
```

In doing so they will generate IP packets with a maximum size of 10. Seeing a ton of fragmentation from a host can be an indicator of this attack, and it would look like the following.

![Wireshark capture showing ICMP echo request from 192.168.10.5 to 0.0.0.10 with no response. Includes fragmented IPv4 and TCP packets with SYN and ACK flags.](https://academy.hackthebox.com/storage/modules/229/2-frag.png)

However, the more notable indicator of a fragmentation scan, regardless of its evasion use is the single host to many ports issues that it generates. Let's take the following for instance.

![Wireshark capture showing TCP packets between 192.168.10.5 and 192.168.10.1. Includes SYN, RST, and ACK flags, with fragmented IPv4 packets.](https://academy.hackthebox.com/storage/modules/229/3-frag.png)

In this case, the destination host would respond with RST flags for ports which do not have an active service running on them (aka closed ports). This pattern is a clear indication of a fragmented scan.

If our Wireshark is not reassembling packets for our inspection, we can make a quick change in our preferences for the IPv4 protocol.

![Wireshark preferences window for IPv4 settings. Options include decoding TOS field, reassembling fragmented datagrams, showing IPv4 summary, validating checksum, supporting packet capture, enabling geolocation, interpreting security flag, and heuristic sub-dissectors.](https://academy.hackthebox.com/storage/modules/229/4-frag.png)