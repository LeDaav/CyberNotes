
Tunneling is a technique employed by adversaries in order to exfiltrate data from one location to another. There are many different kinds of tunneling, and each different kind uses a different protocol. Commonly, attackers may utilize proxies to bypass our network controls, or protocols that our systems and controls allow.

## Basics of Tunneling

Essentially, when an attacker wants to communicate data to another host, they may employ tunneling. In many cases, we might notice this through the attacker possessing some command and control over one of our machines. As noted, tunneling can be conducted in many different ways. One of the more common types is SSH tunneling. However, proxy-based, HTTP, HTTPs, DNS, and other types can be observed in similar ways.

![Diagram showing SSH tunnel from localhost:9999 to instance web server on port 80 using SSH command.](https://academy.hackthebox.com/storage/modules/229/basic-tunnel-1.png)

The idea behind tunneling is that an attacker will be able to expand their command and control and bypass our network controls through the protocol of their choosing.

## ICMP Tunneling

In the case of ICMP tunneling an attacker will append data they want to exfiltrate to the outside world or another host in the data field in an ICMP request. This is done with the intention to hide this data among a common protocol type like ICMP, and hopefully get lost within our network traffic.

![Diagram showing Host A sending an Echo Request to Server, and Server sending an Echo Reply back.](https://academy.hackthebox.com/storage/modules/229/icmp_ping_example.jpg)

## Finding ICMP Tunneling

Since ICMP tunneling is primarily done through an attacker adding data into the data field for ICMP, we can find it by looking at the contents of data per request and reply.

![Wireshark capture showing ICMP echo requests and replies between IP 192.168.10.5 and 192.168.10.1, followed by fragmented IPv4 packets.](https://academy.hackthebox.com/storage/modules/229/1-ICMP-tunneling.png)

We can filter our wireshark capture to only ICMP requests and replies by entering ICMP into the filter bar.

![Wireshark capture showing ICMP echo requests and replies between IP 192.168.10.5 and 192.168.10.1](https://academy.hackthebox.com/storage/modules/229/2-ICMP-tunneling.png)

Suppose we noticed fragmentation occurring within our ICMP traffic as it is above, this would indicate a large amount of data being transferred via ICMP. In order to understand this behavior, we should look at a normal ICMP request. We may note that the data is something reasonable like 48 bytes.

![ICMP echo request packet details: Type 8, checksum correct, sequence number 256, timestamp July 17, 2023, data length 48 bytes.](https://academy.hackthebox.com/storage/modules/229/3-ICMP-tunneling.png)

However a suspicious ICMP request might have a large data length like 38000 bytes.

![ICMP echo request packet details: Type 8, checksum correct, sequence number 0, data length 38000 bytes.](https://academy.hackthebox.com/storage/modules/229/4-ICMP-tunneling.png)

If we would like to take a look at the data in transit, we can look on the right side of our screen in Wireshark. In this case, we might notice something like a Username and Password being pinged to an external or internal host. This is a direct indication of ICMP tunneling.

![Hex dump showing repeated patterns of "Username: root; Password: rd123$".](https://academy.hackthebox.com/storage/modules/229/5-ICMP-tunneling.png)

On the other hand, more advanced adversaries will utilize encoding or encryption when transmitting exfiltrated data, even in the case of ICMP tunneling. Suppose we noticed the following.

![Hex dump with repeated patterns of encoded text.](https://academy.hackthebox.com/storage/modules/229/6-ICMP-tunneling.png)

We could copy this value out of Wireshark and decode it within linux with the base64 utility.

  ICMP Tunneling

```shell-session
LeDaav@htb[/htb]$ echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
```

This would also be a case where ICMP tunneling is observed. In many cases, if the ICMP data length is larger than 48-bytes, we know something fishy is going on, and should always look into it.

## Preventing ICMP Tunneling

In order to prevent ICMP tunneling from occurring we can conduct the following actions.

1. `Block ICMP Requests` - Simply, if ICMP is not allowed, attackers will not be able to utilize it.
    
2. `Inspect ICMP Requests and Replies for Data` - Stripping data, or inspecting data for malicious content on these requests and replies can allow us better insight into our environment, and the ability to prevent this data exfiltration.