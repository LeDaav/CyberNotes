

Time-to-Live attacks are primarily utilized as a means of evasion by attackers. Basically speaking the attacker will intentionally set a very low TTL on their IP packets in order to attempt to evade firewalls, IDS, and IPS systems. These work like the following.

![Network diagram showing an attacker originating from a computer, passing through two routers with decreasing TTL values, reaching a destination computer with TTL 0.](https://academy.hackthebox.com/storage/modules/229/ttl-attack-diagram.png)

1. The attacker will craft an IP packet with an intentionally low TTL value (1, 2, 3 and so on).
    
2. Through each host that this packet passes through this TTL value will be decremented by one until it reaches zero.
    
3. Upon reaching zero this packet will be discarded. The attacker will try to get this packet discarded before it reaches a firewall or filtering system to avoid detection/controls.
    
4. When the packets expire, the routers along the path generate ICMP Time Exceeded messages and send them back to the source IP address.
    

#### Finding Irregularities in IP TTL

For starters, we can begin to dump our traffic and open it in Wireshark. Detecting this in small amounts can be difficult, but fortunately for us attackers will most times utilize ttl manipulation in port scanning efforts. Right away we might notice something like the following.

![Wireshark capture showing TCP SYN packets from IP 192.168.10.5 to 192.168.10.1 on port 80](https://academy.hackthebox.com/storage/modules/229/1-ttl.png)

However, we might also notice a returned SYN, ACK message from one of our legitimate service ports on our affected host. In doing so, the attacker might have successfully evaded one of our firewall controls.

![Wireshark capture showing TCP SYN packets from IP 192.168.10.5 to 192.168.10.1 on port 80, followed by a SYN-ACK response.](https://academy.hackthebox.com/storage/modules/229/2-ttl.png)

So, if we were to open one of these packets, we could realistically see why this is. Suppose we opened the IPv4 tab in Wireshark for any of these packets. We might notice a very low TTL like the following.

![Packet details showing IPv4 from 192.168.10.5 to 192.168.10.1, protocol TCP, TTL 3.](https://academy.hackthebox.com/storage/modules/229/3-ttl.png)

As such, we can implement a control which discards or filters packets that do not have a high enough TTL. In doing so, we can prevent these forms of IP packet crafting attacks.