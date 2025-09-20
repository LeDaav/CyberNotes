
Unfortunately, TCP does not provide the level of protection to prevent our hosts from having their connections terminated or hijacked by an attacker. As such, we might notice that a connection gets terminated by an RST packet, or hijacked through connection hijacking.

## TCP Connection Termination

Suppose an adversary wanted to cause denial-of-service conditions within our network. They might employ a simple TCP RST Packet injection attack, or TCP connection termination in simple terms.

This attack is a combination of a few conditions:

1. `The attacker will spoof the source address to be the affected machine's`
    
2. `The attacker will modify the TCP packet to contain the RST flag to terminate the connection`
    
3. `The attacker will specify the destination port to be the same as one currently in use by one of our machines.`
    

As such, we might notice an excessive amount of packets going to one port.

![Wireshark capture showing TCP RST packets from IP 192.168.10.4 to 192.168.10.1 on port 80](https://academy.hackthebox.com/storage/modules/229/1-RST.png)

One way we can verify that this is indeed a TCP RST attack is through the physical address of the transmitter of these TCP RST packets. Suppose, the IP address 192.168.10.4 is registered to aa:aa:aa:aa:aa:aa in our network device list, and we notice an entirely different MAC sending these like the following.

![Packet details showing Ethernet, IPv4, and TCP headers from 192.168.10.4 to 192.168.10.1, source port 2615, destination port 80](https://academy.hackthebox.com/storage/modules/229/2-RST.png)

This would indicate malicious activity within our network, and we could conclude that this is likely a TCP RST Attack. However, it is worth noting that an attacker might spoof their MAC address in order to further evade detection. In this case, we could notice retransmissions and other issues as we saw in the ARP poisoning section.

---

## TCP Connection Hijacking


For more advanced actors, they might employ TCP connection hijacking. In this case the attacker will actively monitor the target connection they want to hijack.

The attacker will then conduct sequence number prediction in order to inject their malicious packets in the correct order. During this injection they will spoof the source address to be the same as our affected machine.

The attacker will need to block ACKs from reaching the affected machine in order to continue the hijacking. They do this either through delaying or blocking the ACK packets. As such, this attack is very commonly employed with ARP poisoning, and we might notice the following in our traffic analysis.

![TCP retransmission packets from port 23 to 36212 with PSH, ACK flags.](https://academy.hackthebox.com/storage/modules/229/4-RST.png)