
There are many cases where we might see irregular traffic for IPv4 and IPv6 packets. In many such cases, this might be done through the source and destination IP fields. We should always consider the following when analyzing these fields for our traffic analysis efforts.

1. `The Source IP Address should always be from our subnet` - If we notice that an incoming packet has an IP source from outside of our local area network, this can be an indicator of packet crafting.
    
2. `The Source IP for outgoing traffic should always be from our subnet` - If the source IP is from a different IP range than our own local area network, this can be an indicator of malicious traffic that is originating from inside our network.
    

An attacker might conduct these packet crafting attacks towards the source and destination IP addresses for many different reasons or desired outcomes. Here are a few that we can look for:

1. `Decoy Scanning` - In an attempt to bypass firewall restrictions, an attacker might change the source IP of packets to enumerate further information about a host in another network segment. Through changing the source to something within the same subnet as the target host, the attacker might succeed in firewall evasion.
    
2. `Random Source Attack DDoS` - Through random source crafting an attacker might be able to send tons of traffic to the same port on the victim host. This in many cases, is used to exhaust resources of our network controls or on the destination host.
    
3. `LAND Attacks` - LAND Attacks operate similarly to Random Source denial-of-service attacks in the nature that the source address is set to the same as the destination hosts. In doing so the attacker might be able to exhaust network resources or cause crashes on the target host.
    
4. `SMURF Attacks` - Similar to LAND and Random Source attacks, SMURF attacks work through the attacker sending large amounts of ICMP packets to many different hosts. However, in this case the source address is set to the victim machines, and all of the hosts which receive this ICMP packet respond with an ICMP reply causing resource exhaustion on the crafted source address (victim).
    
5. `Initialization Vector Generation` - In older wireless networks such as wired equivalent privacy, an attacker might capture, decrypt, craft, and re-inject a packet with a modified source and destination IP address in order to generate initialization vectors to build a decryption table for a statistical attack. These can be seen in nature by noticing an excessive amount of repeated packets between hosts.
    

It is important to note, that unlike ARP poisoning, the attacks we will be exploring in this section derive from IP layer communications and not ARP poisoning necessarily. However, these attacks tend to be conducted in tandem for most nefarious activities.

---

## Finding Decoy Scanning Attempts


Simply put, when an attacker wants to gather information, they might change their source address to be the same as another legitimate host, or in some cases entirely different from any real host. This is to attempt to evade IDS/Firewall controls, and it can be easily observed.

In the case of decoy scanning, we will notice some strange behavior.

1. `Initial Fragmentation from a fake address`
2. `Some TCP traffic from the legitimate source address`

![Wireshark capture showing network traffic between IP 192.168.10.5 and 0.0.0.10, including ICMP echo requests, TCP SYN and ACK packets, and fragmented IPv4 protocols.](https://academy.hackthebox.com/storage/modules/229/1-decoy.png)

Secondarily, in this attack the attacker might be attempting to cloak their address with a decoy, but the responses for multiple closed ports will still be directed towards them with the RST flags denoted for TCP.

![Wireshark capture showing network traffic between IP 192.168.10.4 and 192.168.10.1, including TCP RST, ACK, and SYN packets, and fragmented IPv4 protocols.](https://academy.hackthebox.com/storage/modules/229/2-decoy.png)

We will definitely notice this in the case of a large port block which has no services running on the victim host.

![Wireshark capture showing TCP traffic between IP 192.168.10.1 and 192.168.10.5, including RST, ACK, and SYN packets.](https://academy.hackthebox.com/storage/modules/229/3-decoy.png)

As such, another simple way that we can prevent this attack beyond just detecting it through our traffic analysis efforts is the following.

1. `Have our IDS/IPS/Firewall act as the destination host would` - In the sense that reconstructing the packets gives a clear indication of malicious activity.
    
2. `Watch for connections started by one host, and taken over by another` - The attacker after all has to reveal their true source address in order to see that a port is open. This is strange behavior and we can define our rules to prevent it.
    

## Finding Random Source Attacks



On the opposite side of things, we can begin to explore denial-of-service attacks through source and destination address spoofing. One of the primary and notable examples is random source attacks. These can be conducted in many different flavors. However, notably this can be done like the opposite of a SMURF attack, in which many hosts will ping one host which does not exist, and the pinged host will ping back all others and get no reply.

![Wireshark capture showing ICMP echo replies from IP 192.168.10.5 to various destinations.](https://academy.hackthebox.com/storage/modules/229/1-random-source.png)

We should also consider that attackers might fragment these random hosts communications in order to draw out more resource exhaustion.

![Wireshark capture showing fragmented IPv4 and ICMP echo reply traffic between IP 192.168.10.5 and 111.43.91.100](https://academy.hackthebox.com/storage/modules/229/2-random-source.png)

However in many cases, like LAND attacks, these attacks will be used by attackers to exhaust resources to one specific service on a port. Instead of spoofing the source address to be the same as the destination, the attacker might randomize them. We might notice the following.

![Wireshark capture showing TCP SYN packets from various sources to IP 192.168.10.1 on port 80.](https://academy.hackthebox.com/storage/modules/229/3-random-source.png)

In this case, we have a few indicators of nefarious behavior:

1. `Single Port Utilization from random hosts`
2. `Incremental Base Port with a lack of randomization`
3. `Identical Length Fields`

In many real world cases, like a web server, we may have many different users utilizing the same port. However, these requests are contrary of our indicators. Such that they will have different lengths and the base ports will not exhibit this behavior.

## Finding Smurf Attacks

SMURF Attacks are a notable distributed denial-of-service attack, in the nature that they operate through causing random hosts to ping the victim host back. Simply put, an attacker conducts these like the following:

1. `The attacker will send an ICMP request to live hosts with a spoofed address of the victim host`
    
2. `The live hosts will respond to the legitimate victim host with an ICMP reply`
    
3. `This may cause resource exhaustion on the victim host`
    

One of the things we can look for in our traffic behavior is an excessive amount of ICMP replies from a single host to our affected host. Sometimes attackers will include fragmentation and data on these ICMP requests to make the traffic volume larger.

![Wireshark capture showing fragmented IPv4 and ICMP echo request traffic between IP 192.168.10.5 and 192.168.10.1](https://academy.hackthebox.com/storage/modules/229/1-SMURF.png)

We might notice many different hosts pinging our single host, and in this case it represents the basic nature of SMURF attacks.

![Wireshark capture showing ICMP echo requests and replies between IP 10.174.15.16 and 10.174.15.19, with some requests having no response](https://academy.hackthebox.com/storage/modules/229/smurf.png)

**Image From**: [https://techofide.com/blogs/what-is-smurf-attack-what-is-the-denial-of-service-attack-practical-ddos-attack-step-by-step-guide/](https://techofide.com/blogs/what-is-smurf-attack-what-is-the-denial-of-service-attack-practical-ddos-attack-step-by-step-guide/)

## Finding LAND Attacks


LAND attacks operate through an attacker spoofing the source IP address to be the same as the destination. These denial-of-service attacks work through sheer volume of traffic and port re-use. Essentially, if all base ports are occupied, it makes real connections much more difficult to establish to our affected host.

![Wireshark capture showing TCP SYN packets from IP 192.168.10.1 to 192.168.10.1 on port 80.](https://academy.hackthebox.com/storage/modules/229/1-LAND.png)