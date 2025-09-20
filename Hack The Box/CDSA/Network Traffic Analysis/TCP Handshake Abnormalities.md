
Innately, when attackers are gaining information on our TCP services, we might notice a few odd behaviors during our traffic analysis efforts. Firstly, let's consider how normal TCP connections work with their 3-way handshake.

![Diagram showing TCP three-way handshake: Client sends SYN to Server, Server replies with SYN/ACK, Client sends ACK.](https://academy.hackthebox.com/storage/modules/229/tcp_handshake_1.jpg)

To initiate a TCP connection for whatever purpose the client first sends the machine it is attempting to connect to a TCP SYN request to begin the TCP connection.

If this port is open, and in fact able to be connected to, the machine responds with a TCP SYN/ACK to acknowledge that the connection is valid and able to be used. However, we should consider all TCP flags.

|**Flags**|**Description**|
|---|---|
|`URG (Urgent)`|This flag is to denote urgency with the current data in stream.|
|`ACK (Acknowledgement)`|This flag acknowledges receipt of data.|
|`PSH (Push)`|This flag instructs the TCP stack to immediately deliver the received data to the application layer, and bypass buffering.|
|`RST (Reset)`|This flag is used for termination of the TCP connection (we will dive into hijacking and RST attacks soon).|
|`SYN (Synchronize)`|This flag is used to establish an initial connection with TCP.|
|`FIN (Finish)`|This flag is used to denote the finish of a TCP connection. It is used when no more data needs to be sent.|
|`ECN (Explicit Congestion Notification)`|This flag is used to denote congestion within our network, it is to let the hosts know to avoid unnecessary re-transmissions.|

As such, when we are performing our traffic analysis efforts we can look for the following strange conditions:

1. `Too many flags of a kind or kinds` - This could show us that scanning is occurring within our network.
    
2. `The usage of different and unusual flags` - Sometimes this could indicate a TCP RST attack, hijacking, or simply some form of control evasion for scanning.
    
3. `Solo host to multiple ports, or solo host to multiple hosts` - Easy enough, we can find scanning as we have done before by noticing where these connections are going from one host. In a lot of cases, we may even need to consider decoy scans and random source attacks.
    

## Excessive SYN Flags

**Related PCAP File(s)**:

- `nmap_syn_scan.pcapng`

Right away one of the traffic patterns that we can notice is too many SYN flags. This is a prime example of nmap scanning. Simply put, the adversary will send TCP SYN packets to the target ports. In the case where our port is open, our machine will respond with a SYN-ACK packet to continue the handshake, which will then be met by an RST from the attackers scanner. However, we can get lost in the RSTs here as our machine will respond with RST for closed ports.

![Wireshark capture showing TCP SYN and RST, ACK packets between IP 192.168.10.5 and 192.168.10.1 on port 80.](https://academy.hackthebox.com/storage/modules/229/1-TCPhandshake.png)

However it is worth noting that there are two primary scan types we might detect that use the SYN flag. These are:

1. `SYN Scans` - In these scans the behavior will be as we see, however the attacker will pre-emptively end the handshake with the RST flag.
    
2. `SYN Stealth Scans` - In this case the attacker will attempt to evade detection by only partially completing the TCP handshake.
    

## No Flags

**Related PCAP File(s)**:

- `nmap_null_scan.pcapng`

On the opposite side of things, the attacker might send no flags. This is what is commonly referrred to as a NULL scan. In a NULL scan an attacker sends TCP packets with no flags. TCP connections behave like the following when a NULL packet is received.

1. `If the port is open` - The system will not respond at all since there is no flags.
    
2. `If the port is closed` - The system will respond with an RST packet.
    

As such a NULL scan might look like the following.

![Wireshark capture showing TCP packets from IP 192.168.10.5 to 192.168.10.1, with various sequence numbers and ports.](https://academy.hackthebox.com/storage/modules/229/2-TCPhandshake.png)

## Too Many ACKs

**Related PCAP File(s)**:

- `nmap_ack_scan.pcapng`

On the other hand, we might notice an excessive amount of acknowledgements between two hosts. In this case the attacker might be employing the usage of an ACK scan. In the case of an ACK scan TCP connections will behave like the following.

1. `If the port is open` - The affected machine will either not respond, or will respond with an RST packet.
    
2. `If the port is closed` - The affected machine will respond with an RST packet.
    

So, we might see the following traffic which would indicate an ACK scan.

![Wireshark capture showing TCP ACK and RST packets between IP 192.168.10.5 and 192.168.10.1](https://academy.hackthebox.com/storage/modules/229/3-TCPhandshake.png)

## Excessive FINs

**Related PCAP File(s)**:

- `nmap_fin_scan.pcapng`

Using another part of the handshake, an attacker might utilize a FIN scan. In this case, all TCP packets will be marked with the FIN flag. We might notice the following behavior from our affected machine.

1. `If the port is open` - Our affected machine simply will not respond.
    
2. `If the port is closed` - Our affected machine will respond with an RST packet.
    

![Wireshark capture showing TCP FIN, RST, and ACK packets between IP 192.168.10.5 and 192.168.10.1](https://academy.hackthebox.com/storage/modules/229/4-TCPhandshake.png)

## Just too many flags

**Related PCAP File(s)**:

- `nmap_xmas_scan.pcapng`

Let's say the attacker just wanted to throw spaghetti at the wall. In that case, they might utilize a Xmas tree scan, which is when they put all TCP flags on their transmissions. Similarly, our affected host might respond like the following when all flags are set.

1. `If the port is open` - The affected machine will not respond, or at least it will with an RST packet.
    
2. `If the port is closed` - The affected machine will respond with an RST packet.
    

Xmas tree scans are pretty easy to spot and look like the following.

![Wireshark capture showing TCP FIN, PSH, URG, RST, and ACK packets between IP 192.168.10.5 and 192.168.10.1](https://academy.hackthebox.com/storage/modules/229/5-TCPhandshake.png)