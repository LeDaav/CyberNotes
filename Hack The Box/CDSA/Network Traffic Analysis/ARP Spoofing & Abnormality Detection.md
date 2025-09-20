
The `Address Resolution Protocol (ARP)` has been a longstanding utility exploited by attackers to launch man-in-the-middle and denial-of-service attacks, among others. Given this prevalence, ARP forms a focal point when we undertake traffic analysis, often being the first protocol we scrutinize. Many ARP-based attacks are broadcasted, not directed specifically at hosts, making them more readily detectable through our packet sniffing techniques.

## How Address Resolution Protocol Works

Before identifying ARP anomalies, we need to first comprehend how this protocol functions in its standard, or 'vanilla', operation.

![Diagram of ARP process: Device 192.168.0.1 sends ARP request asking 'Who is 192.168.0.4?' to broadcast address. Device 192.168.0.4 replies with its MAC address to 192.168.0.1. Other devices 192.168.0.3 and 192.168.0.5 are also shown.](https://academy.hackthebox.com/storage/modules/229/ARP-protocol.png)

In our network, hosts must know the physical address (MAC address) to which they must send their data. This need gave birth to ARP. Let's elucidate this with a step-by-step process.

|**Step**|**Description**|
|---|---|
|`1`|Imagine our first computer, or Host A, needs to send data to our second computer, Host B. To achieve successful transmission, Host A must ascertain the physical address of Host B.|
|`2`|Host A begins by consulting its list of known addresses, the ARP cache, to check if it already possesses this physical address.|
|`3`|In the event the address corresponding to the desired IP isn't in the ARP cache, Host A broadcasts an ARP request to all machines in the subnet, inquiring, "Who holds the IP x.x.x.x?"|
|`4`|Host B responds to this message with an ARP reply, "Hello, Host A, my IP is x.x.x.x and is mapped to MAC address aa:aa:aa:aa:aa:aa."|
|`5`|On receiving this response, Host A updates its ARP cache with the new IP-to-MAC mapping.|
|`6`|Occasionally, a host might install a new interface, or the IP address previously allocated to the host might expire, necessitating an update and remapping of the ARP cache. Such instances could introduce complications when we analyze our network traffic.|

---

## ARP Poisoning & Spoofing

In an ideal scenario, robust controls would be in place to thwart these attacks, but in reality, this isn't always feasible. To comprehend our Indicators of Compromise (IOCs) more effectively, let's delve into the behavior of ARP Poisoning and Spoofing attacks.

![Diagram showing ARP communication: Device 192.168.0.5 with MAC bb:bb:bb:bb:bb:bb connects to 192.168.0.1. Device 192.168.0.8 with MAC cc:cc:cc:cc:cc:cc connects to 192.168.0.1 with MAC aa:aa:aa:aa:aa:aa.](https://academy.hackthebox.com/storage/modules/229/ARP-spoofing-poisoning.png)

Detecting these attacks can be challenging, as they mimic the communication structure of standard ARP traffic. Yet, certain ARP requests and replies can reveal their nefarious nature. Let's illustrate how these attacks function, enabling us to better identify them during our traffic analysis.

|**Step**|**Description**|
|---|---|
|`1`|Consider a network with three machines: the victim's computer, the router, and the attacker's machine.|
|`2`|The attacker initiates their ARP cache poisoning scheme by dispatching counterfeit ARP messages to both the victim's computer and the router.|
|`3`|The message to the victim's computer asserts that the gateway's (router's) IP address corresponds to the physical address of the attacker's machine.|
|`4`|Conversely, the message to the router claims that the IP address of the victim's machine maps to the physical address of the attacker's machine.|
|`5`|On successfully executing these requests, the attacker may manage to corrupt the ARP cache on both the victim's machine and the router, causing all data to be misdirected to the attacker's machine.|
|`6`|If the attacker configures traffic forwarding, they can escalate the situation from a denial-of-service to a man-in-the-middle attack.|
|`7`|By examining other layers of our network model, we might discover additional attacks. The attacker could conduct DNS spoofing to redirect web requests to a bogus site or perform SSL stripping to attempt the interception of sensitive data in transit.|

Detecting these attacks is one aspect, but averting them is a whole different challenge. We could potentially fend off these attacks with controls such as:

1. `Static ARP Entries`: By disallowing easy rewrites and poisoning of the ARP cache, we can stymie these attacks. This, however, necessitates increased maintenance and oversight in our network environment.
    
2. `Switch and Router Port Security`: Implementing network profile controls and other measures can ensure that only authorized devices can connect to specific ports on our network devices, effectively blocking machines attempting ARP spoofing/poisoning.
    

---

## Installing & Starting TCPDump

To effectively capture this traffic, especially in the absence of configured network monitoring software, we can employ tools like `tcpdump` and `Wireshark`, or simply `Wireshark` for Windows hosts.

We can typically find `tcpdump` located in `/usr/sbin/tcpdump`. However, if the tool isn't installed, it can be installed using the appropriate command, which will be provided based on the specific system requirements.

#### TCPDump

  ARP Spoofing & Abnormality Detection

```shell-session
LeDaav@htb[/htb]$ sudo apt install tcpdump -y
```

To initiate the traffic capture, we can employ the command-line tool `tcpdump`, specifying our network interface with the `-i` switch, and dictating the name of the output capture file using the `-w` switch.

  ARP Spoofing & Abnormality Detection

```shell-session
LeDaav@htb[/htb]$ sudo tcpdump -i eth0 -w filename.pcapng
```

## Finding ARP Spoofing

For detecting ARP Spoofing attacks, we'll need to open the related traffic capture file (`ARP_Spoof.pcapng`) from this module's resources using Wireshark.

  ARP Spoofing & Abnormality Detection

```shell-session
LeDaav@htb[/htb]$ wireshark ARP_Spoof.pcapng
```

Once we've navigated to Wireshark, we can streamline our view to focus solely on ARP requests and replies by employing the filter `arp.opcode`.

![Wireshark capture showing ARP requests and replies. Source: PcsCompu_53:0c:ba, Destination: Broadcast and Netgear_e2:d5:c3. Protocol: ARP. Info includes 'Who has 192.168.10.4?' and '192.168.10.4 is at 08:00:27:53:0c:ba'.](https://academy.hackthebox.com/storage/modules/229/ARP_Spoof_1.png)

A key red flag we need to monitor is any anomaly in traffic emanating from a specific host. For instance, one host incessantly broadcasting ARP requests and replies to another host could be a telltale sign of ARP spoofing.

In such a scenario, we might identify that the MAC address `08:00:27:53:0C:BA is behaving suspiciously`.

To ascertain this, we can fine-tune our analysis to inspect solely the interactions—both requests and replies—among the attacker's machine, the victim's machine, and the router. The opcode functionality in `Wireshark` can simplify this process.

1. `Opcode == 1`: This represents all types of ARP Requests
2. `Opcode == 2`: This signifies all types of ARP Replies

As a preliminary step, we could scrutinize the requests dispatched using the following filter.

- `arp.opcode == 1`

![Wireshark capture showing ARP requests. Source: PcsCompu_53:0c:ba and ASUSTeK_ec:0e:7f, both to Broadcast. Protocol: ARP. Info includes 'Who has 192.168.10.4?' and 'Who has 192.168.10.1? (duplicate use detected)'.](https://academy.hackthebox.com/storage/modules/229/ARP_Spoof_2.png)

Almost instantly, we should notice a red flag - an address duplication, accompanied by a warning message. If we delve into the details of the error message within Wireshark, we should be able to extract additional information.

![Wireshark capture showing ARP request with duplicate IP address detection for 192.168.10.4. Source: ASUSTeK_ec:0e:7f, Destination: Broadcast. Duplicate use detected by 08:00:27:53:0c:ba.](https://academy.hackthebox.com/storage/modules/229/ARP_Spoof_3.png)

Upon immediate inspection, we might discern that one IP address is mapped to two different MAC addresses. We can validate this on a Linux system by executing the appropriate commands.

#### ARP

  ARP Spoofing & Abnormality Detection

```shell-session
LeDaav@htb[/htb]$ arp -a | grep 50:eb:f6:ec:0e:7f

? (192.168.10.4) at 50:eb:f6:ec:0e:7f [ether] on eth0
```

  ARP Spoofing & Abnormality Detection

```shell-session
LeDaav@htb[/htb]$ arp -a | grep 08:00:27:53:0c:ba

? (192.168.10.4) at 08:00:27:53:0c:ba [ether] on eth0
```

In this situation, we might identify that our ARP cache, in fact, contains both MAC addresses allocated to the same IP address - an anomaly that warrants our immediate attention.

To sift through more duplicate records, we can utilize the subsequent Wireshark filter.

- `arp.duplicate-address-detected && arp.opcode == 2`

---

## Identifying The Original IP Addresses

A crucial question we need to pose is, what were the initial IP addresses of these devices? Understanding this aids us in determining which device altered its IP address through MAC spoofing. After all, if this attack was exclusively performed via ARP, the victim machine's IP address should remain consistent. Conversely, the attacker's machine might possess a different historical IP address.

We can unearth this information within an ARP request and expedite the discovery process using this Wireshark filter.

- `(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))`

![Wireshark capture showing ARP request details. Source: PcsCompu_53:0c:ba, Destination: Broadcast. Sender IP: 192.168.10.5, Target IP: 192.168.10.4.](https://academy.hackthebox.com/storage/modules/229/ARP_Spoof_4.png)

In this case, we might instantly note that the MAC address `08:00:27:53:0c:ba` was initially linked to the IP address `192.168.10.5`, but this was recently switched to `192.168.10.4`. This transition is indicative of a deliberate attempt at ARP spoofing or cache poisoning.

Additionally, examining the traffic from these MAC addresses with the following Wireshark filter can prove insightful:

- `eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba`

![Wireshark capture showing TCP and ARP packets. TCP packets involve IPs 204.79.197.254 and 192.168.10.4 with various flags. ARP requests from PcsCompu_53:0c:ba and ASUSTeK_ec:0e:7f to Broadcast, detecting duplicate IP use.](https://academy.hackthebox.com/storage/modules/229/ARP_Spoof_5.png)

Right off the bat, we might notice some inconsistencies with TCP connections. If TCP connections are consistently dropping, it's an indication that the attacker is not forwarding traffic between the victim and the router.

If the attacker is, in fact, forwarding the traffic and is operating as a man-in-the-middle, we might observe identical or nearly symmetrical transmissions from the victim to the attacker and from the attacker to the router.