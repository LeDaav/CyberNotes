
Addressing rogue access points and evil-twin attacks can seem like a gargantuan task due to their often elusive nature. Nevertheless, with the appropriate strategies in place, these illegitimate access points can be detected and managed effectively. In the realm of malevolent access points, rogue and evil-twin attacks invariably surface as significant concerns.

![Diagram showing an Attacker PC connecting to HTB-Wireless (Open), which connects to a Router. HTB-Wireless (WPA2) also connects to the Router.](https://academy.hackthebox.com/storage/modules/229/rogueap.png)

A rogue access point primarily serves as a tool to circumvent perimeter controls in place. An adversary might install such an access point to sidestep network controls and segmentation barriers, which could, in many cases, take the form of hotspots or tethered connections. These rogue points have even been known to infiltrate air-gapped networks. Their primary function is to provide unauthorized access to restricted sections of a network. The critical point to remember here is that rogue access points are directly connected to the network.

---

## Evil-Twin

An evil-twin on the other hand is spun up by an attacker for many other different purposes. The key here, is that in most cases these access points are not connected to our network. Instead, they are standalone access points, which might have a web server or something else to act as a man-in-the-middle for wireless clients.

![Diagram showing an Attacker PC performing a deauthentication attack on a Victim PC connected to HTB-Wireless (Open). HTB-Wireless (WPA2) connects to a Router.](https://academy.hackthebox.com/storage/modules/229/evil-twin.png)

Attackers might set these up to harvest wireless or domain passwords among other pieces of information. Commonly, these attacks might also encompass a hostile portal attack.

## Airodump-ng Detection

Right away, we could utilize the ESSID filter for Airodump-ng to detect Evil-Twin style access points.

  Rogue Access Point & Evil-Twin Attacks

```shell-session
LeDaav@htb[/htb]$ sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw

 CH  4 ][ Elapsed: 1 min ][ 2023-07-13 16:06    
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
 F8:14:FE:4D:E6:F2   -7 100      470      155    0   4   54   OPN              HTB-Wireless
 F8:14:FE:4D:E6:F1   -5  96      682        0    0   4  324   WPA2 CCMP   PSK  HTB-Wireless 
```

The above example would show that in fact an attacker might have spun up an open access point that has an identical ESSID as our access point. An attacker might do this to host what is commonly referred to as a hostile portal attack. A hostile portal attack is used by attackers in order extract credentials from users among other nefarious actions.

We might also want to be vigilant about deauthentication attempts, which could suggest enforcement measures from the attacker operating the evil-twin access point.

To conclusively ascertain whether this is an anomaly or an Airodump-ng error, we can commence our traffic analysis efforts (`rogueap.cap`). To filter for beacon frames, we could use the following.

- `(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)`

![Wireshark capture showing 802.11 beacon frames. Source: Unionman_4d:e6:f1 and Unionman_4d:e6:f2, Destination: Broadcast. SSID: HTB-Wireless, with sequence numbers and flags.](https://academy.hackthebox.com/storage/modules/229/1-evil-twin.png)

Beacon analysis is crucial in differentiating between genuine and fraudulent access points. One of the initial places to start is the `Robust Security Network (RSN)` information. This data communicates valuable information to clients about the supported ciphers, among other things.

Suppose we wish to examine our legitimate access point's RSN information.

![Wireshark capture showing IEEE 802.11 Wireless Management details. SSID: HTB-Wireless, supported rates, current channel: 4, country code: US. RSN Information includes cipher suites TKIP, AES, and PSK.](https://academy.hackthebox.com/storage/modules/229/2-evil-twin.png)

It would indicate that WPA2 is supported with AES and TKIP with PSK as its authentication mechanism. However, when we switch to the illegitimate access point's RSN information, we may find it conspicuously missing.

![Wireshark capture showing IEEE 802.11 beacon frame. SSID: HTB-Wireless, supported rates, current channel: 4, and traffic indication map details.](https://academy.hackthebox.com/storage/modules/229/3-evil-twin.png)

In most instances, a standard evil-twin attack will exhibit this characteristic. Nevertheless, we should always probe additional fields for discrepancies, particularly when dealing with more sophisticated evil-twin attacks. For example, an attacker might employ the same cipher that our access point uses, making the detection of this attack more challenging.

Under such circumstances, we could explore other aspects of the beacon frame, such as vendor-specific information, which is likely absent from the attacker's access point.

## Finding a Fallen User

Despite comprehensive security awareness training, some users may fall prey to attacks like these. Fortunately, in the case of open network style evil-twin attacks, we can view most higher-level traffic in an unencrypted format. To filter exclusively for the evil-twin access point, we would employ the following filter.

- `(wlan.bssid == F8:14:FE:4D:E6:F2)`

![Wireshark capture showing 802.11 authentication and association frames between Unionman_4d:e6:f2 and IntelCor_af:eb:91. Includes ARP probes asking 'Who has 169.254.63.254?' sent to Broadcast.](https://academy.hackthebox.com/storage/modules/229/4-evil-twin.png)

If we detect ARP requests emanating from a client device connected to the suspicious network, we would identify this as a potential compromise indicator. In such instances, we should record pertinent details about the client device to further our incident response efforts.

1. `Its MAC address`
2. `Its host name`

Consequently, we might be able to instigate password resets and other reactive measures to prevent further infringement of our environment.

## Finding Rogue Access Points

On the other hand, detecting rogue access points can often be a simple task of checking our network device lists. In the case of hotspot-based rogue access points (such as Windows hotspots), we might scrutinize wireless networks in our immediate vicinity. If we encounter an unrecognizable wireless network with a strong signal, particularly if it lacks encryption, this could indicate that a user has established a rogue access point to navigate around our perimeter controls.