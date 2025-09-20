
## Connecting to the lab environment

Most of the hosts mentioned above are vulnerable to several attacks and live in an isolated network that can be accessed via the VPN. While on the VPN, a student can directly access the machines WS001 and/or Kali (depending on the section), which, as already mentioned, will act as initial foothold and attacker devices throughout the scenarios.

Below, you may find guidance (from a Linux host):

- How to connect to the Windows box WS001
- How to connect to the Kali box
- How to transfer files between WS001 and your Linux attacking machine

---

## Connect to WS001 via RDP

Once connected to the VPN, you may access the Windows machine via RDP. Most Linux flavors come with a client software, 'xfreerdp', which is one option to perform this RDP connection. To access the machine, we will use the user account Bob whose password is 'Slavi123'. To perform the connection execute the following command:

  Overview

```shell-session
LeDaav@htb[/htb]$ xfreerdp /u:eagle\\bob /p:Slavi123 /v:TARGET_IP /dynamic-resolution
```

![[Pasted image 20241224121936.png]]

If the connection is successful, a new window with WS001's desktop will appear on your screen, as shown below:

![[Pasted image 20241224122001.png]]

---

## Connect to Kali via SSH

Once connected to the VPN, we can access the Kali machine via SSH. The credentials of the machine are the default 'kali/kali'. To connect, use the following command:

  Overview

```shell-session
LeDaav@htb[/htb]$ ssh kali@TARGET_IP
```

![[Pasted image 20241224122029.png]]

**`Note:`** We have also enabled RDP on the Kali host. For sections with the Kali host as the primary target, it is recommended to connect with RDP. Connection credentials will be provided for each challenge question.

  Overview

```shell-session
LeDaav@htb[/htb]$ xfreerdp /v:TARGET_IP /u:kali /p:kali /dynamic-resolution
```

---

## Moving files between WS001 and your Linux attacking machine

To facilitate easy file transfer between the machines, we have created a shared folder on WS001, which can be accessed via SMB.

![[Pasted image 20241224122044.png]]

To access the folder from the Kali machine, you can use the 'smbclient' command. Accessing the folder requires authentication, so you will need to provide credentials. The command can be executed with the Administrator account as follows:

  Overview

```shell-session
LeDaav@htb[/htb]$ smbclient \\\\TARGET_IP\\Share -U eagle/administrator%Slavi123
```

![[Pasted image 20241224122113.png]]

Once connected, you can utilize the commands `put` or `get` to either upload or download files, respectively.