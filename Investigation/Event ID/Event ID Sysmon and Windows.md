
## Sysmon - Event IDs

| Event ID | Description |
|----------|-------------|
| 1        | Process Create |
| 2        | File Creation Time Changed |
| 3        | Network Connection |
| 4        | Sysmon Service State Changed |
| 5        | Process Terminated |
| 6        | Driver Loaded |
| 7        | Image Loaded |
| 8        | CreateRemoteThread |
| 9        | RawAccessRead |
| 10       | ProcessAccess |
| 11       | FileCreate |
| 12       | RegistryObjectAddedOrDeleted |
| 13       | RegistryValueSet |
| 14       | RegistryKeyRenamed |
| 15       | FileCreateStreamHash |
| 16       | Sysmon Configuration Change |
| 17       | Pipe Created |
| 18       | Pipe Connected |
| 19       | WMI Event Filter activity detected |
| 20       | WMI Event Consumer activity detected |
| 21       | WMI Event Consumer To Filter activity detected |
| 22       | DNS query |
| 23       | FileDelete |
| 24       | Clipboard Change |
| 25       | Process Tampering |
| 26       | FileDeleteDetected |

---

## Windows - Key Event IDs

### Security Log

| Event ID | Description |
|----------|-------------|
| 4624     | Successful logon |
| 4625     | Failed logon |
| 4634     | Logoff |
| 4647     | User-initiated logoff |
| 4662     | Object operation (Directory Service Access) |
| 4672     | Special privileges assigned to new logon |
| 4688     | A new process has been created |
| 4689     | A process has exited |
| 4720     | User account created |
| 4722     | User account enabled |
| 4723     | Attempt to change an account's password |
| 4724     | Attempt to reset an account's password |
| 4725     | User account disabled |
| 4726     | User account deleted |
| 4728     | Member added to a security-enabled global group |
| 4732     | Member added to a security-enabled local group |
| 4733     | Member removed from a security-enabled local group |
| 4740     | Account locked out |
| 4768     | Kerberos TGT requested |
| 4769     | Kerberos service ticket requested |
| 4771     | Kerberos pre-authentication failed |
| 4776     | NTLM authentication |
| 5136     | Directory object modified |

### System Log

| Event ID | Description |
|----------|-------------|
| 6005     | The Event log service was started (system startup) |
| 6006     | The Event log service was stopped (system shutdown) |
| 6008     | Unexpected shutdown |
| 41       | Unexpected restart (Kernel-Power) |

### Application Log

| Event ID | Description |
|----------|-------------|
| 1000     | Application Error |
| 1026     | .NET Runtime Error |
| 11707    | Application installation succeeded (MSI Installer) |
| 11708    | Application installation failed (MSI Installer) |

---

## Further Resources

- [Sysmon Event IDs - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-descriptions)
- [Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Event IDs Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-security-audit-events)
