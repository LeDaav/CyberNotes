
# 🛠️ Nmap – Network Exploration Tool and Security/Port Scanner

**Nmap 7.95SVN**  
🔗 [Official Website](https://nmap.org)

---

## 📌 Basic Syntax



```bash
nmap [Scan Type(s)] [Options] {target specification}
```

---

## 🎯 Target Specification

- Supported: hostnames, IP addresses, networks, etc.
    
- Examples:
    
    - `scanme.nmap.org`
        
    - `microsoft.com/24`
        
    - `192.168.0.1`
        
    - `10.0.0-255.1-254`
        

### Options:

- `-iL <inputfilename>`: Input from file
    
- `-iR <num hosts>`: Random targets
    
- `--exclude <host1,host2,...>`: Exclude specific hosts
    
- `--excludefile <file>`: Exclude hosts from a file
    

---

## 🔍 Host Discovery

- `-sL`: List Scan – list targets only
    
- `-sn`: Ping Scan – no port scan
    
- `-Pn`: Treat all hosts as online (skip discovery)
    
- `-PS/PA/PU/PY[ports]`: SYN, ACK, UDP, or SCTP discovery
    
- `-PE/PP/PM`: ICMP echo, timestamp, netmask
    
- `-PO[protocols]`: IP protocol ping
    
- `-n / -R`: No DNS resolution / Always resolve
    
- `--dns-servers <dns1,dns2,...>`: Use custom DNS
    
- `--system-dns`: Use OS resolver
    
- `--traceroute`: Trace network path
    

---

## ⚙️ Scan Techniques

- `-sS/sT/sA/sW/sM`: TCP SYN / Connect() / ACK / Window / Maimon
    
- `-sU`: UDP scan
    
- `-sN/sF/sX`: Null / FIN / Xmas scans
    
- `--scanflags <flags>`: Custom TCP flags
    
- `-sI <zombie[:port]>`: Idle scan via zombie host
    
- `-sY/sZ`: SCTP INIT / COOKIE-ECHO scans
    
- `-sO`: IP protocol scan
    
- `-b <ftp host>`: FTP bounce scan
    

---

## 🚪 Port Specification & Scan Order

- `-p <ports>`: Specific port(s)  
    _Ex: `-p22`, `-p1-65535`, `-p U:53,T:80`_
    
- `--exclude-ports <ports>`: Exclude ports
    
- `-F`: Fast mode – fewer ports
    
- `-r`: Scan sequentially
    
- `--top-ports <number>`: Scan most common ports
    
- `--port-ratio <ratio>`: Scan ports more common than given ratio
    

---

## 🔎 Service / Version Detection

- `-sV`: Detect service/version info
    
- `--version-intensity <0–9>`: Set detection level
    
- `--version-light`: Light detection (intensity 2)
    
- `--version-all`: Full detection (intensity 9)
    
- `--version-trace`: Verbose version scan output
    

---

## 📜 NSE Script Scan

- `-sC`: Default scripts (`--script=default`)
    
- `--script=<scripts>`: Comma-separated list (files, dirs, categories)
    
- `--script-args=<key=val,...>`: Pass args to scripts
    
- `--script-args-file=<file>`: Load args from file
    
- `--script-trace`: Show raw script data
    
- `--script-updatedb`: Update script DB
    
- `--script-help=<scripts>`: Show script info
    

---

## 🧠 OS Detection

- `-O`: OS detection
    
- `--osscan-limit`: Limit to promising targets
    
- `--osscan-guess`: Aggressive guessing
    

---

## ⏱️ Timing & Performance

- `-T<0–5>`: Timing template
    
- `--min/max-hostgroup <size>`
    
- `--min/max-parallelism <probes>`
    
- `--min/max/initial-rtt-timeout <time>`
    
- `--max-retries <num>`: Max retries
    
- `--host-timeout <time>`: Per-target timeout
    
- `--scan-delay / --max-scan-delay <time>`
    
- `--min-rate / --max-rate <packets/sec>`
    

---

## 🛡️ Firewall / IDS Evasion & Spoofing

- `-f`, `--mtu <val>`: Packet fragmentation
    
- `-D <decoy1,decoy2,...>`: Decoys
    
- `-S <ip>`: Spoof source IP
    
- `-e <iface>`: Use specific interface
    
- `-g`, `--source-port <port>`: Set source port
    
- `--proxies <proxy1,proxy2,...>`: Use HTTP/SOCKS proxies
    
- `--data`, `--data-string`, `--data-length`: Custom packet data
    
- `--ip-options <options>`: IP options
    
- `--ttl <val>`: Time-To-Live field
    
- `--spoof-mac <mac>`: Spoof MAC address
    
- `--badsum`: Send invalid checksums
    

---

## 🧾 Output Options

- `-oN/-oX/-oS/-oG <file>`: Normal / XML / Script Kiddie / Grepable formats
    
- `-oA <basename>`: All output formats
    
- `-v`, `-vv`: Increase verbosity
    
- `-d`, `-dd`: Debug level
    
- `--reason`: Show port state reasons
    
- `--open`: Show open ports only
    
- `--packet-trace`: Trace all packets
    
- `--iflist`: Show interfaces/routes
    
- `--append-output`: Append to files
    
- `--resume <file>`: Resume aborted scan
    
- `--noninteractive`: Disable keyboard input
    
- `--stylesheet <path/URL>`: XSL stylesheet for XML
    
- `--webxml`: Use Nmap.org stylesheet
    
- `--no-stylesheet`: Disable XSL linking
    

---

## 🧩 Miscellaneous

- `-6`: Enable IPv6 scanning
    
- `-A`: Enable OS detection, version detection, scripts, traceroute
    
- `--datadir <dir>`: Custom data directory
    
- `--send-eth / --send-ip`: Send raw Ethernet/IP
    
- `--privileged / --unprivileged`: Force privilege mode
    
- `-V`: Show version
    
- `-h`: Show help
    

---

## 📦 Extended Examples

### 🔍 Host Discovery

```bash
nmap -sn 192.168.1.0/24
# Ping scan – discover live hosts only, no port scan
```

```bash
nmap -Pn 10.0.0.1
# Assume host is up, skip ping check
```

```bash
nmap -PS22,80,443 192.168.1.0/24
# TCP SYN discovery on specific ports
```

### 🔎 Port Scanning

```bash
nmap -p 1-1000 192.168.1.1
# Scan first 1000 ports of target
```

```bash
nmap -p U:53,T:22,80 10.0.0.1
# Scan UDP port 53 and TCP ports 22, 80
```

```bash
nmap -F 192.168.0.1
# Fast scan of the top 100 ports
```

### 🧠 OS and Version **Detection**

```bash
nmap -O 10.0.0.1
# Attempt to detect operating system
```

```bash
nmap -sV 192.168.1.1
# Detect service versions
```

```bash
nmap -A 192.168.1.1
# Aggressive scan: OS, version, script, traceroute
```


