index
1. Find the IP address for the host we8105desk on 24 AUGUST 2016 :

```
index="botsv1" we8105desk 
|  stats count by src_ip 
|  sort - count
```

ANS:``192.168.250.100

2. What is the name of the USB key iunserted by bob smith

```
index="botsv1" sourcetype="winregistry" friendlyname 
|  table _time host user object data
```

ANS:``MIRANDA_PRI`

3. What is the name of the file executed after the USB insertion ?

```
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk "d:\\"
```

ANS:``D:\Miranda_Tate_unveiled.dotm

4. During the infection a VBScript is run. the entire script from this execution can be found in a field in splunk,. what is the length in characters of this field?

```
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk *.exe EventCode=1
|  eval sz=len(CommandLine)
| table _time CommandLine ParentCommandLine Computer Image sz
```

ANS:``4491

5. Bob Smith’sworkstation was connected to a file server during the ransomware outbreak. What is the ip address of the file server?
find the ip
```
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk src=we8105desk.waynecorpinc.local
| stats count by dest_ip
| sort - count
```

Find if it is a fileserver
```
index="botsv1" sourcetype="winregistry" host=we8105desk fileshare
```

Find the name
```
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 192.168.250.20
| stats count by DestinationHostname
| sort - count
```
ANS:`` we9041srv

6. What was the first suspicious domain visited by we8105desk on 24AUG2016 ?

```
index="botsv1" sourcetype="stream:dns" src_ip=192.168.250.100 
| stats count by queries
|  sort - count
```

ANS:``solidaritedeproximite.org


7. The malware downloads a file that contains the Cerbet ransomware cryptor code. What is the name of that file?

```spl
index=botsv1 sourcetype="stream:http" src=192.168.250.100
| stats count values(url) by dest
```

```spl
index=botsv1 sourcetype="fgt_utm" srcip=192.168.250.100
```

ANS:`mhtr.jpg

8. What is the parent process id of 121214.tmp

```spl
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 121214.tmp | table ParentCommandLine ParentProcessId
```


ANS:`` 3968

9. Which signature and ID alerted the fewest number of times ?

```spl
index="botsv1"sourcetype="suricata"cerber (src_ip=192.168.250.100 OR dest_ip=192.168.250.100) | table alert.category, alert.signature, alert.signature_id 
```

ANS:``2816763

10.  The cerber ransomware encrypts files lcoated in Bob smith’s windows profile. How many .txt files does it encrypt ?

```spl
index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=2 host=we8105desk TargetFilename="*bob.smith*.txt"  | stats count by Image
```

ANS:``406

11. How many distinct PDFs did the ransomware encrypt on the remote file server?


```spl
index=botsv1 sourcetype=*win* pdf dest=we9041srv.waynecorpinc.local Source_Address=192.168.250.100
|  stats dc(Relative_Target_Name)
```
ANS:``257

12. What fully qualified domain name (FQDN) does the Cerbet ransomware attempt to direct the user to at the end of its encryption phase ?

```spl
index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100 query{}!=null record_type=A query{}!="*microsoft.com*"
|   table _time, query{}
```

ANS:``cerberhhyed5frqa.xmfir0.win



![[Pasted image 20250814105959.png]]
![[Pasted image 20250814105923.png]]