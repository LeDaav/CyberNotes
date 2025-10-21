
1. What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities ?

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http"
| stats count by src_ip
| sort -count
```

ANS: 40.80.148.42

![[attachments/Pasted image 20251021152720.png]]


2. What comapny created the web vulnerability scanner used by Po1s0n1vy?

hint: 
- use the src_ip found
- check stream:http
- check user_agent

```sql
index="botsv1" src_ip="40.80.148.42" sourcetype="stream:http"
| stats count by http_user_agent
```


Ans: Acunetix

![[attachments/Pasted image 20251021153558.png]]

3. 