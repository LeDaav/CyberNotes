
1. What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities ?

```sql
index="botsv1" imreallynotbatman.com sourcetype="stream:http"
| stats count by src_ip
| sort -count
```

ANS: 40.80.148.42

