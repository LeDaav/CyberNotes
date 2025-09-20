
Many times, we might notice strange traffic to our web servers. In one of these cases, we might see that one host is generating excessive traffic with HTTP or HTTPs. Attackers like to abuse the transport layer many times, as the applications running on our servers might be vulnerable to different attacks. As such, we need to understand how to recognize the steps an attacker will take to gather information, exploit, and abuse our web servers.

Generally speaking, we can detect and identify fuzzing attempts through the following

1. `Excessive HTTP/HTTPs traffic from one host`
2. `Referencing our web server's access logs for the same behavior`

Primarily, attackers will attempt to fuzz our server to gather information before attempting to launch an attack. We might already have a `Web Application Firewall` in place to prevent this, however, in some cases we might not, especially if this server is internal.

## Finding Directory Fuzzing

Directory fuzzing is used by attackers to find all possible web pages and locations in our web applications. We can find this during our traffic analysis by limiting our Wireshark view to only http traffic.

- `http`

![Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.1, including unauthorized access attempts to various files.](https://academy.hackthebox.com/storage/modules/229/2-HTTP-Enum.png)

Secondarily, if we wanted to remove the responses from our server, we could simply specify `http.request`

![Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.1, including attempts to access various files.](https://academy.hackthebox.com/storage/modules/229/3-HTTP-Enum.png)

Directory fuzzing is quite simple to detect, as it will in most cases show the following signs

1. `A host will repeatedly attempt to access files on our web server which do not exist (response 404)`.
    
2. `A host will send these in rapid succession`.
    

We can also always reference this traffic within our access logs on our web server. For Apache this would look like the following two examples. To use grep, we could filter like so:

  HTTP/HTTPs Service Enumeration

```shell-session
LeDaav@htb[/htb]$ cat access.log | grep "192.168.10.5"

192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bashrc HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cache HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.config HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvs HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvsignore HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.forward HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
...SNIP...
```

And to use awk, we could do the following

  HTTP/HTTPs Service Enumeration

```shell-session
LeDaav@htb[/htb]$ cat access.log | awk '$1 == "192.168.10.5"'

192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bashrc HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cache HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.config HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvs HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvsignore HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.forward HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.git/HEAD HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.hta HTTP/1.1" 403 438 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
...SNIP...
```

## Finding Other Fuzzing Techniques

However, there are other types of fuzzing which attackers might employ against our web servers. Some of these could include fuzzing dynamic or static elements of our web pages such as id fields. Or in some other cases, the attacker might look for IDOR vulnerabilities in our site, especially if we are handling json parsing (changing `return=max` to `return=min`).

To limit traffic to just one host we can employ the following filter:

- `http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))`

![Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.7, accessing user IDs.](https://academy.hackthebox.com/storage/modules/229/4-HTTP-Enum.png)

Secondarily, we can always build an overall picture by right clicking any of these requests, going to follow, and follow HTTP stream.

![HTTP 404 error page showing 'Not Found' for user IDs 8 and 9 on server 192.168.10.7.](https://academy.hackthebox.com/storage/modules/229/4a-HTTP-Enum.png)

Suppose we notice that a lot of requests were sent in rapid succession, this would indicate a fuzzing attempt, and we should carry out additional investigative efforts against the host in question.

However sometimes attackers will do the following to prevent detection

1. `Stagger these responses across a longer period of time.`
    
2. `Send these responses from multiple hosts or source addresses.`
    

## Preventing Fuzzing Attempts

We can aim to prevent fuzzing attempts from adversaries by conducting the following actions.

1. `Maintain our virtualhost or web access configurations to return the proper response codes to throw off these scanners.`
    
2. `Establish rules to prohibit these IP addresses from accessing our server through our web application firewall.`