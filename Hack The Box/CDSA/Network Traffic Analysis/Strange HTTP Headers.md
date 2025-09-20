
We might not notice anything like fuzzing right away when analyzing our web server's traffic. However, this does not always indicate that nothing bad is happening. Instead, we can always look a little bit deeper. In order to do so, we might look for strange behavior among HTTP requests. Some of which are weird headers like

1. `Weird Hosts (Host: )`
2. `Unusual HTTP Verbs`
3. `Changed User Agents`

## Finding Strange Host Headers

In order to start, as we would normally do, we can limit our view in Wireshark to only http replies and requests.

- `http`

![Wireshark capture showing HTTP requests between 192.168.10.5 and 192.168.10.7, including file and login page accesses.](https://academy.hackthebox.com/storage/modules/229/1-http-headers.png)

Then, we can find any irregular Host headers with the following command. We specify our web server's real IP address to exclude any entries which use this real header. If we were to do this for an external web server, we could specify the domain name here.

- `http.request and (!(http.host == "192.168.10.7"))`

![Wireshark capture showing repeated HTTP requests from 192.168.10.5 to 192.168.10.7 for login.php with file parameter.](https://academy.hackthebox.com/storage/modules/229/2-http-headers.png)

Suppose we noticed that this filter returned some results, we could dig into these HTTP requests a little deeper to find out what hosts these bad actors might have tried to use. We might commonly notice `127.0.0.1`.

![HTTP GET request for login.php with file parameter, showing headers and response details.](https://academy.hackthebox.com/storage/modules/229/3-http-headers.png)

Or instead something like admin.

![HTTP GET request for login.php with file parameter, showing headers and response details.](https://academy.hackthebox.com/storage/modules/229/4-http-headers.png)

Attackers will attempt to use different host headers to gain levels of access they would not normally achieve through the legitimate host. They may use proxy tools like burp suite or others to modify these before sending them to the server. In order to prevent successful exploitation beyond only detecting these events, we should always do the following.

1. `Ensure that our virtualhosts or access configurations are setup correctly to prevent this form of access.`
2. `Ensure that our web server is up to date.`

## Analyzing Code 400s and Request Smuggling

We might also notice some bad responses from our web server, like code 400s. These codes indicate a bad request from the client, so they can be a good place to start when detecting malicious actions via http/https. In order to filter for these, we can use the following

- `http.response.code == 400`

![Wireshark capture showing HTTP 400 Bad Request responses between 192.168.10.7 and 192.168.10.5.](https://academy.hackthebox.com/storage/modules/229/6-http-headers.png)

Suppose we were to follow one of these HTTP streams, we might notice the following from the client.

![HTTP GET request for login.php with encoded parameters, showing headers.](https://academy.hackthebox.com/storage/modules/229/5-http-headers.png)

This is commonly referred to as HTTP request smuggling or CRLF (Carriage Return Line Feed). Essentially, an attacker will try the following.

- `GET%20%2flogin.php%3fid%3d1%20HTTP%2f1.1%0d%0aHost%3a%20192.168.10.5%0d%0a%0d%0aGET%20%2fuploads%2fcmd2.php%20HTTP%2f1.1%0d%0aHost%3a%20127.0.0.1%3a8080%0d%0a%0d%0a%20HTTP%2f1.1 Host: 192.168.10.5`

Which will be decoded by our server like this.

Code: decoded

```url-decoded
GET /login.php?id=1 HTTP/1.1
Host: 192.168.10.5

GET /uploads/cmd2.php HTTP/1.1
Host: 127.0.0.1:8080

 HTTP/1.1
Host: 192.168.10.5
```

Essentially, in cases where our configurations are vulnerable, the first request will go through, and the second request will as well shortly after. This can give an attacker levels of access that we would normally prohibit. This occurs due to our configuration looking like the following.

## Apache Configuration

Code: txt

```txt
<VirtualHost *:80>

    RewriteEngine on
    RewriteRule "^/categories/(.*)" "http://192.168.10.100:8080/categories.php?id=$1" [P]
    ProxyPassReverse "/categories/" "http://192.168.10.100:8080/"

</VirtualHost>
```

[CVE-2023-25690](https://github.com/dhmosfunk/CVE-2023-25690-POC)

As such watching for these code 400s can give clear indication to adversarial actions during our traffic analysis efforts. Additionally, we would notice if an attacker is successful with this attack by finding the code `200` (`success`) in response to one of the requests which look like this.