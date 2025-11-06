---
title: 'HTB | Sneaky'
published: 2025-07-02
draft: false
description: 'HTB Machine `Sneaky` writeup.'
tags: ['HackTheBox', 'linux']
---

## Recon

### Port Scanning

- Nmap scanned only TCP port 80, and UDP port 161 (SNMP) as open.

### Directory Bruteforcing

- At the root, it seems like a static website with a landing page `under development`.
- A Bruteforce Attack reveals a in-development endpoint `/dev/`.
- A login form appears at endpoint `/dev/` .
- Bruteforcing this endpoint reveals a single page `/dev/login.php` , which returns a custom `Not Found` error (404) for both `GET` and `POST` request, when submitted invalid credentials.

### Footprinting `SNMP`

- Using `snmpwalk` on the server does not reveal much interesting data.

```shell
$ snmapwalk -v3c -c public 10.10.10.20
```

- Although, with the available data, we can calculate the `ipv6` address of the server.

## Exploitation

### SQL Injection

- The login form at `/dev/` is vulnerable to `SQL Injection`.
- With a simple `Boolean` payload, we can bypass the login form, and get the server user's name, and its `SSH Key`.
- `MySQL` is running as `'root'@localhost` user, and have all the permissions possible.
- It means we can read files, and write to them.
- The only problem is the variable `secure_file_priv` was set to value `/var/lib/mysql-files/`.
- This means as root user of `mysql` , we can **Only Read and Write files Under this Directory**.
- This becomes a dead-end as writing a rev-shell under this directory won't lead to anything.

### Finding `IPv6` Address of the Server

- In the `snmpwalk` output, an IPv6 address is exposed at MiB iso.3.6.1.2.1.4.34.1.5.2.16.
- This address is in `decimal`, so we need to convert it into `hex` to its correct value.
- We simply take two decimal numbers at a time separated by a `.` and convert each of them individually into `hex` , place them together and add a `:` after them to continue ahead.
- In this manner, we get an `ipv6` address : `dead:beef:00:00:250:56ff:feb9:e625`
  - This will be changed each time the box resets.
- We can verify this address by typing it in the browser like this : `[dead:beef:00:00:250:56ff:feb9:e625]` , and we would get the same `under development` page.

#### Scanning for Running Services bind to `Ipv6`

- Using `nmap` to scan for services running at `Ipv6` , we get the following output :

```
$ nmap -6 -p 22,80 -sCV -oA scans/nmap6-tcpscripts dead:beef::250:56ff:feb9:be08
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 5d:5d:2a:97:85:a1:20:e2:26:e4:13:54:58:d6:a4:22 (DSA)
|   2048 a2:00:0e:99:0f:d3:ed:b0:19:d4:6b:a8:b1:93:d9:87 (RSA)
|   256 e3:29:c4:cb:87:98:df:99:6f:36:9f:31:50:e3:b9:42 (ECDSA)
|_  256 e6:85:a8:f8:62:67:f7:01:28:a1:aa:00:b5:60:f2:21 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

#### We can SSH now with the key we found previously.
