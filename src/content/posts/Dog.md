---
title: 'HTB | Dog'
published: 2025-07-02
draft: false
description: 'HTB Machine `Dog` writeup.'
tags: ['HackTheBox', 'linux']
---

## Recon : Phase 1

### `Nmap` Scan

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git:
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries
| /core/ /profiles/ /README.md /web.config /admin
| /comment/reply /filter/tips /node/add /search /user/register
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password
|_/?q=user/register /?q=user/login /?q=user/logout
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Dumping Git Directory

```shell
(_pyenv)$ git-dumper -u http://dog.htb/.git
```

- In the app source code, we find a password **Hard-coded** for the `root` user to connect to the `mysql` service on localhost.
  - This could be founded by running the `snyk` extension in `vs code` .
- Searching further in the source code for anything related to the term `dog.htb` , we find a user named `tiffany` (`tiffany@dog.htb`).
- We can use this set of credentials to log in to the `Backdrop` system.

## Exploitation

### Malicious Plugin

- We can get the version of the `Backdrop CMS` system from `Status Report` page at
  `?q=/admin/reports/status` .
- The version is `1.27.1` , for which we can find an [authenticated `RCE` vulnerability](https://www.exploit-db.com/exploits/52021) from `exploitdb` by loading a malicious plugin.
- Instead of creating a `zip` archive , we create a `tar` using :
  `$ tar cvf shell.tar shell`
- We can execute the malicious plugin at `/modules/shell/shell.php` .

## Recon: Phase 2

- On the box, there are two users : `johncusack` and `jobert`.
- Checking the `SQL` database, we find a user named `jobert` along with his password hash.
- We can attempt to crack this hash as `drupal hash` using `hashcat` with mode set to `7900`, but its not required for this box.
- We have `backdrop cms` credentials for a user named `tiffany` , but this user is not available in the system.
- Trying `tiffany`'s password for the user `johncusack` , we get in.
- We can now ssh as `johncusack`.

## Post-Exploitation

### Special Permissions

- Running `sudo -l` , we see that our user `johncusack` can run a binary `/usr/local/bin/bee` as root.

#### **Bee**

- Bee is a command line utility for Backdrop CMS. It includes commands that allow developers to interact with Backdrop sites, performing actions like:
  - Running cron
  - Clearing caches
  - Downloading and installing Backdrop
  - Downloading, enabling and disabling projects
  - Viewing information about a site and/or available projects

- Trying to run a `php` script or a `php` command using `php-eval` gives the following error :

```shell
$ sudo /usr/local/bin/bee php-eval 'system(whoami)'
 ✘  The required bootstrap level for 'eval' is not ready.
```

- It is required for `bee` to run in the directory where `backdrop cms` is installed.

- We can set the root directory using the `--root` flag, or we can just `cd` to the `/var/www/html` directory.

```shell
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee php-script ~/shell.php
```

- We receive a reverse shell as `root` at our machine on the port specified.
