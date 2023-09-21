---
title: "HackTheBox - Olympus"
layout: "post"
categories: "Linux"
tags: ["HackTheBox", "Writeup", "Network", "Docker"]
---

Bonjour à tous, je vous présente mon **write-up** qui porte sur la machine **Olympus** de **HackTheBox** qui était assez cool et qui m'a apprit des choses que je n'avais jamais vu auparavant surtout dans un CTF. Elle n'est pas difficile mais très intéréssante et amusante à root... 😀

## Port Scanning

```bash
# Nmap 7.91 scan initiated Fri Jan 29 17:30:12 2021 as: nmap -sC -sV -oA nmap -Pn olympus.htb
Nmap scan report for olympus.htb (10.10.10.83)
Host is up (0.13s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| dns-nsid:
|_  bind.version: Bind
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|     bind
|_    Bind
80/tcp   open     http    Apache httpd
|_http-server-header: Apache
|_http-title: Crete island - Olympus HTB
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-City of olympia
| ssh-hostkey:
|   2048 f2:ba:db:06:95:00:ec:05:81:b0:93:60:32:fd:9e:00 (RSA)
|   256 79:90:c0:3d:43:6c:8d:72:19:60:45:3c:f8:99:14:bb (ECDSA)
|_  256 f8:5b:2e:32:95:03:12:a3:3b:40:c5:11:27:ca:71:52 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.91%I=7%D=1/29%Time=60143823%P=x86_64-unknown-linux-gnu%r
SF:(DNSVersionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07vers
SF:ion\x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0
SF:\x0c\0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=1/29%Time=6014381E%P=x86_64-unknown-linux-gnu
SF:%r(NULL,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\r\n");
```


Nous pouvons voir que le serveur contient 3 ports ouverts:
1. Port 53 (Serveur DNS)
2. Port 80 (Serveur Web Apache)
3. Port 2222 (Serveur SSH)

## DNS enumeration

Commencons par intérroger le serveur DNS afin d'afficher l'opcode mnémotechnique **AXFR** avec **dig**. La requete AXFR ne renvoie rien d'intéréssant, cependant un autre nom de domaine peut etre important...

![dig](https://i.imgur.com/IvHQg4g.png)

## Xdebug Exploitation

En regardant les headers des requetes et réponses HTTP on sait maintenant que **Xdebug 2.5.5** est en marche sur la machine, ce qui peut permettre aux développeurs de déboguer à distance.

![headers](https://i.imgur.com/UPfH78c.png)

Après quelques recherches, on s'apercoit que cette librairie est touché par une [RCE](https://paper.seebug.org/397/), ce qui va nous permettre d'avoir un premier foothold sur la machine. 😇

Nous allons utiliser un [PoC développé en python](https://github.com/vulhub/vulhub/blob/master/php/xdebug-rce/exp.py) déjà présent sur GitHub pour plus de rapidité et facilité.

![rce_script](https://i.imgur.com/qTLDi5R.png)

Nous pouvons maintenant executer des commandes en www-data sur la cible, il ne reste plus qu'a executer un reverse shell. 😎

![rce_shell](https://i.imgur.com/XDHlNPz.png)

Enfin, nous avons un shell sur la machine cible !

## Pivot to Olympia container

La présence d'un .dockerenv certifie bien le fait que nous sommes dans un container Docker.

![dockerenv](https://i.imgur.com/KpJtQ8w.png)

Avec une énumération un peu plus appronfondie, nous avons un fichier .cap de capture réseau associé à un .txt de la part de Zeus. Nous allons donc le transférer sur notre machine local afin de l'étudier avec Wireshark.

![presence&transfert_cap](https://i.imgur.com/XLbOkkM.png)

### Analyse .cap

Plusieurs solutions sont possibles:

1. Regarder les strings qui correspondent à l'hexdump du fichier .cap avec xxd et strings.
2. Ouvrir le fichier via Wireshark

![analyse_cap](https://i.imgur.com/CDPomUA.png)

### Cracking WPA key

À partir d'un SSID nous pouvons tenter de casser la clé **WPA** de ce AP sans fil avec **aircrack-ng**

![crack_key](https://i.imgur.com/orzve4A.png)

La clé est dans la wordlist rockyou donc ca n'a pas été très difficile pour l'a casser.

J'ai eu des difficultés pour comprendre que après cette étape, nous devons deviner que icarus était en effet un utilisateur du serveur SSH.

![ssh_connexion](https://i.imgur.com/RcgLtEb.png)

On se retrouve une nouvelle fois à l'intérieur d'un container Docker.

## Pivot to Hades / Olympus

Un document .txt dans le répertoire courant révèle un nouveau nom de domaine pour la machine.

Je vais l'ajouter à ma liste de VHOST:

```bash
127.0.0.1  localhost
127.0.1.1  host
10.10.10.83	olympus.htb	ctfolympus.htb
```

Lors de la phase initiale d'énumération, j'avais essayé de faire un transfert de zone mais on avait rien trouvé, avec le nouveau nom de domaine nous aurons peut etre un retour.

![zonetransfer_ctf](https://i.imgur.com/CJuhzRQ.png)

Nous avons des informations en or dans les **records TXT**.

### Port Knocking

Durant notre scan nmap, nous avons vu que le port 22 était filtré.
On obtient maintenant les credentials d'un utilisateur nommé prometheus, ainsi que des numéros pour aller au portail d'Hadès qui sont concrètement les numéros de port sur lesquels nous devons nous connecter pour réaliser un **Port Knocking** afin de se connecter à l'utilisateur prometheus.

Pour cela c'est très simple nous allons executer une boucle for en bash pour automatiser la chose dans le temps imparti:

```bash
for nuts in 3456 8234 62431; do nmap -p $nuts 10.10.10.83; done; ssh prometheus@10.10.10.83
```

Ensuite nous pouvons nous connecter avec le mot de passe obtenu auparavant. 🤠

![port_knocking](https://i.imgur.com/tJ5fJMj.png)

## Local Privilege Escalation (LPE)

Pour conclure cette machine plaisante, l'éscalation de privilèges est très simple.
Prometheus est dans le **groupe "docker"**. De plus, le client Docker exige des droits root donc je vais exécuter un shell à partir d'une image du Docker Hub:

```bash
prometheus@olympus:~$ docker run -it olympia bash
root@f388364ddf48:/#
```

À noter que nous pouvons aussi monter la racine du système de fichiers local dans cette image comme le réfère [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell):

```bash
prometheus@olympus:~$ docker run -v /:/mnt --rm -it olympia chroot /mnt bash
root@421e0ac051c7:/#
```

Voila nous sommes enfin root ! 🙂
