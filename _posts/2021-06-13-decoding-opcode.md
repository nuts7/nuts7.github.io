---
title: "Intro to Opcode Decoding"
layout: "post"
categories: "Linux"
tags: ["Reverse Engineering"]
---

# Qu'est ce qu'un opcode ?

Tout d'abord, un opcode est une **instruction** (écrite hexadécimal) en **langage machine** qui spécifie l'opération à effectuer. Les opcodes sont les **instructions assembleur** notés en **hexadécimal** que le CPU va exécuter.
Un opcode primaire peut avoir une longueur de 1, 2 ou 3 octets.

L'**hexdump** d'un binaire est l'ensemble des opcodes du programme. Voici un sample des opcodes d'un hello world en C compilé :

```bash
❯ xxd helloworld
<...>
000002a0: 0100 0000 0000 0000 2f6c 6962 3634 2f6c  ......../lib64/l
000002b0: 642d 6c69 6e75 782d 7838 362d 3634 2e73  d-linux-x86-64.s
000002c0: 6f2e 3200 0400 0000 1400 0000 0300 0000  o.2.............
000002d0: 474e 5500 244c 91c8 e319 bc06 2283 5226  GNU.$L......".R&
<...>
```

# Le format des instructions des architectures Intel® 64 et IA-32

Premièrement les instructions sont composées de :

- Préfixes d'instruction (facultatif)
- Octets d'opcode primaire (3 bytes maximum)
- Spécificateur de forme d'adressage (si nécessaire) constitué d'un octet **Mod R/M** et parfois d'un octet **SIB** (Scale-Index-Base)
- Déplacement (si nécessaire)
- Un champ de données immédiates (si nécessaire)

Voici un schéma qui résume le format des instructions en architecture Intel® 64 et IA-32 :

![image1](https://i.imgur.com/pJfQoOO.png)

## Qu'est ce qu'un déplacement ?

- Un **déplacement** est une constante qui est ajoutée au reste de l'adresse. Un déplacement va prendre la valeur pointée à une adresse ainsi que les octets permettant un déplacement de mémoire

Par exemple avec ce déplacement nous mettons la valeur pointée par EBP + 8 dans le registre de destination EAX :

```py
mov eax, DWORD [ebp + 0x8]
```

## Qu'est ce qu'un immédiat ?

- Un **immédiat** est une **valeur directe** et non une valeur pointé dans un registre. La valeur immédiate sera donc **incluse dans l'opcode**.

Par exemple avec cette immédiat nous mettons simplement 0x1337 dans le registre EAX :

```py
mov eax, 0x1337
```

# Décodons nos premiers opcodes !

En guise d'exemple nous allons développer une petite fonction en C et récupérer l'hexdump du binaire :

```c
int main(int a, int b) {
    return (a + b);
}
```

Voici les opcodes du programme :

```
55
89 e5
83 ec 10
8b 45 08
8b 55 0c
01 d0
c9
c3
```

Le premier opcode est 0x55, c'est un **opcode primaire** alors nous avons simplement à regarder l'instruction correspondante dans [l'opcode table](http://sparksandflames.com/files/x86InstructionChart.html) :

![image2](https://i.imgur.com/ehrSeWo.png)

La première instruction est alors `PUSH EBP`, c'est une instruction qui fait 1 byte, et qui n'a pas le Mod R/M.

Ensuite, les 2 opcodes suivants sont 0x89 0xe5.
Commencons par le premier opcode en regardant dans la table :

![image3](https://i.imgur.com/oo62lmP.png)

Cependant cette instruction a le Mod R/M activé.

## Qu'est ce que le Mod Register/Memory ?

L'octet Mod R/M spécifie les opérandes de l'instruction et leur mode d'adressage.

Voici un schéma simple pour comprendre la composition du byte Mod R/M :

![image4](https://i.imgur.com/XzHMDtT.png)

Le **champ MOD** peut prendre plusieurs valeurs ainsi ce dernier va définir le mode d'adressage :

![image5](https://i.imgur.com/PeZmzAN.png)

En résumé :

- MOD 00 : Aucun déplacement qui est effectuer (octet immédiat)
- MOD 01 : Déplacement de 1 octet
- MOD 10 : Déplacement de 4 octets
- MOD 11 : Le champ R/M est un registre

Afin de déterminer quel opérande est la source et lequel est la destination, nous devons récupérer le **d bit**. (avant dernier bit de l'octet/l'opcode)

- Si **d = 0** : MOD R/M <- REG, **REG** est la **source**
- Si **d = 1** : REG <- MOD R/M, **REG** est la **destination**

Pour finir le **champ REG** détermine le registre source ou destination :

![image6](https://i.imgur.com/CY5GBxK.png)

Revenons à nos 2 opcodes, nous savons déjà que l'instruction `MOV` est présente avec le Mod R/M.
Nous allons donc prendre l'opcode suivant : 0xe5 et le décomposer en bits pour récupérer le d bit et nos champs vus précédemment :

```
11  100 101
MOD REG R/M
```

Le d bit est égal à 0 donc REG est la source et son registre est `ESP`. Deplus le MOD est 11 alors le champ R/M est un registre.

Il nous reste plus qu'a regarder dans la table d'adressage de la [documentation Intel](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf) le registre destination :

![image7](https://i.imgur.com/QJuJFbM.png)

Maintenant nous savons que l'instruction `MOV` met la valeur pointée dans `ESP` (source) dans le registre `EBP`. (destination)

Nous retrouvons parfaitement l'épilogue de notre fonction.

Cet article peut etre être une base de connaissances pour l'écriture d'un désassembleur, cependant la méthode présentée ne permet de décoder tous les opcodes existants. Il s'agit simplement d'un introduction au decoding d'opcode. 😄
