# PWN#Delta — Vault Terminal PowerPC (canary leak + gadgets PPC)

- **Auteur :** Le_Geek
- **Cible :** `<HOST>:<PORT>` (Vault Terminal, architecture PowerPC 32-bit)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (voir regle de non-persistance des flags)
- **Fichiers fournis :** binaire ELF 32-bit PowerPC

## Contexte

Variante PowerPC du Vault Terminal, meme boucle de menu que PWN#001 et PWN#002 (nom puis message). Le binaire est un ELF 32-bit big-endian, lie statiquement, non strippe (1949 symboles visibles). Les protections actives sont le canary, NX et Partial RELRO. PIE est desactive, ce qui fixe toutes les adresses du binaire.

## Reconnaissance

### Protections

| Protection   | Etat                |
|---|---|
| Canary       | Actif               |
| NX           | Actif               |
| RELRO        | Partiel             |
| PIE          | Desactive           |
| Liaison      | Statique            |

Le binaire statique contient `system()` et la chaine `"/bin/sh"` a des adresses fixes, ce qui elimine le besoin de fuite libc.

### Layout de pile

- Buffer de nom : 64 octets.
- Lecture du nom : 65 octets (`read(0, buf, 0x41)`) dans un buffer de 64 octets, soit un depassement d'un octet (off-by-one) qui ecrase le LSB du canary.
- Lecture du message : 108 octets dans le meme buffer de 64 octets, debordement controle au-dela du canary et de l'adresse de retour.

### Adresses cles (statiques, pas de ASLR)

| Element           | Adresse       |
|---|---|
| `gadget_load_r9`  | `0x100007cc`  |
| `gadget_vec_r3`   | `0x10000834`  |
| `system()`        | `0x100020d0`  |
| `"/bin/sh"`       | `0x10074850`  |

## Vulnerabilite

### Fuite du canary

Le nom est lu avec 65 octets dans un buffer de 64 octets. Le 65e octet ecrase le NUL de poids faible du canary. Comme le nom est ensuite affiche par `printf("Hello, %s\n", buf)` sans terminaison NUL ajoutee, les 7 octets restants du canary fuient dans la reponse. Le canary complet est reconstruit : `b"\x00" + leak[64:71]`.

Ce mecanisme est identique aux variantes x86 (PWN#001, PWN#002, PWN#Epsilon).

### Debordement du message

Les 108 octets du message debordent le buffer de 64 octets et permettent d'ecrire au-dela du canary, du frame pointer sauvegarde et de l'adresse de retour.

## Exploitation

### Particularite PPC : le back-chain pointer

Sur PowerPC, le prologue `stwu r1, -0x30(r1)` ecrit l'ancien `r1` (le back-chain pointer) exactement dans le slot de pile que `gadget_load_r9` lit pour charger `r9`. Plutot que de combattre cette contrainte architecturale, l'exploitation l'utilise : la valeur de `r9` est connue implicitement via le back-chain, ce qui simplifie la chaine.

### Chaine d'exploitation

1. **Fuite du canary** : envoyer 65 octets comme nom, lire les 7 octets du canary dans la reponse `Hello, ...`.

2. **Preparation du payload message** :
   - Octets `[0..63]` : remplissage du buffer.
   - Octets `[64..71]` : canary reconstruit.
   - Octet 84 : chaine litterale `"sh\0\0"` — c'est la commande que `system()` lira depuis son propre cadre d'appel.
   - Adresse de retour : pointe vers `gadget_load_r9` (`0x100007cc`), qui charge `r9` depuis la pile (via le back-chain pointer), puis enchaine vers `gadget_vec_r3` (`0x10000834`), qui charge `r3` (premier argument PPC) avant de brancher vers `system()` (`0x100020d0`).

3. **Appel de `system()`** : `system()` recoit la chaine `"sh"` comme argument via `r3`, qui pointe vers le slot du buffer a l'offset 84. Le binaire etant statique et non-PIE, toutes les adresses sont fixes et aucune fuite supplementaire n'est necessaire.

### Pourquoi pas de fuite libc

Le binaire est lie statiquement : `system()` et `"/bin/sh"` sont inclus dans le binaire lui-meme. Les adresses sont fixes (pas de PIE). L'ASLR est contourne par construction.

## Resultat

Shell distant obtenu. Le flag a ete lu et soumis avec succes.

```
$ id
uid=65534(nobody) gid=65534(nogroup)
$ cat /flag/flag.txt
CTF{REDACTED}
```

## Pieges rencontres

- **Back-chain PPC** : le prologue `stwu` ecrase un slot de pile utilise par le gadget. Il est contre-productif de chercher a le contourner ; mieux vaut l'integrer dans la chaine.
- **Big-endian** : l'encodage des adresses dans le payload est inverse par rapport aux variantes x86. Utiliser `p32()` de pwntools avec le reglage `context.endian = 'big'`.
- **Argument de `system()`** : sur PPC, le premier argument passe par `r3`, pas par la pile. La chaine `"sh\0\0"` placee dans le buffer est referencee par `r3` grace au gadget `gadget_vec_r3`.
- **Taille du payload** : le message est limite a 108 octets, ce qui laisse peu de marge pour les gadgets. La chaine minimale (deux gadgets + `system()`) tient dans cette enveloppe.

## Lecons

1. **Architectures exotiques** : les conventions PPC (back-chain, registres d'argument, big-endian) different de x86 mais les principes fondamentaux (fuite du canary, ROP) restent identiques.
2. **Binaire statique = pas de libc externe** : quand le binaire inclut `system()` et `"/bin/sh"`, aucune fuite libc n'est necessaire. L'exploitation est ASLR-proof par construction.
3. **Travailler avec l'architecture, pas contre** : utiliser le back-chain pointer plutot que de le combattre simplifie la chaine et reduit la taille du payload.
4. **Gadgets plantes** : `gadget_load_r9` et `gadget_vec_r3` sont des gadgets volontairement places par l'auteur du challenge. Leur identification dans les symboles (binaire non strippe) est la cle de la resolution.
