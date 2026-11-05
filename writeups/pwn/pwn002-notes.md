# PWN#002 — Deep Vault Terminal (PIE + pext ROP + open/read/write)

- **Auteur :** Le_Geek
- **Cible :** `<HOST>:<PORT>` (Deep Vault Terminal, ELF x86-64 PIE strippe)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (voir regle de non-persistance des flags)
- **Fichiers fournis :** binaire ELF x86-64 PIE (strippe)

## Contexte

Deuxieme challenge de la serie Vault Terminal. Le binaire est un ELF x86-64 avec PIE actif et strippe (pas de symboles). Il utilise la meme libc que PWN#001 (Debian GLIBC 2.42-13). Le filtre seccomp est plus precis cette fois : un filtre BPF brut qui bloque uniquement `execve` (59) et `openat` (257), mais **laisse passer `open` (2)**.

## Reconnaissance

### Protections

| Protection   | Etat                              |
|---|---|
| Canary       | Actif                             |
| NX           | Actif                             |
| RELRO        | Full                              |
| PIE          | Actif (adresses randomisees)      |
| seccomp BPF  | Bloque `execve`(59), `openat`(257)|
| Symboles     | Strippes                          |

### Fuite PIE depuis le banner

Au demarrage, le service affiche un banner contenant un sceau :

```
Vault seal: %016lx
```

La valeur imprimee correspond a `base + 0x13a6`. La base PIE est donc `seal_value - 0x13a6`.

### Fuite du canary

Meme mecanisme que PWN#001 : lecture de 73 octets dans un buffer de 72 octets, le 73e octet ecrase le LSB nul du canary, `printf("%s")` fuit les 7 octets superieurs.

### Seccomp BPF : analyse fine

Le filtre BPF brut bloque :
- `execve` (syscall 59) : pas de shell.
- `openat` (syscall 257) : pas d'ouverture de fichier via `openat`.

Mais `open` (syscall 2) **n'est pas bloque**. C'est la cle : on peut ouvrir un fichier avec `open()` puis le lire avec `read()` et l'ecrire sur stdout avec `write()`.

### Chemin du flag dans .bss

Le binaire decode la chaine `"/flag/flag.txt"` dans une zone ecrasable `.bss` a l'adresse `PIE + 0x4070` au demarrage. Ce chemin est donc disponible a une adresse calculable une fois la base PIE connue.

### Gadgets : pas de `pop rdi` classique

Le binaire ne contient pas de gadget `pop rdi; ret` classique. L'auteur a plante un trio de gadgets utilisant l'instruction BMI2 `pext` :

```
pext rdi, rax, rcx
```

Ce trio permet de charger `rdi` a partir de `rax` et `rcx`, qui sont controles via d'autres gadgets de pile. L'identification de ces gadgets dans un binaire strippe necessite un scan exhaustif des opcodes.

## Vulnerabilite

- **Fuite PIE** : le banner `Vault seal: %016lx` revele la base PIE.
- **Fuite canary** : off-by-one identique a PWN#001.
- **Debordement de pile** : le message deborde le buffer et permet le controle de l'adresse de retour.
- **seccomp incomplet** : `open(2)` est autorise malgre le blocage de `openat(257)`.

## Exploitation

### Etape 1 — Fuite libc

Chaine ROP utilisant les gadgets `pext` pour charger `rdi` avec l'adresse de `puts@GOT` (calculee via la base PIE), puis appeler `puts@PLT` :

```
padding[72] + canary[8] + rbp[8] + ROP_chain
```

La chaine ROP :
1. Charge `rdi = puts@GOT` via le trio `pext`.
2. Appelle `puts@PLT` pour afficher l'adresse resolue de `puts`.
3. Retourne a la machine d'etat a l'offset `PIE + 0x1676` pour relancer la boucle.

Resultat : `libc_base = puts_leak - puts_offset_glibc_2.42`.

### Etape 2 — open + read + write

Avec la base libc et la base PIE connues :

1. **`open(PIE + 0x4070, O_RDONLY)`** : ouvre `"/flag/flag.txt"` (chaine deja decodee dans `.bss`). Le syscall `open` (2) passe le filtre seccomp.
2. **`read(fd, buf, n)`** : lit le contenu du fichier dans un buffer controle.
3. **`write(1, buf, n)`** : ecrit le contenu sur stdout (fd 1).

Les gadgets libc standards (`pop rdi`, `pop rsi`, `pop rdx`, `syscall`) sont utilises pour cette deuxieme etape, leur adresse etant calculee a partir de la base libc.

### Retour a la machine d'etat

L'offset `0x1676` dans le binaire correspond au point d'entree de la machine d'etat (state machine) qui gere la boucle nom/message. Retourner a ce point apres l'etape 1 permet de relancer l'exploitation pour l'etape 2 sans reconnecter (le canary reste le meme dans une connexion).

## Resultat

Le flag a ete lu depuis `/flag/flag.txt` via la chaine `open` + `read` + `write` et soumis avec succes.

```
CTF{REDACTED}
```

## Pieges rencontres

- **Pas de `pop rdi`** : l'absence du gadget classique `pop rdi; ret` force l'utilisation des gadgets `pext` BMI2 plantes par l'auteur. Sans scan exhaustif des opcodes, ces gadgets restent invisibles.
- **`openat` vs `open`** : le filtre seccomp bloque `openat` (257) mais pas `open` (2). Il faut analyser le BPF brut pour decouvrir cette distinction, qui n'apparait pas dans un simple `seccomp-tools dump`.
- **PIE strippe** : sans symboles, localiser les gadgets et les fonctions PLT/GOT necessite une analyse manuelle ou un outil comme ROPgadget/ropper avec le binaire charge a la bonne base.
- **Chemin du flag dans .bss** : le chemin `"/flag/flag.txt"` est decode au demarrage dans `.bss`. Ne pas essayer de pousser la chaine sur la pile ; utiliser l'adresse `.bss` directement.

## Lecons

1. **Analyser le BPF brut** : un `seccomp-tools dump` peut manquer des subtilites. Lire le filtre BPF instruction par instruction revele que `open` (2) est autorise alors que `openat` (257) ne l'est pas.
2. **Gadgets BMI2 (`pext`)** : les instructions BMI2 sont rares dans les binaires standards mais peuvent etre plantees par les auteurs de challenges. Scanner les opcodes bruts est indispensable dans un binaire strippe.
3. **Chaine `open` + `read` + `write`** : quand `execve` est bloque, la lecture directe de fichier via `open`/`read`/`write` (ou `sendfile`) est l'alternative classique.
4. **Machine d'etat reutilisable** : retourner au point d'entree de la boucle permet de chainer plusieurs etapes dans une seule connexion, evitant la re-randomisation du canary et de l'ASLR.
