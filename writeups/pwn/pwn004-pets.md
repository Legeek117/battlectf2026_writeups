# PWN#004 — Pets Shelter (FSOP House of Apple 2 + freelist poisoning)

- **Auteur :** Le_Geek
- **Cible :** `<HOST>:<PORT>` (Pets Shelter, ELF x86-64 C++ strippe)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}` (voir regle de non-persistance des flags)
- **Fichiers fournis :** binaire ELF x86-64 C++ strippe, 18568 octets

## Contexte

Service de gestion d'animaux de compagnie en C++. Le binaire est un ELF x86-64 strippe (pas de symboles). Aucune libc n'est fournie ; le service distant utilise la **glibc 2.43-5**, identifiee par empreinte de symboles (fingerprinting des offsets GOT).

Le binaire contient le meme allocateur de pool que PWN#003, mais avec une rotation de 7 (au lieu de 13) pour l'encodage `mangle` :

```
mangle(ptr, node) = ptr XOR rol(node, 7)
```

## Reconnaissance

### Protections

| Protection   | Etat                          |
|---|---|
| Canary       | Actif                         |
| NX           | Actif                         |
| RELRO        | Full                          |
| PIE          | Actif                         |
| Symboles     | Strippes                      |

### Piege du point d'entree

Le champ `e_entry` de l'en-tete ELF pointe vers `0x269e`, qui provoque un **SIGSEGV** avant `main`. C'est un piege delibere. Le veritable `_start` se trouve a l'adresse `0x1130`. Il faut patcher ou ignorer `e_entry` lors de l'analyse statique.

### Allocateur de pool

Meme architecture que PWN#003 :
- Pool avec freelist encodee par `mangle` avec `rol 7`.
- Allocations de classe 2 (taille `0x80`).
- 16 indices de notes au total, chaque ecriture consomme 2 indices (single-use).

### Operation "poke pet"

L'operation `poke` effectue `read` + `memcpy` dans un objet libere, ce qui constitue le primitif d'ecriture apres liberation (write-after-free). Cela permet l'empoisonnement de la freelist, comme dans PWN#003.

## Vulnerabilite

### Write-after-free via poke

L'operation `poke pet` ecrit dans un objet deja libere. Le contenu ecrase le pointeur freelist encode dans le chunk libere, permettant de rediriger la prochaine allocation vers une adresse arbitraire.

### Contrainte de budget

Avec 16 indices de notes et 2 indices consommes par ecriture, le budget total est de 8 operations d'ecriture. La chaine d'exploitation doit etre soigneusement optimisee pour tenir dans ce budget.

## Exploitation

### Strategie : FSOP House of Apple 2

Les contraintes (pas de `execve` trivial, pas de gadgets ROP evidents dans un binaire C++ strippe) orientent vers une exploitation FSOP (File Stream Oriented Programming) via la technique "House of Apple 2" :

1. Detourner le pointeur `_IO_list_all` en libc pour qu'il pointe vers une structure `FILE` contrefaite.
2. Declencher le nettoyage des flux via `exit(0)`, qui parcourt `_IO_list_all` et appelle les vtables de chaque flux.
3. La vtable contrefaite redirige l'execution vers `system("/bin/sh")`.

### Etape 1 — Fuite libc

Par empoisonnement de la freelist (meme principe que PWN#003, avec `rol 7` au lieu de `rol 13`), detourner une allocation vers les metadonnees d'un objet et remplacer son callback par `puts@PLT` pointant vers `puts@GOT`.

```
libc_base = puts_leak - puts_offset_glibc_2.43
```

### Etape 2 — Construction de la structure FILE contrefaite

La structure `FILE` contrefaite et les donnees wide associees representent :
- **Fake FILE** : `0xe0` octets (224 octets).
- **Wide-data** : `0xe8` octets (232 octets).

Ces structures sont ecrites comme **quatre allocations de classe 2** (taille `0x80` chacune), en utilisant les indices restants.

### Piege critique : " /bin/sh" avec espace initial

La chaine `"/bin/sh"` a un octet de poids faible `0x2f`, dont le bit 3 est a 1. Or, dans la structure `FILE`, ce bit correspond au drapeau `_IO_NO_WRITES`. Si ce drapeau est actif, la vtable de sortie n'est pas appelee et l'exploitation echoue.

**Solution** : utiliser `" /bin/sh"` (avec un espace initial), dont l'octet de poids faible est `0x20` (bit 3 a 0). La commande `system(" /bin/sh")` fonctionne car le shell ignore les espaces initiaux.

### Etape 3 — Empoisonnement de `_IO_list_all`

Par empoisonnement de la freelist, ecrire dans `_IO_list_all` l'adresse de la structure FILE contrefaite.

### Etape 4 — Declenchement via exit(0)

Provoquer l'appel a `exit(0)` (soit par retour normal du programme, soit par ROP). Le nettoyage des flux parcourt `_IO_list_all`, atteint la structure contrefaite, et appelle `system(" /bin/sh")` via la vtable detournee.

## Resultat

Shell obtenu via FSOP. Le flag a ete lu depuis la variable d'environnement `FLAG=` et depuis `/flag/flag.txt`.

```
CTF{REDACTED}
```

## Pieges rencontres

- **`e_entry` piege** : le point d'entree ELF (`0x269e`) provoque un SIGSEGV. Le vrai `_start` est a `0x1130`. Ce piege peut bloquer l'analyse statique si on ne le detecte pas.
- **Rotation `rol 7`** : l'encodage `mangle` utilise `rol 7` (et non `rol 13` comme PWN#003). Reutiliser l'exploit de PWN#003 sans ajuster la rotation echoue silencieusement.
- **Budget de 16 indices** : chaque ecriture coute 2 indices, soit 8 operations maximum. La fake FILE necessite 4 allocations, plus 2 pour la fuite libc et 2 pour l'empoisonnement final. Aucune marge d'erreur.
- **`"/bin/sh"` vs `" /bin/sh"`** : l'octet de poids faible de `"/bin/sh"` (`0x2f`) active `_IO_NO_WRITES`, ce qui empeche le declenchement de la vtable. Utiliser un espace initial (`" /bin/sh"`, octet `0x20`) contourne le probleme.
- **glibc 2.43-5** : la libc distante est differente de celle de PWN#001/002/003 (2.42-13). Les offsets de `system`, `puts`, `_IO_list_all` et des structures internes doivent etre recalcules. L'identification se fait par empreinte de symboles.
- **Fake FILE multi-allocations** : la structure `FILE` (0xe0) + wide-data (0xe8) ne tient pas dans une seule allocation de 0x80. Il faut la repartir sur quatre allocations contigues.

## Lecons

1. **House of Apple 2** : quand les contraintes interdisent le ROP classique ou `execve`, FSOP via `_IO_list_all` est une alternative puissante. Elle necessite la connaissance precise de la structure `FILE` de la libc cible.
2. **Attention aux bits de drapeau** : dans FSOP, chaque octet de la structure `FILE` peut avoir un sens. L'octet de poids faible de l'argument commande peut interagir avec les drapeaux internes du flux. Tester avec des variantes de la chaine.
3. **Budget d'allocation** : un nombre limite d'indices force a planifier toute la chaine avant d'ecrire le premier octet. Pas de place pour l'experimentation iterative.
4. **Pieges anti-analyse** : un `e_entry` piege est une technique anti-reverse classique. Toujours verifier que le point d'entree est valide avant de lancer l'analyse.
5. **Fingerprinting de libc** : sans libc fournie, l'empreinte des offsets GOT permet d'identifier la version exacte. Des outils comme `libc-database` ou `patchelf` automatisent ce processus.
