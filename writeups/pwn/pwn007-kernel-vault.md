# PWN#007 — Kernel Vault

**Catégorie** : Pwn / Kernel  
**Points** : 148  
**Difficulté** : Hard  
**Flag** : `FLAG{REDACTED}`

## Description

Un driver kernel custom `/dev/vault` tourne dans une VM QEMU (Linux 6.1.176). Le but est d'obtenir root et lire `/root/flag.txt`. Le handout fournit `vmlinux` (symboles), `bzImage`, `initramfs.cpio.gz` et `run.sh`.

## Environnement

- QEMU x86_64, 256M RAM
- CPU flags : **SMEP activé**, **SMAP désactivé**
- BusyBox statique, utilisateur non-root `user`
- Driver vault intégré au kernel (pas de module externe)

## Analyse du driver

### Symboles identifiés

```
vault_open       — retourne 0
vault_release    — retourne 0
vault_ioctl      — toute la logique
vault_default_notify — callback par défaut (juste ret)
```

### Commandes ioctl

| Commande | Code | Taille arg | Description |
|----------|------|-----------|-------------|
| CREATE   | 0x40085601 | 8 | Crée un slot (id + taille) |
| DELETE   | 0x40045602 | 4 | Supprime un slot |
| READ     | 0x40105603 | 16 | Lit les données d'un slot |
| WRITE    | 0x40105604 | 16 | Écrit dans un slot |
| NOTIFY   | 0x40045605 | 4 | Appelle le callback du slot |
| LEAK     | 0x80085606 | 8 | Copie l'adresse de vault_ioctl vers userspace |

### Structure interne

Table globale de 16 slots (pointeurs). Chaque slot possède un header de 32 octets (kmalloc-32) :

```
offset 0x00 : callback obfusqué (XOR avec 0x6f6f56e06f2d7f60)
offset 0x08 : argument du callback
offset 0x10 : taille du buffer de données
offset 0x18 : pointeur vers le buffer de données
```

Le buffer de données est alloué séparément via `__kmalloc(size)`.

## Vulnérabilité : Use-After-Free

**DELETE ne remet pas `slots[id]` à NULL après les appels à kfree.**

Le code de DELETE :
1. Charge `slots[id]` dans un registre
2. Appelle `kfree(header->data)`
3. Appelle `kfree(header)`
4. Retourne 0

Mais `slots[id]` conserve le pointeur vers le header libéré. Les commandes READ, WRITE et NOTIFY continuent d'y accéder.

## Exploitation

### Étape 1 : Neutraliser KASLR

La commande LEAK copie l'adresse de `vault_ioctl` vers userspace. On calcule le slide KASLR :

```
slide = leaked_addr - 0xffffffff8156efa0
commit_creds = 0xffffffff810a13b0 + slide
init_cred    = 0xffffffff82851000 + slide
```

### Étape 2 : UAF → contrôle du callback

1. **CREATE slot 0** (size=32) → header_0 dans kmalloc-32, data_0 dans kmalloc-32
2. **DELETE slot 0** → kfree(data_0), kfree(header_0), mais `slots[0]` pointe toujours vers header_0
3. **CREATE slot 1** (size=32) → kmalloc réutilise la mémoire libérée
   - `data_1` récupère l'emplacement de header_0
   - `slots[0]` pointe vers `data_1`

### Étape 3 : Écrire le callback malveillant

**WRITE slot 1** écrit dans `data_1` (= ancien header_0), ce qui modifie les champs interprétés comme le header du slot 0 :

```
payload[0:8]  = XOR_KEY ^ commit_creds   (callback obfusqué)
payload[8:16] = &init_cred               (argument)
```

### Étape 4 : Déclencher l'escalade

**NOTIFY slot 0** lit le header (qui est maintenant notre payload) :
- Décode : `callback = XOR_KEY ^ payload[0:8] = commit_creds`
- Appelle : `commit_creds(&init_cred)`
- Le processus courant devient root

### Étape 5 : Lire le flag

```sh
cat /root/flag.txt
```

## Exploit (assembleur x86_64, ~8.5 KB statique)

L'exploit est écrit en assembleur pur (NASM) pour minimiser la taille et permettre un upload rapide via base64+gzip dans la VM. Seuls les syscalls `open`, `ioctl`, `getuid`, `write` et `execve` sont utilisés.

Le binaire fait 8576 octets, compressé en gzip+base64 : 744 caractères, uploadable en une seule commande shell.

## Points techniques

- **SMAP désactivé** : le kernel peut lire la mémoire userspace directement (pas de SMEP contournement nécessaire pour les données, seulement pour le code)
- **SMEP activé** : pas de retour direct vers du code userspace, mais la méthode `commit_creds(&init_cred)` n'en a pas besoin
- **XOR obfuscation** : le callback est protégé par un XOR avec une clé fixe, trivialement contournable une fois l'adresse de base connue
- L'allocation en kmalloc-32 pour data ET header (quand size ≤ 32) rend la réutilisation fiable
