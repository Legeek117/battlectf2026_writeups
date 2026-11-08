# PWN#Delta — Vault Terminal (PowerPC)

**Objective (verbatim):** *"Get a shell on the remote host and read the flag."*
**Deliverable:** `vault` — ELF 32-bit **PowerPC**, big-endian, **statically linked, NOT stripped**
(1949 symbols), Canary found, NX, Partial RELRO, No PIE.
**Flag:** `CTF{c9a9816576849a4aae690a65c1fba37d}`

### 0. TL;DR

Same "Vault Terminal" name/message prompt loop as PWN#001/002, recompiled for PowerPC32. A
64-byte stack buffer, 65-byte `read()` for the name (classic off-by-one into the canary's low
byte), 108-byte `read()` for the message (reaches well past the saved return address). Because
the binary is **not stripped**, the symbol table hands over two custom helper functions —
`gadget_load_r9` and `gadget_vec_r3` — planted by the challenge author specifically to make PPC
ROP tractable. The real win, though, came from *not* fighting PPC's `stwu` auto-write-back
convention but *using* it: `stwu r1,-0x30(r1)` unconditionally writes the **old** `r1` (a stack
address, the "back-chain") to the exact stack slot the author's gadget reads into `r9` before a
clean `mr r3,r9; blr`. Feed the chain nothing but a 4-byte filler/command string (`"sh\0"`) placed
at that back-chain-pointed offset and `system()` runs it — **no libc leak, no ASLR dependency,
works even though the target binary is PIE-free and the loader is not.**

### 1. Binary recon

- `vuln` at `0x100008f0`, called from `main` (`0x10000a80`) in an unconditional loop
  (`bl vuln; b` back to the call — same shape as PWN#001/002/Beta).
- Stack frame: `stwu r1,-0x70(r1)`; buffer at `r31+0x1c`; canary saved/checked at `r31+0x5c`
  (**buffer offset 0x40 = 64**, matching the x86 binaries exactly); saved `r30`/`r31`/`LR` at
  `r31+0x68/0x6c/0x74` (**buffer offsets 76/80/88**).
- `read(0, buf, 0x41)` for the name (65 into a 64-byte buffer — 1-byte overflow of the canary's
  low byte only); `read(0, buf, 0x6c)` for the message (108 bytes — reaches past `LR`).
- No seccomp. `do_system` and `system` (`0x100020d0`) are present (static binary, so
  `system()`/`"/bin/sh"` addresses are **fixed, no libc leak needed**). `"/bin/sh\0"` lives at
  `0x10074850`.
- Planted gadgets (found via `nm`, not normally present in a PPC glibc static binary):
  - `gadget_load_r9` @ `0x100007cc`: `stwu r1,-0x30(r1); ...; lwz r9,0(r1); lwz r0,4(r1); mtlr r0;
    addi r1,r1,8; blr` — looks like a clean "pop r9 / pop next-LR" gadget.
  - `gadget_vec_r3` @ `0x10000834`: an AltiVec `vperm`/`vsel` obfuscated constant loader (decoy —
    not needed for the exploit; computes `0` after working through it by hand).
  - A library-wide gadget search (capstone, `skipdata=True` — **objdump has no PowerPC target on
    this box**, and a plain `Cs(...).disasm()` silently stops at the first undecodable opcode
    without `skipdata`) finds a clean **`mr r3, r9; blr`** at `0x10015b40` (several duplicates
    exist), plus a "fatter" variant `mr r3,r9; lwz r0,<off>(r1); lwz r30,<off-0xc>(r1);
    addi r1,r1,<off+4>; mtlr r0; blr` at several addresses with different reload offsets
    (`0x14`, `0x24`, `0x34`, `0x44`) — the offset choice matters (§4).

### 2. The `stwu` back-chain trick (the actual key insight)

PowerPC `stwu rS,D(rA)` is store-*then*-update: it writes **rA's old value** to `EA = rA+D`, then
sets `rA = EA`. `gadget_load_r9`'s first instruction, `stwu r1,-0x30(r1)`, therefore
**unconditionally clobbers** whatever the attacker placed at the slot it's about to read `r9`
from (buffer offset 36) with the *old* `r1` — i.e. a live stack address (`R1_main`, the frame
pointer `vuln` was called with). Planting `"/bin/sh"`'s address there is pointless; it never
survives. Two options:
1. Accept that `r9` becomes `R1_main` (a stack pointer) and make **that address itself** hold the
   payload: point `r9`'s eventual target (`buffer+80`, which the fatter `mr r3,r9` gadget reloads
   as the *next* LR, see below) at a scratch slot, and put the raw command bytes there instead of
   a pointer anywhere.
2. Concretely: place the literal bytes `b"sh\x00\x00"` at **buffer offset 84** (`R1_main-8` region,
   past the back-chain-corrupted word), because `system(r3)`'s `r3` ends up being the **address**
   `R1_main` (`buffer+84`-ish after the fatter gadget's own stack walk) rather than a value we
   chose — `system()` then reads the command directly out of *its own calling frame*, which is
   exactly the bytes we wrote. No `/bin/sh` string address, no libc, no leak — the exploit is
   entirely stack-pointer-relative and ASLR-proof by construction.

### 3. Byte-exact chain (`vuln`'s message buffer, 100 bytes total)

```
[0:36)   filler "A"*36
[36:40)  p32(BINSH_ADDR)        # clobbered by stwu's back-chain write — unused, keep as filler
[40:44)  p32(STAGE2)            # 0x10061724: mr r3,r9; lwz r0,0x24(r1); lwz r30,0x18(r1);
                                 #   addi r1,r1,0x20; mtlr r0; blr   (reload offset chosen to land
                                 #   past the canary — 0x14 collides with it, 0x24 lands on the
                                 #   old r31-restore slot which vuln only *reads*, never reused)
[44:64)  filler "B"*20
[64:68)  p32(leaked_canary)      # from the name-buffer info leak (§4)
[68:84)  filler "C"*16 + "D"*4
[84:88)  b"sh\x00\x00"           # becomes system()'s argument via the back-chain pointer
[88:92)  p32(GADGET_LOAD_R9)     # 0x100007cc — vuln's real hijacked return address
[92:96)  filler "E"*4
[96:100) p32(SYSTEM_ADDR)        # 0x100020d0 — STAGE2's reloaded LR
```
Flow: `vuln` returns into `gadget_load_r9` → its `stwu` writes the back-chain pointer over
`buf+36`, then pops `r9=buf+36`'s (now back-chain) content and a new LR from `buf+40` (`STAGE2`) →
jumps to `STAGE2`, which sets `r3=r9` (a stack address pointing at `buf+84`-ish, i.e. `"sh\0"`),
reloads LR from `buf+80` (`SYSTEM_ADDR`), and returns into `system()`. `system("sh")` spawns a
shell on the inherited stdio (the socket).

### 4. Canary leak (info leak via a dangling non-null-terminated `%s`)

Identical mechanic to the x86 binaries: `name` is read with `read(0,buf,0x41)` (65 bytes) into a
64-byte buffer with **no forced NUL**, then printed with `printf("Hello, %s\n", name)`. Send
exactly **65 bytes of filler (no trailing newline!)** — the 65th byte lands on the canary's own
low byte (always `0x00` for glibc's SSP) and overwrites it with non-null filler, so `%s` doesn't
stop there and keeps printing the **real** remaining 3 canary bytes plus whatever follows
(constant stack content across connections — confirms **no stack ASLR** under this deployment) —
until it hits the *next* natural `0x00`. This leaks the canary **in one shot, same connection**,
with enough slack left to still complete the message step correctly (no trailing `\n` means the
name's own `read()` doesn't bleed into the message `read()`).

### 5. Dead ends / pitfalls hit

- **No `objdump` ARM/PPC/MIPS target on this box** — binutils here only knows `x86_64`. Use
  `capstone` with `md.skipdata = True`; without it the linear disassembler silently stops at the
  first AltiVec/undecodable opcode and returns a near-empty instruction list (looked like "only
  45 instructions in the whole binary" before this was caught).
- **Naive gadget search found many `mr r3,r9` instances followed by a `bl` (real call), not a
  `blr`** — those aren't usable as a clean 1-hop gadget chain; only the handful immediately
  followed by `blr` (or by a load-LR-then-blr epilogue) are safe to jump into blind.
- **First choice of fatter-gadget reload offset (`0x14`) silently overlapped the canary slot** —
  since that offset is relative to the *already-advanced* `r1` after `gadget_load_r9`'s own pop,
  not to the original buffer, the arithmetic has to track `r1`'s value at *each* hop, not just the
  original buffer offsets.
- **Assumed `/bin/sh`'s fixed address was the way to set `system()`'s argument** — wrong, because
  `gadget_load_r9`'s own `stwu` prologue destroys exactly that stack slot before it can be read.
  Recognizing the back-chain write and *using* it (rather than avoiding it) is what unblocked the
  chain.

### 6. Solver

Local validation used `qemu-ppc` + a downloaded armhf-equivalent PPC rootfs via `pty.fork()`
(`harness.py`), confirmed byte-for-byte against a `qemu -d in_asm,cpu` register trace before firing
at the real target — this caught the `r9` back-chain surprise (saw `r9 == buf+84`, not
`BINSH_ADDR`, in the trace) that a blind remote-only attempt would have burned many tries on.
Remote: `python3 exploit2.py 169.58.126.107 5011` → `[+] SHELL OK` → `cat /flag/flag.txt`.
Flag confirmed: `CTF{c9a9816576849a4aae690a65c1fba37d}`.

---

## PWN#Alpha — Vault Terminal (ARM)
