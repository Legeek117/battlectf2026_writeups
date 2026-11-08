# PWN#004 — Pets Shelter

**Deliverable:** `pets` (ELF x86-64 C++ stripped, 18 568 B). **No libc shipped**, but the remote
runs **glibc 2.43-5** (Debian) — identified live by symbol low-12-bit fingerprint.
**Remote:** `169.58.126.107:5007`
**Flag:** `CTF{cd8831a9ea1fa9b3ab39da0ad921964aABIVaaaaaaaaa}` — **again in the env var `FLAG=`**
(also `/flag/flag.txt`), read through a `system(" /bin/sh")` shell.

### 0. TL;DR

A C++ "pet shelter" (Add/Remove/Poke/Speak pet, Add/Remove/Peek note, leak, exit) over the **same
hand-written pool allocator** as PWN#003. Two memory bugs: `poke pet` = `read(0, stack, 0x20)` +
`memcpy(pets[idx], stack, len)` into a **freed** object → **freelist poisoning**; `remove pet` =
`call *(*(pets[idx])+8)` (virtual call) with no whitelist check. Same primitives as PWN#003 give
arbitrary read/write within the binary. Because every `note` index is single-use and the
binary `exit`s on EOF, we go all the way to **FILE-structure exploitation**: **FSOP "House of
Apple 2"** through the wide vtable, hijacking `_IO_list_all` and triggering on `exit(0)` (option
`8`, or EOF in `read_long`) → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `system(" /bin/sh")`.

### 1. The trap: re-pointed ELF entry

The provided binary is **booby-trapped**: its `.e_entry` (`0x269e`) points at a junk trampoline
that `SIGSEGV`s *before* `main`, on purpose. The real `_start` is at **`0x1130`**. Fix for local
testing — patch `e_entry`:

```python
# copy 'pets' -> pets_e ; then
data = open("pets_e","rb").read()
# ELF64 header e_entry at file offset 0x18
open("pets_e","wb").write(data[:0x18] + struct.pack("<Q", 0x1130) + data[0x20:])
```

Remote was already run with the correct entry, so this only affects local runs.

### 2. Binary recon

C++ **stripped**, **PIE, Full RELRO** (BIND_NOW, `GNU_RELRO` covers `.got` `0x4f48..0x5000`),
Canary, NX, no seccomp. Requires **GLIBC_2.38+** (`__isoc23_strtol@GLIBC_2.38`).

Data layout (PIE-relative):
- `class_sizes` = `0x3010` = `[0x20,0x40,0x80]`
- `.rodata` = `0x3000`; `.data.rel.ro` = `0x4c50..0x4d48` (RO); `.got` = `0x4f48..0x5000` (RO)
- `.data` = `0x5000..0x5018`; `.bss` from `0x5018`, ends `0x5238`
- `stdout/stdin/stderr` = `0x5020/0x5030/0x5040`
- `pool` = `0x5060` (`malloc(0x4000)`), `pool_cursor` = `0x5068`, `freelist[3]` = `0x5070`
- **`pets[16]` = `0x50a0`**, `notes[16]` = `0x5120`, `notes_sizes[16]` = `0x51a0`, `whitelist[3]` = `0x5220`
- Free scratch zone: `0x5050..0x505f`
- Vtables in `.data.rel.ro`: Animal `0x4c60`, Cat `0x4c88`, Dog `0x4cb0`. **kind 0 → vtable `0x4cb0`**

GOT (pie-relative): `setvbuf 0x4f60`, `printf 0x4f68`, `write 0x4f70`, `strchr 0x4f78`,
`strncpy 0x4f80`, `memset 0x4f88`, `memcpy 0x4f90`, `exit 0x4fb8`, `read 0x4fc0`,
**`puts 0x4fc8`**, `__isoc23_strtol 0x4fd0`.

Menu (jump table `0x31a8`): `1` add pet `0x1744`, `2` remove pet `0x194b`, `3` poke pet `0x1a36`,
`4` speak `0x1b27`, `5` add note `0x1c12`, `6` remove note `0x1d55`, `7` peek note `0x1e18`,
**`8` exit `0x20a3`**, **`9` leak `0x1f0c`**.

### 3. Handler semantics

- **Option 9 (`0x1f0c`) — PIE leak.** `printf("%p\n", *(pets[idx]))` dereferences `pets[idx]` and
  prints the 8 bytes there. For a live pet that is its **vtable pointer** (`Cat` `0x4c88` /
  `Dog` `0x4cb0`) → `PIE = leak - 0x4cb0` for kind 0. It is also a **general 8-byte arbitrary read**:
  point `pets[i]` at any address and option 9 prints what it holds.
- **`poke pet` (3).** `read(0, stack_buf, 0x20)`; then `memcpy(pets[idx], stack_buf, len)`. If the
  pet object was already freed, this **rewrites a free chunk's `next` pointer** → freelist poison.
- **`remove pet` (2).** `call *(*(pets[idx]) + 8)` — a virtual call with `rdi = pets[idx]`, no check
  against `whitelist` — usable for control flow (we do not rely on it).
- **`add_note(idx,size)` (`0x1c12`).** **Refuses if `notes[idx] != 0`** ⇒ **each of the 16 indices is
  single-use**. `notes[idx] = palloc(size)`; `read(0, notes[idx], size)`. `remove_note` does **not**
  null `notes[idx]` (UAF for `peek`/poison) but the `!=0` guard means **16 allocations total**.
- **`peek note` (7).** `write(1, notes[idx], 0x20)` — read a live/freed chunk.
- **`read_long` (`0x16a9`).** On a `read <= 0` (EOF) it calls **`exit@plt(0)`** (`0x1700`). Streams are
  **unbuffered** (`setvbuf(..,_IONBF)`), so `puts`/`printf` flush immediately — no `_IO` buffer help,
  but `exit(0)` → `_IO_cleanup` is our trigger.

### 4. Allocator internals (identical to PWN#003)

- `get_class(size)` (`0x1219`): first class `>= size` (`<=0x20`→0, `<=0x40`→1, `<=0x80`→2, else `-1`
  = real `malloc` bypass).
- `mangle(a,b) = a ^ rol(b,7)`.
- `palloc`: pop head `h`; `next = *h; freelist[c] = next ^ rol(h,7)`; else bump from `pool_cursor`.
- `pfree(ptr,size)` (`0x1418`): uses the class of the **passed `size`** (not the chunk's real class!);
  `*ptr = freelist[c] ^ rol(ptr,7)`; `freelist[c] = ptr`. **No validation of `ptr`.**

### 5. Primitives

- **Heap leak.** `add_note(0,0x20)` then `remove_note(0)`: `freelist[0]` was empty → the freed
  chunk holds `rol(chunk,7)`. `peek_note(0,8)` → `chunk = ror(leak,7)`; the pet object is
  `pool + 0x20` ⇒ **`pool = ror(peek,7) - 0x20`**.
- **PIE leak.** option 9 on pet 0 (vtable `0x4cb0`).
- **Arbitrary write.** With `poke_pet(1)` rewriting a freed class-0 chunk `C0`:
  `poke_pet(1, tgt ^ rol(C0,7))`; `add_note(a,0x20)` pops `C0` → `freelist[0] = tgt`;
  `add_note(b,nb,data)` pops `tgt` and writes `data` there; `remove_note(a)` repushes `C0` so the
  primitive can be reused. **Each use costs 2 note indices.**
- **libc leak.** Point `pets[0] = &puts@GOT` (`0x4fc8`) via the write primitive, then option 9 →
  `puts` runtime address. `libc = puts - puts_off` (must be page-aligned; else retry).
- **Class-2 (`0x80`) channel.** Allocate+free a `0x80` note → `freelist[2]` was empty so the freed
  chunk stores `rol(chunk,7)` → `Hc2 = ror(peek(ci,8),7)`. Same poisoning with `Hc2` gives a
  second, independent write channel (needed because the fake FILE spans more than a 0x20 write).

### 6. FSOP — House of Apple 2 (trigger on `exit`)

Because every index is single-use and there is no direct `system(x)` gadget with controlled `rdi`,
we hijack the `exit(0)` path (option `8`, or EOF) via `_IO_cleanup → _IO_flush_all`.

Chain:
```
_IO_list_all = F
_IO_flush_all walks the list; F->_wide_data  ->  _IO_wfile_overflow(F)
  _IO_wfile_overflow:  if (_flags & _IO_NO_WRITES(0x8)) -> EBADF (NO doallocate!)
                       else if (_wide->_IO_write_base < _IO_write_ptr)
                            -> _IO_wdoallocbuf(F)
  _IO_wdoallocbuf: call _wide->_wide_vtable->__doallocate(F)
```
Fake **`_IO_FILE` F** (fields, offsets relative to F):
- `F[0x00] = " /bin/sh"` — low byte `0x20`, so **`_IO_NO_WRITES` (bit 3) is CLEAR**; and as a C
  string this is `" /bin/sh"`, which `system` happily runs. (**This is the bug that cost hours:** the
  natural `"/bin/sh\x00"` has low byte `0x2f` → bit 3 set → `_IO_wfile_overflow` returns EBADF and
  `_IO_wdoallocbuf` is never reached.)
- `F[0x28] = 1` (`_IO_write_ptr`) > `_IO_write_base` (`F[0x20]=0`)
- `F[0x88] = LK` (`_lock`, points at a zeroed scratch region so locking is benign)
- `F[0xa0] = W` (`_wide_data`)
- `F[0xd8] = libc+_IO_wfile_jumps` (`_vtable`, so the FILE looks wide)
- `F[0x78] = system` — the fake jump table is placed at `F+0x10`, and `__doallocate` sits at
  **offset `0x68`** in the wide-jumps-like table ⇒ slot address `F+0x10+0x68 = F+0x78`.

Fake **`_IO_wide_data` W**:
- `W[0x20] = 1` (`_IO_write_ptr`) > `W[0x18]=0` (`_IO_write_base`) ⇒ `_IO_wfile_overflow` proceeds
- `W[0xe0] = F+0x10` (`_wide_vtable` = our fake table inside F)

Then `_IO_list_all = F` (written **early**, before the class-2 writes, to avoid re-entry issues),
and trigger: send `8\n` (exit) — or just close the socket (EOF → `read_long` → `exit(0)`).

Note: the fake FILE spans `0xe0` bytes and `W` spans `0xe8`, so each is written as **two `0x80`
class-2 allocations** (total 4 × 2 = 8 indices), plus the class-0 writes (libc leak + `_IO_list_all`
+ repointing `pets[2]`) share the remaining 8 indices. **`solve2`'s `nx()` asserts `i <= 15`** and
reports `note indices used = 16`.

### 7. Remote libc identification (glibc 2.43-5)

No libc was shipped and the local test libc (2.43-4) did **not** match the remote. We fingerprinted
the remote by leaking several GOT entries through the arbitrary-read primitive and matching their
**low 12 bits** (ASLR-independent) with **libc.rip**:

| symbol | low-12 |
|--------|--------|
| `puts` | `be0` |
| `read` | `480` |
| `write`| `ee0` |
| `printf`| `dc0` |
| `memcpy`| `670` |
| `memset`| `100` |
| `exit`  | `c10` |

`POST https://libc.rip/api/find {"symbols":{"puts":"be0","read":"480"}}` → **`libc6_2.43-5_amd64`**
(`puts 0x81be0`, `read 0x106480`, `write 0x106ee0`, `printf 0x5adc0`, `system 0x541b0`). Its
symbols file (`…/libc6_2.43-5_amd64.symbols`) gave `_IO_list_all 0x1e8480` and
`_IO_wfile_jumps 0x1e6228` (identical to 2.43-4 here).

> **Tip — one-read-per-connection.** Cross-connection ASLR makes absolute gaps meaningless; only
> the **low 12 bits** are stable. The remote throttles/serialises many rapid ops, so leaking each
> anchor in a **fresh connection** (and comparing low-12 bits) is far more robust than many writes
> on one socket.

### 8. Offsets used

Binary: PIE leak vtable `0x4cb0`; `pets[16]=0x50a0`; `puts@GOT=0x4fc8`.
Remote **glibc 2.43-5**: `puts=0x81be0`, `system=0x541b0`, `_IO_wfile_jumps=0x1e6228`,
`_IO_list_all=0x1e8480` (`_IO_wdoallocbuf=0x84da0`, `_IO_wfile_overflow=0x86b60`).
Local **glibc 2.43-4** (for the local harness): `puts=0x81e20`, `system=0x543f0`,
`_IO_list_all=0x1e8480`, `_IO_wfile_jumps=0x1e6228`.

### 9. Dead ends / pitfalls hit

- **Booby-trapped `e_entry` (`0x269e`)** → `SIGSEGV` before `main`. Patch to `0x1130` for local runs.
- **`_flags` bit 3 (`_IO_NO_WRITES`)** — the classic FSOP killer. `"/bin/sh\x00"` (low byte `0x2f`,
  bit 3 set) makes `_IO_wfile_overflow` bail with EBADF before `_IO_wdoallocbuf`. Use
  **`" /bin/sh"`** (leading space, low byte `0x20`) so bit 3 is clear and `system(" /bin/sh")` runs.
  If `_IO_wfile_overflow` also checks `_IO_NO_WRITES`/read-end flags, keep `_flags` minimal
  (only low byte set) so nothing else is accidentally set.
- **`add_note` refuses a used index** and `remove_note` does not clear it ⇒ **16 indices total**, and
  every arbitrary write costs 2 ⇒ budget ~8 writes. The fake FILE `0xe0` + wide-data `0xe8` must
  therefore be split into four `0x80` writes.
- **`remove_pet` calls `rdi=pets[i]`, `rdx=*(pets[i]+8)`** — the direct `system("/bin/sh")` route
  needs a chunk holding `/bin/sh` with `system` in the next qword; this *does* work (used in an
  earlier variant) but the FSOP route is cleaner and independent of `whitelist`.
- **Remote throttling** and unbuffered streams → after the trigger, keep reading with a generous
  timeout; the shell banner (`PWNED_42`) confirms code execution.
- **`puts` leak is a C-string** (stops at first `\0`) — option 9 in this binary uses `printf("%p")`,
  so the full 8 bytes are printed; still, treat a page-unaligned `libc` as a bad match and retry.

### 10. Solver

`/tmp/opencode/pwn004/solve2.py` (stdlib only, retry-friendly; `harness.py` provides the TCP helper,
freelist-poison `arb_write`, PIE/heap leaks, and option-9 read). Run against remote:
`python3 solve2.py 169.58.126.107 5007` → `[+] SHELL OK`, then
`cat /flag/flag.txt; env | grep -i FLAG`.
Flag confirmed: `CTF{cd8831a9ea1fa9b3ab39da0ad921964aABIVaaaaaaaaa}`.

---

## PWN#Delta — Vault Terminal (PowerPC)
