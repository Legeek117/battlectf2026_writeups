# OT#002 — Breaker 52 (custom binary, Aurora attack)

### Scenario
Generator tie-breaker controller at a substation interconnect. Objective: *"Physically
destroy the generator, then retrieve the flag that records the incident."* The briefing
states the **sync-check relay (ANSI device 25) is NOT PRESENT** — the whole hint in one line.

### Protocol recon (what the player discovers)
- **Custom binary TCP**, fixed **5-byte requests**: `[opcode][arg0][arg1][arg2][arg3]`.
- No banner; server waits for input. Connection is **persistent** (multi-command).
- **Response framing is length-by-opcode and must be exact**, or the byte stream desyncs and
  every later read is shifted (this bites players hard — see pitfalls):
  - `0x01` → **11-byte** telemetry: `[status=00][float32 LE grid_angle][float32 LE gen_angle][breaker_closed][00]`
  - `0x02..0x05` → **1 byte**
  - any other opcode → **1 byte** `0xff`
- Valid opcodes: only `0x01..0x05`.

### Command model (reverse-engineered)
| opcode | meaning |
|--------|---------|
| `0x01` | telemetry (two phase angles, breaker bit) |
| `0x02` | breaker status read (0 = open) |
| `0x03` | **generator status**: `01` online · `00` offline · **`02` = DESTROYED** |
| `0x04` | open breaker |
| `0x05` arg=1 | **close breaker** |

### The physics the challenge simulates
- `grid_angle` and `gen_angle` both rotate 0→360°. The generator runs at a slightly different
  frequency, so the **slip angle Δ = (grid − gen) mod 360** accumulates from 0 at ~5°/s.
- A fresh connection starts **synchronised** (Δ≈0). Closing the breaker at Δ≈0 is a *safe
  synchronisation* → nothing happens.
- Because there's **no sync-check interlock**, the breaker will close at **any** Δ. Closing
  near **Δ ≈ 180°** (anti-phase) produces the destructive torque transient = **Aurora**.

### The working attack
1. Open one connection; poll `0x01`, compute `Δ = (grid − gen) mod 360`.
2. Wait until `|Δ − 180| ≤ ~6°`.
3. Fire `0x05 01 00 00 00` (close) at that instant.
4. `0x03` reports `02` (generator destroyed) for a few ticks and the **flag is returned** in
   the responses; scan all bytes for `CTF{`.

### Minimal exploit
```python
# persistent socket, exact framing (11 bytes if opcode==0x01 else 1)
# loop: read 0x01 -> d=(grid-gen)%360 ; if abs(d-180)<=6: send b'\x05\x01\x00\x00\x00'
# then read telemetry/0x03 and regex the stream for CTF{...}
```

### Why it's a good challenge (designer notes)
- Pure **protocol-logic** vuln: the destructive primitive is the legitimate "close breaker"
  command; the bug is the *missing interlock*, stated plainly in the briefing for fairness.
- Forces real reverse-engineering with **no docs**: opcode enumeration, float endianness,
  and — crucially — **self-describing framing** (fixed length per opcode).
- The **timing/phase gate** makes it more than "send the magic byte": you must model the slip
  and fire in a window, which is satisfying and hard to brute.
- `0x03 == 0x02` as a distinct "destroyed" state is a clean, discoverable success signal.

### Pitfalls players hit (anti-frustration tuning)
- **Stream desync**: reading with a timeout-and-drain loop instead of exact lengths makes
  `0x03` appear to "randomly" return 00/01/02 and wastes hours. A good design choice *if*
  intended; otherwise document a length byte. (Here there's none — exact-length framing is
  the intended discovery.)
- Treating the two floats as independent/garbage (wrong endianness: they're **little-endian**).
- Closing at a random time (Δ small early in the connection) → "nothing happens", player
  concludes the close command is wrong.

---

## Design cookbook — building OT/ICS challenges like these
