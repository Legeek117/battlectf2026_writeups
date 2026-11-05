# OT#005 — Grid Command Injection · Investigation state

- **Target:** `169.58.126.107:6004` — "RTU Gatekeeper", IEC 60870-5-104-*inspired*
- **Goal:** open the *critical* breaker (1 of 2, with "vendor hardening") → grid
  destabilization event → flag `CTF{...}`. 150 pts, 0/3 attempts.
- **Status:** UNSOLVED. Endpoint rigorously characterized; a genuine feedback-less wall.

## What the endpoint actually does (verified, clean quiet window, + reference lib)

| Stimulus | Result |
|---|---|
| TCP connect | no banner, stays open ~10s |
| `68 04 07 00 00 00` (STARTDT_ACT) | **→ `68 04 0b 00 00 00`** (STARTDT_CON). The ONLY reaction. |
| trailing bytes of the 0x07 frame (`07 ff ff ff`, `07 01 01 00`, …) | ignored — response always `0b 00 00 00`, no side effect, no async |
| any LEN ≠ 4 (e.g. `68 06 …`, `68 0e …`) | silently dropped |
| STOPDT `0x13`, TESTFR `0x43`, S-frames, other U-opcodes | **silent** (a real IEC104 slave MUST answer TESTFR → it does not) |
| I-frames: GI (type 100) any CA 0/1/2/0xFFFF; C_SC(45)/C_DC(46) open, direct & many IOAs | **silent** — no response, no ACT_CON, no timer reset, no effect |
| injected ASDU after a `0x07` control field (`68 LEN 07 00 00 00 <asdu>`) | silent |

### Timer / flood facts
- Idle timeout = **10s from the last *processed* frame**; only STARTDT resets it.
- **Flood protection:** ~25 fast frames → server closes. Space frames ≥ ~1.5s.
- k-window: unacked I-frames pile up (server never acks) → client stacks close/reconnect.

### Reference-library confirmation (`c104`, battle-tested IEC104 master)
- STARTDT handshake → **Connection ACTIVATED** (CON received). ✓
- General Interrogation (CA=65535) → **TIMEOUT, no response.**
- `C_DC` commands (CA 1 & 65535, IOA 1..1001) → **`transmit=False`** (no ACT_CON);
  connection churns on the k-window. **My hand-rolled framing was never the bug.**

## Diagnosis (what this means)
The server implements **only the STARTDT handshake** and acknowledges nothing else.
No interrogation, no command ACK. Therefore:
- The point map **cannot** be enumerated via GI (the documented "discover by talking").
- Commands are at best **fire-and-forget**: a correct open of the *critical* breaker
  would produce **no ACK** — the only possible signal is a **spontaneous flag frame**
  (the "destabilization event") or an out-of-band reveal.
- With **zero feedback**, only the single correct `(type, CA, IOA, value, hardening-bypass)`
  tuple yields anything; everything else is indistinguishable silence. This is why
  Z.ai's ~80 blind I-frame variants all returned "silent" — a blind search here has
  no oracle to climb.

## Neighbors (ruled out)
6000/6003 other OT challenges (silent custom TCP); 6001 empty; **6002** = HTTP
"Rhein-Vogt Steelworks / Blast Furnace 2" — a *different* challenge. Flag is via 6004.

## Open hypotheses / what's missing
1. **Fire-and-forget + spontaneous flag:** need the exact critical-breaker `(CA, IOA)`
   and the "hardening" bypass (most likely **Select-Before-Operate**: S/E=1 select →
   S/E=0 execute). No oracle to find the IOA except the flag itself.
2. The command mechanism is **non-standard** (like OT-004's custom `<BI>` transport
   that *looked* like OPC-UA but wasn't). But here STARTDT is genuinely standard and
   everything past it is inert — so the "injection" may be a detail not visible to
   black-box probing of a silent server.
3. Different-IP exploration (Z.ai cracked OT-004 exactly this way) may see behavior our
   single rate-limited IP cannot.

## Tooling written (in `work/`)
`rawcap.py` `probe3.py` `timer.py` (timer-reset oracle) `oracle.py` `survey.py`
`inject.py` `stvar.py` `cmd_sweep.py` `opscan.py` `param_test.py`;
`/tmp/iec_client.py` + `/tmp/iec_cmd.py` (c104 reference master, venv `/tmp/iecvenv`).
