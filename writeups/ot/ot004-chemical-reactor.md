# OT#004 — Chemical Reactor (protocole binaire custom, style OPC-UA)

- **Cible :** `<HOST>:<PORT>` — page du challenge : https://otctf.pages.dev/ot-004-chemical-reactor/
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}`
- **Protocole :** TCP binaire custom (annoncé « OPC-UA-style », mais pas de l'OPC UA binaire réel)

## Contexte

Un réacteur chimique avec un Safety Instrumented System (SIS) censé déclencher un arrêt
avant toute condition dangereuse soutenue. Address space annoncé : `Objects (ns=0, id=85)`
→ `Reactor Controller` (tags process) + `Safety System` (trip/protection). Aucune
documentation fournie : « discover them by talking to the endpoint » — pas de source, pas
de binaire, pas de carte des nœuds.

## Investigation — cadrage du transport (confirmé)

- TCP ouvert, **pas de bannière** : le serveur attend que le client parle en premier.
- **Ce n'est pas de l'OPC UA binaire réel** : un HEL OPC UA (`HELF` + taille LE + corps),
  testé à la fois à la main et via `asyncua`, provoque une fermeture immédiate.
- Framing confirmé par essais successifs : **`[uint32 big-endian longueur][payload]`**, la
  longueur ne comptant que le payload (hors en-tête) :
  - `len=8` + 3 octets → connexion vivante, le serveur attend les 5 octets restants.
  - `len=4`, en-tête seul → vivant, attend 4 octets de payload.
  - `len=0` (trame vide) → vivant : no-op, le serveur reboucle sur la trame suivante.
  - 5 octets `AAAAA` → fermeture (`len=0x41414141` ≈ 1 Go, dépasse un plafond → rejet).
  - Un HEL OPC UA ferme pour la même raison (`"HELF"` lu comme une longueur énorme).

## Investigation — couche message (bloquante un temps)

Le serveur **ferme en silence** sur toute trame complète mal formée, et **ne répond
jamais** quoi qu'on envoie (ni avant ni après `shutdown(SHUT_WR)`), ce qui rend le
brute-force à l'aveugle du format de payload très coûteux (chaque essai = une nouvelle
connexion, sous rate-limit). Essayé sans succès pendant cette phase, tout provoquant une
fermeture silencieuse :

- Texte brut framé : `hello`, `HELLO`, `Read`, `Browse`, `Write`, `PING`,
  `BROWSE 85\n`, `WRITE 85 1\n`, etc.
- JSON framé : `{"op":"hello"}`, `{"type":"Hello"}`, `{"op":"browse","node":"ns=0;i=85"}`, etc.
- Binaire framé : opcodes `0x00`-`0x09` + `u32be(85)`, mono-octets `'H'/'B'/'R'/'W'`, en-tête
  OPC UA `HEL`/`HELF` + corps, NodeId OPC UA 2 octets.

**Piège noté** : un timeout de lecture n'est pas une preuve de connexion vivante — le
serveur tarde parfois à envoyer le FIN. Seule la réception effective de données compte
comme signal positif ; sinon on croit à tort qu'un essai « passe ».

**Rate-limit observé** : ~20 connexions rapides (≈10/min) → ban (EOF immédiat sur tout,
même passif), levé après ~8 min de silence total. ~5 connexions/min (12 s d'écart) reste
tenable sur 10+ connexions sans déclencher de ban.

## Protocole réel (résolution)

Le format réel n'a pas été deviné par brute-force aveugle mais obtenu après avoir croisé
plusieurs hypothèses avec les comportements observés : **`[op:u8][len:u32 little-endian][payload]`**.
L'erreur bloquante était de lire le premier octet comme une longueur big-endian — c'est en
réalité l'opcode, et la longueur qui suit est little-endian (pas big-endian comme au niveau
transport).

- `0x01` handshake (payload vide) → réponse `0x81` + session id (`u32` LE).
- `0x03` read : payload `<I H I>` (`sid, ns, nid`) → corps `u32 | status:u8 | type:u8 | value`.
- `0x04` write : payload `<I H I>` (`sid, ns, nid`) + `type:u8` + `value` → status en `body[4]`.
- Types de valeur : `1` = i32, `2` = f64, `3` = bool, `4` = string.

### Nœuds clés

| Namespace.ID | Rôle |
|---|---|
| `(1, 1001)` | `HeaterPower` (f64) — commande process |
| `(1, 1002)` | `Temperature` (lecture) |
| `(1, 1003)` | `Pressure` (lecture) |
| `(2, 2001)` | `TripEnable` (bool) — **SIS** |
| `(2, 2008)` | `PretripLatch` (bool) — **SIS** |
| `(2, 2003)` | `Tripped` (lecture) |
| `(2, 2004)` | `Flag` (string) — ne se peuple qu'en condition dangereuse |

## Faille

Le SIS est censé être indépendant du process controller, mais il partage la **même
address space et la même session** : les opérations génériques read/write (`0x03`/`0x04`)
permettent d'écrire directement dans ses nœuds, exactement comme pour n'importe quel tag
process. Aucune séparation de privilège entre « lire/écrire un process value » et
« modifier l'état d'un système de sécurité ».

## Méthode

1. Handshake `0x01` → récupérer la session id.
2. Write `TripEnable = False` sur `(2, 2001)` et `PretripLatch = False` sur `(2, 2008)` →
   le SIS ne peut plus déclencher l'arrêt.
3. Write `HeaterPower = 100.0` sur `(1, 1001)` → runaway thermique soutenu (la température
   monte sans jamais être coupée).
4. Lire en boucle `(2, 2004)` : le flag ne se peuple que pendant que la condition
   dangereuse est active (`Tripped` doit rester à `0`), donc lire pendant le runaway, pas
   après coup.

## Script (solver)

Voir `challenges/ot-004-chemical-reactor/solve.py` — handshake, désactivation des deux
drapeaux SIS, write `HeaterPower=100.0`, puis polling de `(2, 2004)` jusqu'à apparition du
flag.

## Résultat

Température observée ~540-620 °C sans jamais déclencher `Tripped`. Flag récupéré dans
`(2, 2004)` : `CTF{REDACTED}` — à soumettre par l'utilisateur.

## Pièges rencontrés

- Le transport (framing `u32be` longueur) et la couche message (`op:u8` + `u32 LE`
  longueur) utilisent **deux endianness différentes** — s'y perdre fait croire à un
  protocole entièrement opaque alors que seule la couche interne diffère.
- Le silence total du serveur sur une trame mal formée (jamais de message d'erreur) rend
  le brute-force à l'aveugle peu rentable ; mieux vaut croiser les indices (nom du
  protocole annoncé, comportements de fermeture) que fuzzer sans hypothèse.
- Le flag est **conditionnel à l'état dangereux en cours** : le lire après un trip annule
  l'observation, il faut maintenir la condition pendant la lecture.

## Généralisation

Vérifier systématiquement, pour tout protocole exposant un SIS/safety layer : la couche
sécurité partage-t-elle le même espace d'adressage et le même canal d'écriture que la
couche process ? Si oui, et si les deux sont accessibles depuis la même session, la
« protection » n'est qu'une convention logicielle sans isolation réelle.

---

*Write-up par **Le_Geek** — BUG|PWN CTF · OT#004 Chemical Reactor.*
