# OT#002 — Breaker 52 (protocole binaire custom, attaque Aurora)

- **Cible :** `<HOST>:<PORT>` (contrôleur de disjoncteur de générateur, interconnexion sous-station)
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}` (voir règle de non-persistance des flags)
- **Protocole :** TCP custom, requêtes de 5 octets fixes

## Contexte

Contrôleur du disjoncteur de couplage (tie-breaker) d'un générateur à une sous-station d'interconnexion. Objectif : « Détruire physiquement le générateur, puis récupérer le flag qui enregistre l'incident. » Le briefing indique que le **relais de vérification de synchronisme (dispositif ANSI 25) n'est PAS PRÉSENT** — tout l'indice en une ligne.

## Identification du protocole

- **TCP binaire custom**, requêtes fixes de **5 octets** : `[opcode][arg0][arg1][arg2][arg3]`.
- Pas de bannière ; le serveur attend l'entrée. Connexion **persistante** (multi-commandes).
- **Le cadrage des réponses est fixe par opcode** et doit être exact, sinon le flux d'octets se désynchronise et chaque lecture suivante est décalée :
  - `0x01` → **11 octets** de télémétrie : `[status=00][float32 LE angle_réseau][float32 LE angle_générateur][disjoncteur_fermé][00]`
  - `0x02..0x05` → **1 octet**
  - tout autre opcode → **1 octet** `0xff`
- Opcodes valides : uniquement `0x01..0x05`.

## Modèle de commandes

| opcode | signification |
|--------|---------------|
| `0x01` | télémétrie (deux angles de phase, bit disjoncteur) |
| `0x02` | lecture état disjoncteur (0 = ouvert) |
| `0x03` | **état du générateur** : `01` en ligne · `00` hors ligne · **`02` = DÉTRUIT** |
| `0x04` | ouvrir le disjoncteur |
| `0x05` arg=1 | **fermer le disjoncteur** |

## Physique simulée

- `angle_réseau` et `angle_générateur` tournent de 0 à 360°. Le générateur tourne à une fréquence légèrement différente, donc l'**angle de glissement Δ = (réseau − générateur) mod 360** s'accumule à ~5°/s.
- Une connexion fraîche démarre **synchronisée** (Δ≈0). Fermer le disjoncteur à Δ≈0 est une *synchronisation sûre* → rien ne se passe.
- Comme il n'y a **pas de vérification de synchronisme**, le disjoncteur se ferme à **n'importe quel Δ**. Fermer près de **Δ ≈ 180°** (opposition de phase) produit le transitoire de couple destructeur = **Aurora**.

## Méthode

1. Ouvrir une connexion ; interroger `0x01`, calculer `Δ = (réseau − générateur) mod 360`.
2. Attendre que `|Δ − 180| ≤ ~6°`.
3. Envoyer `0x05 01 00 00 00` (fermer) à cet instant.
4. `0x03` renvoie `02` (générateur détruit) pendant quelques cycles et le **flag est renvoyé** dans les réponses ; scanner tous les octets pour `CTF{`.

## Squelette d'exploit

```python
# socket persistant, cadrage exact (11 octets si opcode==0x01, sinon 1)
# boucle: lire 0x01 -> d=(réseau-générateur)%360
#   si abs(d-180)<=6: envoyer b'\x05\x01\x00\x00\x00'
# puis lire télémétrie/0x03 et regex le flux pour CTF{...}
```

## Résultat

Flag récupéré après fermeture du disjoncteur en opposition de phase (Δ ≈ 180°).

```
CTF{REDACTED}
```

## Pièges rencontrés

- **Désynchronisation du flux** : lire avec un timeout-and-drain au lieu de longueurs exactes fait apparaître `0x03` comme « aléatoirement » 00/01/02 et gaspille des heures. Le cadrage exact par opcode est la découverte attendue.
- **Endianness des floats** : les deux angles sont en **little-endian** — tester les deux endianness tôt.
- **Fermeture à un moment aléatoire** (Δ faible au début de la connexion) → « rien ne se passe », on conclut à tort que la commande close est incorrecte.

## Ancrage historique

Reproduit l'**INL Aurora Generator Test de 2007** : destruction physique d'un générateur diesel par fermeture hors synchronisme du disjoncteur de couplage. La vulnérabilité est l'absence d'interlock de sécurité sur le fil, pas un bug mémoire.

---

*Write-up par **Le_Geek** — BUG|PWN CTF · OT#002 Breaker 52.*
