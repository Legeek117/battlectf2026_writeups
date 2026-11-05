# Operation BLACKHOLE (1–8) — Writeup

- **Catégorie :** out context (forensics réseau) · **Auteur :** Kondo
- **Points :** 5+5+10+10+10+15+15+30 = 100 (série de 8)
- **Fichier :** `CTF1.pcapng` (unique, partagé par les 8 questions) — 7 665 paquets, capture ~17 min (2026-09-17 12:40→12:58)
- **Flag (BLACKHOLE 8) :** `CTF{UF0N3t_DD0S_4n4lys1s_2026}`

## Scénario

« Acme Corp a subi une attaque DDoS ; le SOC a capturé le trafic. Analysez
`CTF1.pcapng` et répondez aux 8 questions. » En réalité ce n'est pas un DDoS
volumétrique distribué mais un **HTTP flood applicatif mono-source** (un seul
attaquant, 668 GET en rafale vers un serveur web sur le port 8000), avec
**rotation de User-Agent** pour imiter du trafic légitime.

## Setup

```bash
# le pcap se télécharge depuis le challenge (lien signé par token)
capinfos CTF1.pcapng        # 7665 paquets, 2026-09-17
```

## Réponses aux 8 questions

### Q1 — IP de la machine attaquante → `192.168.43.128`
Top talker + unique source du flood SYN/HTTP.
```bash
tshark -r CTF1.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src | sort | uniq -c | sort -rn
# 668  192.168.43.128   <- unique source de 668 SYN
```

### Q2 — IP de la cible → `192.168.43.1`
Destination des 668 connexions, héberge le serveur HTTP.
```bash
tshark -r CTF1.pcapng -Y "http.request" -T fields -e ip.dst | sort | uniq -c
```

### Q3 — Port TCP ciblé par l'attaque HTTP → `8000`
```bash
tshark -r CTF1.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e tcp.dstport | sort | uniq -c
# 668  8000
```

### Q4 — Méthode HTTP du flood → `GET`
```bash
tshark -r CTF1.pcapng -Y "http.request" -T fields -e http.request.method | sort | uniq -c
# 668 GET   <- le flood
#  45 M-SEARCH  <- bruit SSDP/UPnP (UDP 1900), pas l'attaque
```

### Q5 — User-Agent associé aux requêtes malveillantes → `curl/8.21.0`
L'attaquant **fait tourner des centaines d'UA de navigateurs** pour se fondre
dans la masse, mais l'outil réel se trahit : `curl/8.21.0` est le seul UA
non-navigateur et le plus fréquent (52 requêtes).
```bash
tshark -r CTF1.pcapng -Y "http.request && ip.src==192.168.43.128" \
  -T fields -e http.user_agent | sort | uniq -c | sort -rn | head
# 52  curl/8.21.0   <- signature de l'outil
# puis des dizaines d'UA navigateurs spoofés (10,9,9,...)
```

### Q6 — Durée de l'attaque (secondes) → `~79 s`
Fenêtre du premier au dernier GET du flood (≠ durée totale de la capture, 1060 s).
```bash
tshark -r CTF1.pcapng -Y "ip.src==192.168.43.128 && tcp.dstport==8000 && http.request" \
  -T fields -e frame.time_epoch | sort -n \
  | awk 'NR==1{f=$1} {l=$1} END{printf "%.3f s\n", l-f}'
# 79.113 s  (668 requêtes)
```

### Q7 — Nombre de requêtes HTTP dans la capture → `713`
`http.request` compte **713** (668 GET du flood + 45 M-SEARCH SSDP).
Nuance analyste : les 45 M-SEARCH sont du SSDP (HTTPU/UDP 1900), pas du HTTP/TCP ;
le flood strict = **668**. La réponse attendue est le compteur `http.request` = **713**.
```bash
tshark -r CTF1.pcapng -Y "http.request" | wc -l      # 713
tshark -r CTF1.pcapng -Y "http.request.method==GET" | wc -l   # 668
```

### Q8 — Flag caché dans un header HTTP → `CTF{UF0N3t_DD0S_4n4lys1s_2026}`
Le flag est planqué dans le header **`Referer`** des GET de l'attaquant :
`Referer: http://ctf.local/CTF{UF0N3t_DD0S_4n4lys1s_2026}`.
```bash
tshark -r CTF1.pcapng -Y 'http.request && ip.src==192.168.43.128' \
  -T fields -e http.referer | grep -oiE 'CTF\{[^}]+\}' | sort -u
# CTF{UF0N3t_DD0S_4n4lys1s_2026}
```

## Flag

```
CTF{UF0N3t_DD0S_4n4lys1s_2026}
```

## À retenir

- **Mono-source ≠ DDoS** : ici un seul attaquant (HTTP flood L7). La « distribution »
  est simulée par rotation d'User-Agent — ne pas se faire piéger, filtrer par `ip.src`.
- **La signature de l'outil se cache dans le bruit** : parmi des centaines d'UA
  navigateurs, le `curl/8.21.0` trahit l'automatisation.
- **Durée d'attaque ≠ durée de capture** : borner sur les paquets du flood.
- **Ne pas oublier les headers « inhabituels »** : un `Referer` pointant vers
  `ctf.local` est anormal — c'est là qu'était planqué le flag.
