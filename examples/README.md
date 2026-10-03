# Example applications

## The GNAP stack (`docker compose up`)

Four applications that together form a complete GNAP deployment:

| Service | Project | URL | What it shows |
|---|---|---|---|
| `authorization-server` | [`GnapAuthorizationServer`](GnapAuthorizationServer) | <http://localhost:5100> | `Gnap.AspNetCore` AS, Razor Pages consent UI, EF Core/SQLite stores, RFC 9767 introspection for the registered RS |
| `resource-server` | [`GnapResourceServer`](GnapResourceServer) | <http://localhost:5200> | GNAP-protected minimal API: `GET /photos` requires `photo-api`/`read`; registers its resource set and challenges with `WWW-Authenticate: GNAP` |
| `web-client` | [`GnapWebClient`](GnapWebClient) | <http://localhost:5300> | ASP.NET Core web app with the redirect flow (finish hash verification, continuation) |
| `console-client` | [`GnapConsoleClient`](GnapConsoleClient) | — | CLI with the user code flow: RS-first discovery, prints a code, polls, calls the RS |

```bash
docker compose -f examples/docker-compose.yml up --build
```

Then:

- **Console client:** the `console-client` log shows
  `Open http://localhost:5100/gnap/device … and enter the code: ABCD-EFGH`. Open the URL,
  enter the code, type any user name on the consent page and approve. The client then
  prints the resource server's answer: `GET http://localhost:5200/photos -> 200 OK`.
  Run it again with `docker compose -f examples/docker-compose.yml run --rm console-client`.
- **Web client:** open <http://localhost:5300>, click *Connect*, approve on the AS consent
  page; you are sent back to the web client, which shows the photos it fetched with the
  key-bound token.

`examples/e2e.sh` plays the resource owner with `curl` and checks both flows; CI runs it
against the compose stack on every push.

All services share the authorization server's network namespace, so every URL is
`http://localhost:<port>` for the containers and for your browser. **Demo only:** the
resource server key in `docker-compose.yml` is published, the consent page trusts any
user name, and everything runs over plain HTTP. See the
[threat model](../docs/threat-model.md) for what a real deployment needs.

### Without Docker

```bash
export ResourceServers__0__Id=demo-rs
export ResourceServers__0__Jwk='{"kty":"EC","crv":"P-256","kid":"demo-rs","x":"n79Lezu9h2nFG6_HurqeZ7p0gjiU8NQjVLOi9_sBCvc","y":"IhanmT9ReUwOvESp_KWZcyNnKwVzLmUwGKSDPZyUXoM"}'
dotnet run --project examples/GnapAuthorizationServer --urls http://localhost:5100 &

export Gnap__SigningKey='{"kty":"EC","crv":"P-256","kid":"demo-rs","x":"n79Lezu9h2nFG6_HurqeZ7p0gjiU8NQjVLOi9_sBCvc","y":"IhanmT9ReUwOvESp_KWZcyNnKwVzLmUwGKSDPZyUXoM","d":"uq2RFBqXKey0b1kseqJZ6_K_Cgykcvk9gALRv1LgShk"}'
dotnet run --project examples/GnapResourceServer --urls http://localhost:5200 &
dotnet run --project examples/GnapWebClient --urls http://localhost:5300 &

dotnet run --project examples/GnapConsoleClient
```

## Other examples

| Project | What it shows |
|---|---|
| [`HttpSignatures.Demo`](HttpSignatures.Demo) | RFC 9421 vector checks plus a live signed-client-against-Kestrel demo |
| [`VerifyingServer`](VerifyingServer) / [`SigningClient`](SigningClient) | HTTP Message Signatures across two terminals |
| [`GnapCore.Demo`](GnapCore.Demo) | Guided walkthrough of the GNAP core primitives with an in-process mini AS |
