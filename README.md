# MSP Dashboard

A multi-tenant dashboard for managed service providers. Product site: [mspdashboard.io](https://mspdashboard.io).

See [TESTING.md](TESTING.md) for how we test critical paths and reported issues, and how to run the suite. See [docs/sso.md](docs/sso.md) for per-tenant SSO provider setup, login selection, and IdP redirect URIs.

The app is built on .NET 10 with:

- A Blazor WebAssembly client (MudBlazor)
- An ASP.NET Core host that serves the API and the client
- Wolverine for HTTP endpoints and messaging
- EF Core with PostgreSQL
- Redis as a distributed cache (falls back to an in-memory cache if no Redis connection string is set)

It is licensed under the [GNU Affero General Public License v3.0](LICENSE).

## Repository layout

```
src/
  Client/     Blazor WebAssembly UI
  Host/       ASP.NET Core host, authentication, and static-file hosting
  Modules/
    Core/     EF Core, tenant entities, and cache
    Identity/ Login, first-run setup, SSO admin, and tenant APIs
  Shared/     Shared types used by the client and server
  tests/      Host integration tests
```

The solution file is `src/mspdashboard.slnx`.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (see `global.json`; currently 10.0.404, with `rollForward: latestFeature`)
- PostgreSQL and Redis, or Docker to run them from the compose files

## Tests

The suite covers critical paths and regressions for reported issues, not exhaustive coverage. See [TESTING.md](TESTING.md) to run it and for when to add a test. PostgreSQL and Redis are not required for `dotnet test`.

## Run locally with Docker

From the `src` directory:

```bash
docker compose up --build
```

This starts PostgreSQL, Redis, and the host in the Development environment at [http://localhost:8080](http://localhost:8080). First-run setup is enabled, and Development seeding creates a demo tenant admin at `admin@demo.local` with password `DevAdmin!234`. That account is seeded only when `ASPNETCORE_ENVIRONMENT` is `Development` (disable it with `SeedDemoData=false` if you do not want it).

## Run locally with `dotnet`

Start PostgreSQL and Redis first. Default connection strings in `src/Host/mspdashboard.Host/appsettings.json` are:

- PostgreSQL: `Host=localhost;Database=mspdashboard;Username=postgres;Password=postgres`
- Redis: `localhost:6379`

Then run the host in Development (required for demo seeding, first-run setup, and starting without a JWT secret):

```bash
dotnet run --project src/Host/mspdashboard.Host --environment Development
```

Without a `launchSettings.json`, Kestrel listens on [http://localhost:5000](http://localhost:5000) by default. Set `ASPNETCORE_URLS` if you want a different URL. On startup the host applies EF Core migrations when it is using PostgreSQL.

In Development, first-run setup is allowed (`Setup:AllowFirstRun` in `appsettings.Development.json`). If no organization exists yet, the setup page can create the first one. After the demo seeder has run, a tenant already exists, so setup is no longer required and you can sign in as `admin@demo.local`.

## Self-hosting

Use the self-host overlay, which runs the host in Production. A JWT signing secret of at least 32 characters is required (see below). No demo user is seeded.

From the repository root:

```bash
export JWT_SECRET="$(openssl rand -base64 32)"
docker compose -f src/docker-compose.yml -f src/docker-compose.selfhost.yml up -d --build
```

The overlay sets `Setup__AllowFirstRun=true` so the first visit can create one organization. After that, remove `Setup__AllowFirstRun` (or set it to `false`) and recreate the host service. In Production, first-run setup is off unless you enable it this way.

## JWT secret

Outside Development, `JwtSettings:Secret` is required or the app will not start. It must be at least 32 characters. Set it with the `JwtSettings__Secret` environment variable, or with `dotnet user-secrets` for a local Production-like run:

```bash
openssl rand -base64 32
```

The self-host compose file reads this from `JWT_SECRET`. The same secret signs API tokens (below) and validates `Authorization: Bearer` requests. In Development the host can start without a secret, but token issuance then returns 503 until one is set.

## API tokens

The Blazor client keeps using httpOnly cookies. For scripts and integrations, issue a short-lived JWT from `POST /api/auth/token` (no refresh tokens — call the endpoint again when it expires; lifetime is `JwtSettings:ExpirationMinutes`, default 15).

With email and password (and optional tenant subdomain in the body or via `X-Tenant-Subdomain`):

```bash
curl -s -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Subdomain: demo" \
  -d '{"email":"admin@demo.local","password":"DevAdmin!234","tenantSubdomain":"demo"}'
```

Or exchange an existing browser cookie session (no body required; do not send `Authorization: Bearer`):

```bash
curl -s -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  --cookie "mspdashboard.auth=..."
```

Use the token:

```bash
curl -s http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "X-Tenant-Subdomain: demo"
```

The token carries `tenant_id` / `tenant_subdomain` claims, so it only works for that tenant (a mismatched `X-Tenant-Subdomain` returns 403). Bearer requests cannot mint a new token; use credentials or a cookie session instead.

## API keys

Long-lived, per-user, tenant-bound credentials for scripts and integrations. An API key has the same permissions as the user who created it (roles are read live from the database on each request, so role changes apply immediately). Keys are revocable; the plaintext secret is shown only once at creation.

Create a key with a cookie session or bearer token (not with another API key):

```bash
curl -s -X POST http://localhost:5000/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "X-Tenant-Subdomain: demo" \
  -d '{"name":"ci-bot","expiresAt":null}'
```

The response includes `key` in the form `msp_<prefix>_<secret>` — store it; it is never returned again.

Use the key:

```bash
curl -s http://localhost:5000/api/auth/me \
  -H "X-Api-Key: msp_..." \
  -H "X-Tenant-Subdomain: demo"
```

`Authorization: ApiKey msp_...` works the same way.

List metadata for the current user's keys (no secrets):

```bash
curl -s http://localhost:5000/api/auth/api-keys \
  -H "X-Api-Key: msp_..." \
  -H "X-Tenant-Subdomain: demo"
```

Revoke (soft-delete; idempotent):

```bash
curl -s -X DELETE http://localhost:5000/api/auth/api-keys/<id> \
  -H "X-Api-Key: msp_..." \
  -H "X-Tenant-Subdomain: demo"
```

Notes: a key cannot create other keys (403). Revoked or expired keys, and keys whose user is deactivated, get 401. Using a key against another tenant's host or `X-Tenant-Subdomain` returns 403.
