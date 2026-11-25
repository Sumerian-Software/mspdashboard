# Testing

This repo does not aim for broad or exhaustive coverage. Tests exist to lock in **critical paths** (authentication, tenant isolation, first-run setup, SSO secret handling, JWT signing rules) and to **regress reported issues**. If a change is not on one of those paths and is not fixing a known bug, a new test is usually not needed.

## When to write a test

Write a test when you are:

- Changing a critical path such as login, authorization, tenant resolution or isolation, first-run setup, SSO provider secrets, or JWT signing-key rules
- Fixing a reported bug or a reported use case that failed

Do not add tests just to increase coverage, or for straightforward UI or wiring changes with no security or isolation impact.

For a reported issue, put the issue number in the test name or in a comment next to it, for example `Login_lockout_after_failed_attempts_issue_123` or `// Regression for #123`.

## How to run the tests

You need the .NET 10 SDK specified in `global.json` (currently 10.0.404, with `rollForward: latestFeature`).

PostgreSQL and Redis are **not** required. `ApiFactory` runs the host in the `Testing` environment with empty Postgres and Redis connection strings, an in-memory SQLite database, an in-memory distributed cache, and Wolverine external transports disabled.

From the repository root:

```bash
dotnet test src/mspdashboard.slnx
```

From `src/`:

```bash
dotnet test
```

Filter to a class or a single test:

```bash
dotnet test src/mspdashboard.slnx --filter FullyQualifiedName~PasswordLoginTests
dotnet test src/mspdashboard.slnx --filter FullyQualifiedName~Login_with_valid_password_sets_auth_cookie
```

## Framework

The project is `src/tests/mspdashboard.Host.Tests`, an xUnit test project (`xunit`, `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio`). Host tests use `Microsoft.AspNetCore.Mvc.Testing` (`WebApplicationFactory<Program>`). The factory swaps in EF Core SQLite and a test Wolverine extension; JWT helpers use `Microsoft.IdentityModel.Tokens` and `System.IdentityModel.Tokens.Jwt`.

## Where tests live

```
src/tests/mspdashboard.Host.Tests/
  Auth/            Login, first-run setup, JWT rules, tenant-create auth, SSO CRUD
  Health/          Health endpoint
  Tenants/         Tenant host resolution and cache parsing
  Infrastructure/  ApiFactory, shared collection, TestTokens, TenantRequests
```

## Conventions for new tests

- Name tests in the existing `Method_condition_result` style, for example `Post_without_token_returns_401`, `Sso_provider_crud_is_tenant_isolated`, or `Missing_key_fails_outside_development`.
- Host tests that share a database should use `[Collection(ApiCollection.Name)]` and take `ApiFactory` in the constructor. Seed isolated data with `SeedTenantAdminAsync` (unique subdomains), create JWTs with `TestTokens`, and create platform-admin tenants with `TenantRequests.CreateTenantAsync`.
- First-run setup tests need an empty tenant table, so create a fresh `new ApiFactory()` (or `ApiFactory.Create(...)`) inside the test instead of using the shared fixture. `Setup:AllowFirstRun` is `true` in the factory's default test settings; set `["Setup:AllowFirstRun"] = "false"` when testing hosted/production behavior.
- Pure unit tests of a helper (JWT key rules, cache parsing) do not need the collection or a host.
