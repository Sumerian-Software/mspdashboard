# Tenant SSO providers

Each tenant can configure one or more OpenID Connect providers (Microsoft Entra ID, Google, or a generic OIDC issuer). End users pick a provider on the login page after resolving their organization; password login always remains available.

## Admin: add, switch, edit, disable, delete

Tenant admins (and platform admins) manage providers in the portal at **SSO providers** (`/admin/sso`), or via the API:

| Action | Method | Path |
|--------|--------|------|
| List | `GET` | `/api/admin/sso-providers` |
| Get | `GET` | `/api/admin/sso-providers/{id}` |
| Create | `POST` | `/api/admin/sso-providers` |
| Update (including enable/disable) | `PUT` | `/api/admin/sso-providers/{id}` |
| Delete | `DELETE` | `/api/admin/sso-providers/{id}` |

Requests require an authenticated tenant admin cookie (or platform admin) and a resolved tenant context (`X-Tenant-Subdomain` / host subdomain).

**Switching providers:** enable the provider users should see (`IsEnabled: true`) and disable the others (`IsEnabled: false`). Resolve-tenant and the login page only list enabled providers. Disabling or deleting a provider immediately refuses new challenges and clears the in-memory OIDC scheme so the next challenge (if re-enabled) reloads fresh options—no host restart.

**Edits** (authority, client id, secret, scopes, display name) also invalidate the registered scheme so changes apply on the next sign-in attempt.

Client secrets are encrypted at rest with ASP.NET Data Protection and are **never returned** from list/get/create/update responses. On update, omit `clientSecret` (or send blank) to keep the stored secret.

## Login: how users pick a provider

1. User enters a work email or tenant subdomain; the client calls `POST /api/auth/resolve-tenant`.
2. The response includes only **enabled** providers for that tenant (`id`, `displayName`, `providerType`).
3. On `/login`:
   - **Several** enabled providers: one outlined button per provider.
   - **Exactly one** enabled provider: a primary **Continue with {display name}** button (password sign-in stays on the page; there is no auto-redirect).
4. Choosing a provider navigates to `GET /api/auth/sso/{providerId}/challenge`, which starts the OIDC redirect. Disabled or deleted providers return **404**.

## Per-type authority and scopes

Default scopes when omitted on create: `openid profile email`.

| Type | Authority |
|------|-----------|
| Microsoft Entra ID | `https://login.microsoftonline.com/{directory-tenant-id}/v2.0` (any `https://login.microsoftonline.com/...` path is accepted) |
| Google | `https://accounts.google.com` (trailing slash allowed) |
| Generic OIDC | Absolute issuer URL that serves `/.well-known/openid-configuration` (http or https) |

## Redirect URI at the identity provider

Register this redirect URI for each provider application:

```text
https://<host>/api/auth/sso/callback/{providerId:N}
```

`{providerId:N}` is the provider’s GUID as **32 lowercase hex characters with no dashes** (for example `a1b2c3d4e5f6478890a1b2c3d4e5f647`). Use the `id` returned when the provider is created.
