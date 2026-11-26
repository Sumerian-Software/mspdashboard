using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Authentication;
using mspdashboard.Host.Tests.Infrastructure;
using mspdashboard.Shared;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class SsoProviderRuntimeTests {
    private readonly ApiFactory _factory;

    public SsoProviderRuntimeTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Resolve_tenant_lists_only_enabled_providers() {
        var (client, subdomain, _) = await CreateLoggedInTenantAsync("rt-en-");

        var enabled = await CreateProviderAsync(client, "Enabled IdP", SsoProviderType.MicrosoftEntra, isEnabled: true);
        var disabled = await CreateProviderAsync(client, "Disabled IdP", SsoProviderType.Google, isEnabled: false);

        using var anonymous = _factory.CreateClient();
        var first = await ResolveProvidersAsync(anonymous, subdomain);
        Assert.Contains(first, p => p.Id == enabled && p.DisplayName == "Enabled IdP");
        Assert.DoesNotContain(first, p => p.Id == disabled);

        var disable = await client.PutAsJsonAsync($"/api/admin/sso-providers/{enabled}", new {
            providerType = SsoProviderType.MicrosoftEntra,
            displayName = "Enabled IdP",
            authority = "https://login.microsoftonline.com/common/v2.0",
            clientId = "client-id",
            clientSecret = (string?)null,
            scopes = "openid profile email",
            isEnabled = false
        });
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        var afterDisable = await ResolveProvidersAsync(anonymous, subdomain);
        Assert.DoesNotContain(afterDisable, p => p.Id == enabled);
    }

    [Fact]
    public async Task Challenge_for_disabled_or_deleted_provider_returns_404() {
        var (client, _, _) = await CreateLoggedInTenantAsync("rt-ch-");

        var providerId = await CreateProviderAsync(client, "Challenge Target", SsoProviderType.MicrosoftEntra);

        var disable = await client.PutAsJsonAsync($"/api/admin/sso-providers/{providerId}", new {
            providerType = SsoProviderType.MicrosoftEntra,
            displayName = "Challenge Target",
            authority = "https://login.microsoftonline.com/common/v2.0",
            clientId = "client-id",
            clientSecret = (string?)null,
            scopes = "openid profile email",
            isEnabled = false
        });
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        using var anon = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var disabledChallenge = await anon.GetAsync($"/api/auth/sso/{providerId:D}/challenge");
        Assert.Equal(HttpStatusCode.NotFound, disabledChallenge.StatusCode);

        var otherId = await CreateProviderAsync(client, "To Delete", SsoProviderType.Google);
        var delete = await client.DeleteAsync($"/api/admin/sso-providers/{otherId}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        var deletedChallenge = await anon.GetAsync($"/api/auth/sso/{otherId:D}/challenge");
        Assert.Equal(HttpStatusCode.NotFound, deletedChallenge.StatusCode);
    }

    [Fact]
    public async Task Update_and_delete_refresh_oidc_scheme_without_breaking_requests() {
        var (client, _, _) = await CreateLoggedInTenantAsync("rt-sch-");

        var providerId = await CreateProviderAsync(
            client,
            "Scheme Provider",
            SsoProviderType.MicrosoftEntra,
            authority: "https://login.microsoftonline.com/common/v2.0",
            clientId: "initial-client");

        var schemes = _factory.Services.GetRequiredService<DynamicOidcSchemeManager>();
        var optionsMonitor = _factory.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>();
        var schemeProvider = _factory.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemeName = SsoSchemeNames.ForProvider(providerId);

        Assert.True(await schemes.EnsureSchemeAsync(providerId));
        var initial = optionsMonitor.Get(schemeName);
        Assert.Equal("https://login.microsoftonline.com/common/v2.0", initial.Authority);
        Assert.Equal("initial-client", initial.ClientId);
        Assert.NotNull(await schemeProvider.GetSchemeAsync(schemeName));

        var update = await client.PutAsJsonAsync($"/api/admin/sso-providers/{providerId}", new {
            providerType = SsoProviderType.MicrosoftEntra,
            displayName = "Scheme Provider",
            authority = "https://login.microsoftonline.com/contoso/v2.0",
            clientId = "updated-client",
            clientSecret = (string?)null,
            scopes = "openid profile email",
            isEnabled = true
        });
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);

        // Stale scheme must not break ordinary requests after invalidate.
        using var probe = _factory.CreateClient();
        var healthAfterUpdate = await probe.GetAsync("/api/health");
        Assert.True(healthAfterUpdate.IsSuccessStatusCode, await healthAfterUpdate.Content.ReadAsStringAsync());

        Assert.Null(await schemeProvider.GetSchemeAsync(schemeName));
        Assert.True(await schemes.EnsureSchemeAsync(providerId));
        var refreshed = optionsMonitor.Get(schemeName);
        Assert.Equal("https://login.microsoftonline.com/contoso/v2.0", refreshed.Authority);
        Assert.Equal("updated-client", refreshed.ClientId);

        var delete = await client.DeleteAsync($"/api/admin/sso-providers/{providerId}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        Assert.Null(await schemeProvider.GetSchemeAsync(schemeName));
        Assert.False(await schemes.EnsureSchemeAsync(providerId));

        var healthAfterDelete = await probe.GetAsync("/api/setup/status");
        Assert.True(healthAfterDelete.IsSuccessStatusCode, await healthAfterDelete.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Google_provider_with_non_google_authority_returns_400_validation_problem() {
        var (client, _, _) = await CreateLoggedInTenantAsync("rt-val-");

        var response = await client.PostAsJsonAsync("/api/admin/sso-providers", new {
            providerType = SsoProviderType.Google,
            displayName = "Bad Google",
            authority = "https://login.microsoftonline.com/common/v2.0",
            clientId = "google-client",
            clientSecret = "secret",
            scopes = "openid email",
            isEnabled = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var errors = problem.RootElement.GetProperty("errors");
        Assert.True(
            errors.EnumerateObject().Any(p => string.Equals(p.Name, "authority", StringComparison.OrdinalIgnoreCase)),
            errors.ToString());
    }

    private async Task<(HttpClient Client, string Subdomain, string Email)> CreateLoggedInTenantAsync(string prefix) {
        var subdomain = prefix + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);
        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return (client, subdomain, email);
    }

    private static async Task<Guid> CreateProviderAsync(
        HttpClient client,
        string displayName,
        SsoProviderType type,
        bool isEnabled = true,
        string? authority = null,
        string clientId = "client-id") {
        authority ??= type switch {
            SsoProviderType.Google => "https://accounts.google.com",
            SsoProviderType.MicrosoftEntra => "https://login.microsoftonline.com/common/v2.0",
            _ => "https://issuer.example.com"
        };

        var create = await client.PostAsJsonAsync("/api/admin/sso-providers", new {
            providerType = type,
            displayName,
            authority,
            clientId,
            clientSecret = "super-secret-value",
            scopes = "openid profile email",
            isEnabled
        });
        var body = await create.Content.ReadAsStringAsync();
        Assert.True(create.IsSuccessStatusCode, body);
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task<List<ResolvedProvider>> ResolveProvidersAsync(HttpClient client, string subdomain) {
        var response = await client.PostAsJsonAsync("/api/auth/resolve-tenant", new {
            email = (string?)null,
            subdomain
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("ssoProviders").EnumerateArray()
            .Select(p => new ResolvedProvider(
                p.GetProperty("id").GetGuid(),
                p.GetProperty("displayName").GetString() ?? string.Empty))
            .ToList();
    }

    private sealed record ResolvedProvider(Guid Id, string DisplayName);
}
