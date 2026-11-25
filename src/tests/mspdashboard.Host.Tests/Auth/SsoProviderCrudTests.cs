using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Tests.Infrastructure;
using mspdashboard.Shared;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class SsoProviderCrudTests {
    private readonly ApiFactory _factory;

    public SsoProviderCrudTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Tenant_admin_can_crud_sso_providers() {
        var subdomain = "sso-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var create = await client.PostAsJsonAsync("/api/admin/sso-providers", new {
            providerType = SsoProviderType.MicrosoftEntra,
            displayName = "Entra",
            authority = "https://login.microsoftonline.com/common/v2.0",
            clientId = "client-id",
            clientSecret = "super-secret-value",
            scopes = "openid profile email",
            isEnabled = true
        });
        var createBody = await create.Content.ReadAsStringAsync();
        Assert.True(create.IsSuccessStatusCode, createBody);
        Assert.DoesNotContain("super-secret-value", createBody, StringComparison.Ordinal);

        var list = await client.GetAsync("/api/admin/sso-providers");
        var listBody = await list.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.Contains("Entra", listBody, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-value", listBody, StringComparison.Ordinal);

        using var doc = System.Text.Json.JsonDocument.Parse(createBody);
        var id = doc.RootElement.GetProperty("id").GetGuid();

        var update = await client.PutAsJsonAsync($"/api/admin/sso-providers/{id}", new {
            providerType = SsoProviderType.MicrosoftEntra,
            displayName = "Entra Updated",
            authority = "https://login.microsoftonline.com/common/v2.0",
            clientId = "client-id",
            clientSecret = (string?)null,
            scopes = "openid profile email",
            isEnabled = false
        });
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);

        var delete = await client.DeleteAsync($"/api/admin/sso-providers/{id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    [Fact]
    public async Task Sso_provider_crud_is_tenant_isolated() {
        var a = "iso-a-" + Guid.NewGuid().ToString("N")[..6];
        var b = "iso-b-" + Guid.NewGuid().ToString("N")[..6];
        await _factory.SeedTenantAdminAsync(a, $"admin@{a}.test", "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        using var clientA = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        clientA.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, a);
        Assert.Equal(HttpStatusCode.OK, (await clientA.PostAsJsonAsync("/api/auth/login", new {
            email = $"admin@{a}.test",
            password = "ValidPass!234",
            tenantSubdomain = a
        })).StatusCode);

        var created = await clientA.PostAsJsonAsync("/api/admin/sso-providers", new {
            providerType = SsoProviderType.Google,
            displayName = "Google A",
            authority = "https://accounts.google.com",
            clientId = "a-client",
            clientSecret = "secret-a",
            scopes = "openid email",
            isEnabled = true
        });
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        using var createdDoc = System.Text.Json.JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var providerId = createdDoc.RootElement.GetProperty("id").GetGuid();

        using var clientB = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        clientB.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);
        Assert.Equal(HttpStatusCode.OK, (await clientB.PostAsJsonAsync("/api/auth/login", new {
            email = $"admin@{b}.test",
            password = "ValidPass!234",
            tenantSubdomain = b
        })).StatusCode);

        var listB = await clientB.GetAsync("/api/admin/sso-providers");
        var listBody = await listB.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, listB.StatusCode);
        Assert.DoesNotContain("Google A", listBody, StringComparison.Ordinal);

        var getOther = await clientB.GetAsync($"/api/admin/sso-providers/{providerId}");
        Assert.Equal(HttpStatusCode.NotFound, getOther.StatusCode);

        var deleteOther = await clientB.DeleteAsync($"/api/admin/sso-providers/{providerId}");
        Assert.Equal(HttpStatusCode.NotFound, deleteOther.StatusCode);
    }

    [Fact]
    public async Task Anonymous_cannot_manage_sso_providers() {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
