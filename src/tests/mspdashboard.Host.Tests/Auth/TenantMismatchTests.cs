using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Auth;

/// <summary>
/// Regression for #14: cookie for tenant A must not authorize access when the request
/// resolves a different tenant via X-Tenant-Subdomain or host subdomain.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class TenantMismatchTests {
    private readonly ApiFactory _factory;

    public TenantMismatchTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Get_sso_providers_with_other_tenant_header_returns_403_tenant_mismatch_issue_14() {
        var a = "mm-a-" + Guid.NewGuid().ToString("N")[..8];
        var b = "mm-b-" + Guid.NewGuid().ToString("N")[..8];
        var emailA = $"admin@{a}.test";
        await _factory.SeedTenantAdminAsync(a, emailA, "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, a);

        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email = emailA,
            password = "ValidPass!234",
            tenantSubdomain = a
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        client.DefaultRequestHeaders.Remove(TenantHeaderNames.Subdomain);
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);

        var response = await client.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Tenant mismatch", problem.RootElement.GetProperty("title").GetString());
        Assert.Equal(403, problem.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Get_sso_providers_with_matching_tenant_header_returns_200_issue_14() {
        var a = "mm-ok-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{a}.test";
        await _factory.SeedTenantAdminAsync(a, email, "ValidPass!234", a + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, a);

        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = a
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var response = await client.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Platform_admin_bearer_with_other_tenant_header_is_not_blocked_issue_14() {
        var b = "mm-pa-" + Guid.NewGuid().ToString("N")[..8];
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", TestTokens.CreatePlatformAdmin());
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);

        var response = await client.GetAsync("/api/admin/sso-providers");
        // PlatformAdmin is cross-tenant by design; must not get Tenant mismatch 403 (#14).
        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Get_sso_providers_with_other_tenant_host_returns_403_tenant_mismatch_issue_14() {
        var a = "mm-ha-" + Guid.NewGuid().ToString("N")[..8];
        var b = "mm-hb-" + Guid.NewGuid().ToString("N")[..8];
        var emailA = $"admin@{a}.test";
        await _factory.SeedTenantAdminAsync(a, emailA, "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        // Login without Host-based resolution (header only), same pattern as other auth tests.
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, a);
        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email = emailA,
            password = "ValidPass!234",
            tenantSubdomain = a
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        client.DefaultRequestHeaders.Remove(TenantHeaderNames.Subdomain);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/sso-providers");
        request.Headers.Host = b + ".mspdashboard.io";
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Tenant mismatch", problem.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task Login_with_stale_other_tenant_cookie_and_new_tenant_header_succeeds_issue_14() {
        var a = "mm-st-" + Guid.NewGuid().ToString("N")[..8];
        var b = "mm-su-" + Guid.NewGuid().ToString("N")[..8];
        var emailA = $"admin@{a}.test";
        var emailB = $"admin@{b}.test";
        await _factory.SeedTenantAdminAsync(a, emailA, "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, emailB, "ValidPass!234", b + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, a);

        var loginA = await client.PostAsJsonAsync("/api/auth/login", new {
            email = emailA,
            password = "ValidPass!234",
            tenantSubdomain = a
        });
        Assert.Equal(HttpStatusCode.OK, loginA.StatusCode);

        // Stale cookie for A + header for B must not block the anonymous login endpoint.
        client.DefaultRequestHeaders.Remove(TenantHeaderNames.Subdomain);
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);

        var loginB = await client.PostAsJsonAsync("/api/auth/login", new {
            email = emailB,
            password = "ValidPass!234",
            tenantSubdomain = b
        });
        Assert.Equal(HttpStatusCode.OK, loginB.StatusCode);
    }
}
