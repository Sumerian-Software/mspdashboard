using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class PasswordLoginTests {
    private readonly ApiFactory _factory;

    public PasswordLoginTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Login_with_valid_password_sets_auth_cookie() {
        var subdomain = "login-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var response = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.Contains("mspdashboard.auth"));

        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var body = await me.Content.ReadAsStringAsync();
        Assert.Contains(email, body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_with_wrong_password_returns_401() {
        var subdomain = "bad-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "WrongPass!234",
            tenantSubdomain = subdomain
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_lockout_after_failed_attempts() {
        var subdomain = "lock-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient();
        HttpStatusCode last = HttpStatusCode.OK;
        for (var i = 0; i < 6; i++) {
            var failed = await client.PostAsJsonAsync("/api/auth/login", new {
                email,
                password = "WrongPass!234",
                tenantSubdomain = subdomain
            });
            last = failed.StatusCode;
            if (last == (HttpStatusCode)423) {
                break;
            }

            Assert.Equal(HttpStatusCode.Unauthorized, last);
        }

        Assert.Equal((HttpStatusCode)423, last);
    }

    [Fact]
    public async Task Resolve_tenant_by_email_domain() {
        var subdomain = "dom-" + Guid.NewGuid().ToString("N")[..8];
        var domain = subdomain + ".example";
        await _factory.SeedTenantAdminAsync(subdomain, $"admin@{domain}", "ValidPass!234", domain);

        using var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/resolve-tenant", new {
            email = $"user@{domain}"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains(subdomain, body, StringComparison.OrdinalIgnoreCase);
    }
}
