using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class ApiTokenTests {
    private readonly ApiFactory _factory;

    public ApiTokenTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Issue_token_with_credentials_then_bearer_me_returns_200() {
        var subdomain = "tok-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient();
        var issue = await client.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });

        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var payload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var root = payload.RootElement;
        var accessToken = root.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.Equal("Bearer", root.GetProperty("tokenType").GetString());
        Assert.True(root.GetProperty("expiresIn").GetInt32() > 0);
        Assert.True(root.TryGetProperty("expiresAt", out _));
        Assert.False(
            issue.Headers.TryGetValues("Set-Cookie", out var cookies) &&
            cookies.Any(c => c.Contains("mspdashboard.auth", StringComparison.OrdinalIgnoreCase)));

        using var api = _factory.CreateClient();
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        api.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var me = await api.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var body = await me.Content.ReadAsStringAsync();
        Assert.Contains(email, body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_token_with_wrong_password_returns_401_without_token() {
        var subdomain = "tokbad-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "WrongPass!234",
            tenantSubdomain = subdomain
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("accessToken", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Bearer_token_with_other_tenant_header_returns_403() {
        var a = "tok-a-" + Guid.NewGuid().ToString("N")[..8];
        var b = "tok-b-" + Guid.NewGuid().ToString("N")[..8];
        var emailA = $"admin@{a}.test";
        await _factory.SeedTenantAdminAsync(a, emailA, "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        using var issuer = _factory.CreateClient();
        var issue = await issuer.PostAsJsonAsync("/api/auth/token", new {
            email = emailA,
            password = "ValidPass!234",
            tenantSubdomain = a
        });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var payload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var accessToken = payload.RootElement.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);

        var response = await client.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Tenant mismatch", problem.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task Issue_token_from_cookie_session_returns_bearer() {
        var subdomain = "tokck-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });

        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var issue = await client.PostAsJsonAsync("/api/auth/token", new { });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var payload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var accessToken = payload.RootElement.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
    }

    [Fact]
    public async Task Issue_token_with_bearer_only_returns_403() {
        var subdomain = "tokbr-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var issuer = _factory.CreateClient();
        var first = await issuer.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var payload = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        var accessToken = payload.RootElement.GetProperty("accessToken").GetString();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var renew = await client.PostAsJsonAsync("/api/auth/token", new { });
        Assert.Equal(HttpStatusCode.Forbidden, renew.StatusCode);
        using var problem = JsonDocument.Parse(await renew.Content.ReadAsStringAsync());
        Assert.Equal("Bearer renewal not allowed", problem.RootElement.GetProperty("title").GetString());
    }
}
