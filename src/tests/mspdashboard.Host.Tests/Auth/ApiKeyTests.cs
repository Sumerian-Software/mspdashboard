using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class ApiKeyTests {
    private readonly ApiFactory _factory;

    public ApiKeyTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Create_key_then_me_and_role_endpoint_with_x_api_key_return_200() {
        var subdomain = "apk-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var issuer = _factory.CreateClient();
        var issue = await issuer.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var tokenPayload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var accessToken = tokenPayload.RootElement.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        using var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        authed.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var create = await authed.PostAsJsonAsync("/api/auth/api-keys", new { name = "ci-bot" });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var fullKey = created.RootElement.GetProperty("key").GetString();
        Assert.False(string.IsNullOrWhiteSpace(fullKey));
        Assert.StartsWith("msp_", fullKey, StringComparison.Ordinal);

        using var api = _factory.CreateClient();
        api.DefaultRequestHeaders.Add("X-Api-Key", fullKey);
        api.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var me = await api.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadAsStringAsync();
        Assert.Contains(email, meBody, StringComparison.OrdinalIgnoreCase);

        var sso = await api.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.OK, sso.StatusCode);
    }

    [Fact]
    public async Task Revoked_key_reuse_returns_401() {
        var subdomain = "apkr-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        var (fullKey, keyId) = await CreateKeyAsync(subdomain, email);

        using var api = _factory.CreateClient();
        api.DefaultRequestHeaders.Add("X-Api-Key", fullKey);
        api.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var revoke = await api.DeleteAsync($"/api/auth/api-keys/{keyId}");
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var me = await api.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Wrong_secret_or_garbage_key_returns_401() {
        var subdomain = "apkw-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        var (fullKey, _) = await CreateKeyAsync(subdomain, email);
        var parts = fullKey.Split('_', 3);
        Assert.Equal(3, parts.Length);
        var wrongSecret = $"msp_{parts[1]}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        using var wrong = _factory.CreateClient();
        wrong.DefaultRequestHeaders.Add("X-Api-Key", wrongSecret);
        wrong.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrong.GetAsync("/api/auth/me")).StatusCode);

        using var garbage = _factory.CreateClient();
        garbage.DefaultRequestHeaders.Add("X-Api-Key", "not-a-valid-key");
        garbage.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);
        Assert.Equal(HttpStatusCode.Unauthorized, (await garbage.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Tenant_a_key_with_tenant_b_header_returns_403() {
        var a = "apka-" + Guid.NewGuid().ToString("N")[..8];
        var b = "apkb-" + Guid.NewGuid().ToString("N")[..8];
        var emailA = $"admin@{a}.test";
        await _factory.SeedTenantAdminAsync(a, emailA, "ValidPass!234", a + ".test");
        await _factory.SeedTenantAdminAsync(b, $"admin@{b}.test", "ValidPass!234", b + ".test");

        var (fullKey, _) = await CreateKeyAsync(a, emailA);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", fullKey);
        client.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, b);

        var response = await client.GetAsync("/api/admin/sso-providers");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Tenant mismatch", problem.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task Api_key_cannot_create_another_key_returns_403() {
        var subdomain = "apkc-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        var (fullKey, _) = await CreateKeyAsync(subdomain, email);

        using var api = _factory.CreateClient();
        api.DefaultRequestHeaders.Add("X-Api-Key", fullKey);
        api.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var before = await api.GetAsync("/api/auth/api-keys");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        using var beforeDoc = JsonDocument.Parse(await before.Content.ReadAsStringAsync());
        var beforeCount = beforeDoc.RootElement.GetArrayLength();

        var create = await api.PostAsJsonAsync("/api/auth/api-keys", new { name = "nested" });
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
        using var problem = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        Assert.Equal("API key cannot create API keys", problem.RootElement.GetProperty("title").GetString());

        var after = await api.GetAsync("/api/auth/api-keys");
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        using var afterDoc = JsonDocument.Parse(await after.Content.ReadAsStringAsync());
        Assert.Equal(beforeCount, afterDoc.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task Create_key_with_offset_expiresAt_returns_utc() {
        var subdomain = "apke-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        using var issuer = _factory.CreateClient();
        var issue = await issuer.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var tokenPayload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var accessToken = tokenPayload.RootElement.GetProperty("accessToken").GetString();

        using var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        authed.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var expires = DateTimeOffset.UtcNow.AddDays(30).ToOffset(TimeSpan.FromHours(2));
        var create = await authed.PostAsJsonAsync("/api/auth/api-keys", new {
            name = "offset-key",
            expiresAt = expires.ToString("yyyy-MM-dd'T'HH:mm:sszzz")
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var expiresAt = created.RootElement.GetProperty("expiresAt").GetString();
        Assert.False(string.IsNullOrWhiteSpace(expiresAt));
        Assert.True(
            expiresAt.EndsWith('Z') ||
            DateTimeOffset.Parse(expiresAt).UtcDateTime == expires.UtcDateTime);
    }

    [Fact]
    public async Task List_returns_metadata_with_prefix_without_secret() {
        var subdomain = "apkl-" + Guid.NewGuid().ToString("N")[..8];
        var email = $"admin@{subdomain}.test";
        await _factory.SeedTenantAdminAsync(subdomain, email, "ValidPass!234", subdomain + ".test");

        var (fullKey, _) = await CreateKeyAsync(subdomain, email);
        var parts = fullKey.Split('_', 3);
        var prefix = parts[1];
        var secret = parts[2];

        using var api = _factory.CreateClient();
        api.DefaultRequestHeaders.Add("X-Api-Key", fullKey);
        api.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var list = await api.GetAsync("/api/auth/api-keys");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var body = await list.Content.ReadAsStringAsync();
        Assert.Contains(prefix, body, StringComparison.Ordinal);
        Assert.DoesNotContain(fullKey, body, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.DoesNotContain("secretHash", body, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<(string FullKey, Guid KeyId)> CreateKeyAsync(string subdomain, string email) {
        using var issuer = _factory.CreateClient();
        var issue = await issuer.PostAsJsonAsync("/api/auth/token", new {
            email,
            password = "ValidPass!234",
            tenantSubdomain = subdomain
        });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        using var tokenPayload = JsonDocument.Parse(await issue.Content.ReadAsStringAsync());
        var accessToken = tokenPayload.RootElement.GetProperty("accessToken").GetString();

        using var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        authed.DefaultRequestHeaders.Add(TenantHeaderNames.Subdomain, subdomain);

        var create = await authed.PostAsJsonAsync("/api/auth/api-keys", new { name = "test-key" });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var fullKey = created.RootElement.GetProperty("key").GetString()!;
        var keyId = created.RootElement.GetProperty("id").GetGuid();
        return (fullKey, keyId);
    }
}
