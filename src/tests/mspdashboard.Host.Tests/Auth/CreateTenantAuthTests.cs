using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using mspdashboard.Host.Tests.Infrastructure;
using mspdashboard.Identity;
using Swashbuckle.AspNetCore.Swagger;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class CreateTenantAuthTests {
    private readonly ApiFactory _factory;

    public CreateTenantAuthTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Post_without_token_returns_401() {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/tenants", new {
            subdomain = "no-auth",
            companyName = "No Auth"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Post_with_token_without_platform_admin_returns_403() {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestTokens.Create(TestTokens.SigningKey, TestTokens.Issuer, TestTokens.Audience, "Viewer"));

        var response = await client.PostAsJsonAsync("/api/tenants", new {
            subdomain = "viewer",
            companyName = "Viewer Co"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Post_with_platform_admin_returns_success() {
        var subdomain = "acme-" + Guid.NewGuid().ToString("N")[..8];
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestTokens.CreatePlatformAdmin());

        var response = await client.PostAsJsonAsync("/api/tenants", new {
            subdomain,
            companyName = "Acme Co",
            contactEmail = "owner@example.com"
        });

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        Assert.Contains(subdomain, body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Post_with_dev_user_jwts_token_returns_success() {
        var subdomain = "dev-" + Guid.NewGuid().ToString("N")[..8];
        using var client = _factory.CreateClient();
        var key = new SymmetricSecurityKey(TestTokens.DevJwtKeyMaterial);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestTokens.Create(
                key,
                TestTokens.DevJwtIssuer,
                TestTokens.DevJwtAudience,
                AuthorizationPolicies.PlatformAdmin));

        var response = await client.PostAsJsonAsync("/api/tenants", new {
            subdomain,
            companyName = "Dev Co"
        });

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        Assert.Contains(subdomain, body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Get_health_without_token_returns_200() {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/health");
        var body = await response.Content.ReadAsStringAsync();

        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        Assert.Contains("Healthy", body, StringComparison.Ordinal);
    }

    [Fact]
    public void Swagger_document_includes_bearer_scheme() {
        using var scope = _factory.Services.CreateScope();
        var swagger = scope.ServiceProvider.GetRequiredService<ISwaggerProvider>();
        var document = swagger.GetSwagger("v1");
        var schemes = document.Components?.SecuritySchemes;
        Assert.NotNull(schemes);
        Assert.True(schemes.TryGetValue("Bearer", out var scheme));
        Assert.NotNull(scheme);
        Assert.Equal("bearer", scheme.Scheme, StringComparer.OrdinalIgnoreCase);
    }
}
