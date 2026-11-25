using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Tests.Infrastructure;
using mspdashboard.Shared;

namespace mspdashboard.Host.Tests.Auth;

/// <summary>
/// Validation and conflict failures on tenant creation, login, SSO setup and first-run setup
/// are returned as ProblemDetails (FluentValidation validators plus endpoint Validate methods).
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class ValidationProblemDetailsTests {
    private readonly ApiFactory _factory;

    public ValidationProblemDetailsTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Duplicate_tenant_subdomain_returns_409_problem_details() {
        var subdomain = "dupe-" + Guid.NewGuid().ToString("N")[..8];
        using var client = CreatePlatformAdminClient();

        var first = await client.PostAsJsonAsync("/api/tenants", new { subdomain, companyName = "First Co" });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var second = await client.PostAsJsonAsync("/api/tenants", new { subdomain, companyName = "Second Co" });

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        using var problem = await ReadProblemAsync(second);
        Assert.Equal(409, problem.RootElement.GetProperty("status").GetInt32());
        Assert.Contains(subdomain, problem.RootElement.GetProperty("detail").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_tenant_request_returns_400_problem_details_with_field_errors() {
        using var client = CreatePlatformAdminClient();

        var response = await client.PostAsJsonAsync("/api/tenants", new {
            subdomain = "Not Valid!",
            companyName = ""
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = await ReadProblemAsync(response);
        Assert.Equal(400, problem.RootElement.GetProperty("status").GetInt32());
        var errors = problem.RootElement.GetProperty("errors");
        Assert.True(HasError(errors, "subdomain"), errors.ToString());
        Assert.True(HasError(errors, "companyName"), errors.ToString());
    }

    [Fact]
    public async Task Login_without_email_or_password_returns_400_problem_details() {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new { email = "", password = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = await ReadProblemAsync(response);
        var errors = problem.RootElement.GetProperty("errors");
        Assert.True(HasError(errors, "email"), errors.ToString());
        Assert.True(HasError(errors, "password"), errors.ToString());
    }

    [Fact]
    public async Task Invalid_sso_provider_returns_400_problem_details() {
        var subdomain = "ssov-" + Guid.NewGuid().ToString("N")[..8];
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

        var response = await client.PostAsJsonAsync("/api/admin/sso-providers", new {
            providerType = SsoProviderType.GenericOidc,
            displayName = "Broken",
            authority = "not-a-url",
            clientId = "",
            clientSecret = ""
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = await ReadProblemAsync(response);
        var errors = problem.RootElement.GetProperty("errors");
        Assert.True(HasError(errors, "authority"), errors.ToString());
        Assert.True(HasError(errors, "clientId"), errors.ToString());
        Assert.True(HasError(errors, "clientSecret"), errors.ToString());
    }

    [Fact]
    public async Task Setup_when_already_done_returns_409_problem_details() {
        await using var factory = new ApiFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient();
        var body = new { companyName = "Northwind MSP", email = "ada@northwind.test", password = "ValidPass!234" };

        var first = await client.PostAsJsonAsync("/api/setup", body);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var again = await client.PostAsJsonAsync("/api/setup", body);

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        using var problem = await ReadProblemAsync(again);
        Assert.Equal(409, problem.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Setup_with_weak_password_returns_400_problem_details() {
        await using var factory = new ApiFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Northwind MSP",
            email = "ada@northwind.test",
            password = "short"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = await ReadProblemAsync(response);
        Assert.True(HasError(problem.RootElement.GetProperty("errors"), "password"));
    }

    private HttpClient CreatePlatformAdminClient() {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestTokens.CreatePlatformAdmin());
        return client;
    }

    private static async Task<JsonDocument> ReadProblemAsync(HttpResponseMessage response) {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    // Field names are matched case-insensitively; the serializer may camel-case or keep PascalCase.
    private static bool HasError(JsonElement errors, string field) {
        return errors.EnumerateObject().Any(p => string.Equals(p.Name, field, StringComparison.OrdinalIgnoreCase));
    }
}
