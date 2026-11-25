using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class SetupTests {
    public SetupTests(ApiFactory _) {
    }

    [Fact]
    public async Task First_run_creates_the_organization_and_signs_in() {
        await using var factory = new ApiFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var status = await client.GetFromJsonAsync<SetupStatusPayload>("/api/setup/status");
        Assert.NotNull(status);
        Assert.True(status.SetupRequired);

        var response = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Northwind MSP",
            email = "ada@northwind.test",
            password = "ValidPass!234"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), cookie => cookie.Contains("mspdashboard.auth"));
        var created = await response.Content.ReadAsStringAsync();
        Assert.Contains("northwind-msp", created, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ada@northwind.test", created, StringComparison.OrdinalIgnoreCase);

        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadAsStringAsync();
        Assert.Contains("ada@northwind.test", meBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TenantAdmin", meBody, StringComparison.Ordinal);

        var again = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Other MSP",
            email = "bea@other.test",
            password = "ValidPass!234"
        });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        var after = await client.GetFromJsonAsync<SetupStatusPayload>("/api/setup/status");
        Assert.NotNull(after);
        Assert.False(after.SetupRequired);
    }

    [Fact]
    public async Task Reserved_company_name_gets_a_usable_subdomain() {
        await using var factory = new ApiFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions {
            HandleCookies = true
        });

        var response = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Admin",
            email = "owner@admin.example",
            password = "ValidPass!234"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("admin-msp", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Invalid_setup_leaves_the_instance_unconfigured() {
        await using var factory = new ApiFactory();
        await factory.InitializeAsync();
        using var client = factory.CreateClient();

        var missing = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "",
            email = "ada@northwind.test",
            password = "ValidPass!234"
        });
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        var weak = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Northwind MSP",
            email = "ada@northwind.test",
            password = "short"
        });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);

        var status = await client.GetFromJsonAsync<SetupStatusPayload>("/api/setup/status");
        Assert.NotNull(status);
        Assert.True(status.SetupRequired);
    }

    [Fact]
    public async Task Hosted_mode_rejects_public_setup() {
        await using var factory = ApiFactory.Create(new Dictionary<string, string?> {
            ["Setup:AllowFirstRun"] = "false"
        });
        await factory.InitializeAsync();
        using var client = factory.CreateClient();

        var status = await client.GetFromJsonAsync<SetupStatusPayload>("/api/setup/status");
        Assert.NotNull(status);
        Assert.False(status.SetupRequired);

        var response = await client.PostAsJsonAsync("/api/setup", new {
            companyName = "Northwind MSP",
            email = "ada@northwind.test",
            password = "ValidPass!234"
        });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        var login = await client.PostAsJsonAsync("/api/auth/login", new {
            email = "ada@northwind.test",
            password = "ValidPass!234"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    private sealed class SetupStatusPayload {
        public bool SetupRequired { get; set; }
    }
}
