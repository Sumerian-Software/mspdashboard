using System.Text.Json;
using mspdashboard.Host.Features.Health;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Tenants;

[Collection(ApiCollection.Name)]
public sealed class TenantResolutionTests {
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ApiFactory _factory;

    public TenantResolutionTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Create_then_resolves_by_host_subdomain() {
        var subdomain = "t" + Guid.NewGuid().ToString("N")[..12];
        using var client = _factory.CreateClient();

        var created = await TenantRequests.CreateTenantAsync(
            client,
            subdomain,
            "Acme MSP",
            "ops@acme.test");

        Assert.Equal(subdomain, created.Subdomain);
        Assert.NotEqual(Guid.Empty, created.TenantId);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        request.Headers.Host = subdomain + ".mspdashboard.io";
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, body);

        var health = JsonSerializer.Deserialize<HealthResponse>(body, JsonOptions);
        Assert.NotNull(health);
        Assert.Equal("Healthy", health.Status);
        Assert.True(health.TenantResolved);
        Assert.Equal(created.TenantId, health.TenantId);
        Assert.Equal(subdomain, health.Subdomain);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("mspdashboard.io")]
    [InlineData("127.0.0.1")]
    public async Task Skips_resolution_when_host_has_no_tenant_subdomain(string host) {
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        request.Headers.Host = host;

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, body);

        var health = JsonSerializer.Deserialize<HealthResponse>(body, JsonOptions);
        Assert.NotNull(health);
        Assert.False(health.TenantResolved);
        Assert.Null(health.TenantId);
        Assert.Null(health.Subdomain);
    }
}
