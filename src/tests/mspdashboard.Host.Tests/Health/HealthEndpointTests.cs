using System.Text.Json;
using mspdashboard.Host.Features.Health;
using mspdashboard.Host.Tests.Infrastructure;

namespace mspdashboard.Host.Tests.Health;

[Collection(ApiCollection.Name)]
public sealed class HealthEndpointTests {
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ApiFactory _factory;

    public HealthEndpointTests(ApiFactory factory) {
        _factory = factory;
    }

    [Fact]
    public async Task Get_returns_healthy_with_memory_cache() {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/health");
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, body);

        var health = JsonSerializer.Deserialize<HealthResponse>(body, JsonOptions);
        Assert.NotNull(health);
        Assert.Equal("Healthy", health.Status);
        Assert.Equal("memory", health.Cache);
        Assert.False(health.TenantResolved);
    }
}
