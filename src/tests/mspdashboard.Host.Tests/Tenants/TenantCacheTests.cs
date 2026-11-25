using mspdashboard.Core.Infrastructure;

namespace mspdashboard.Host.Tests.Tenants;

public sealed class TenantCacheTests {
    [Fact]
    public void Key_trims_and_lowercases_subdomain() {
        Assert.Equal("tenant:subdomain:acme", TenantCache.Key("  Acme "));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no-separator")]
    [InlineData("|acme")]
    [InlineData("not-a-guid|acme")]
    public void TryRead_rejects_invalid_values(string? value) {
        var ok = TenantCache.TryRead(value, out var tenantId, out var subdomain);

        Assert.False(ok);
        Assert.Equal(Guid.Empty, tenantId);
        Assert.Equal("", subdomain);
    }

    [Fact]
    public void TryRead_rejects_trailing_separator() {
        var value = "11111111-1111-1111-1111-111111111111|";

        var ok = TenantCache.TryRead(value, out var tenantId, out var subdomain);

        Assert.False(ok);
        Assert.Equal(Guid.Empty, tenantId);
        Assert.Equal("", subdomain);
    }

    [Fact]
    public void TryRead_reads_tenant_id_and_subdomain() {
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var ok = TenantCache.TryRead(id.ToString("D") + "|acme", out var tenantId, out var subdomain);

        Assert.True(ok);
        Assert.Equal(id, tenantId);
        Assert.Equal("acme", subdomain);
    }
}
