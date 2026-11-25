using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Distributed;
using mspdashboard.Core.Contracts;
using Wolverine.Http;

namespace mspdashboard.Host.Features.Health;

public static class GetHealthEndpoint {
    [AllowAnonymous]
    [WolverineGet("/api/health")]
    public static async Task<HealthResponse> Get(
        GetHealthQuery query,
        HttpContext httpContext,
        IDistributedCache cache,
        IConfiguration configuration) {
        var tenantContext = httpContext.Items["TenantContext"] as ITenantContext;
        var cacheStatus = "memory";
        if (!string.IsNullOrEmpty(configuration.GetConnectionString("Redis"))) {
            try {
                await cache.GetAsync("health:redis");
                cacheStatus = "redis";
            } catch (Exception) {
                cacheStatus = "redis-unreachable";
            }
        }

        return new HealthResponse(
            Status: "Healthy",
            Timestamp: DateTime.UtcNow,
            TenantResolved: tenantContext?.IsResolved ?? false,
            TenantId: tenantContext?.TenantId,
            Subdomain: tenantContext?.Subdomain,
            Cache: cacheStatus
        );
    }
}
