using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Data;
using mspdashboard.Core.Infrastructure;

namespace mspdashboard.Host.Middleware;

public class TenantResolutionMiddleware {
    private static readonly HashSet<string> ReservedSubdomains = new(StringComparer.OrdinalIgnoreCase) {
        "www", "api", "portal", "app", "admin", "static", "assets"
    };

    private readonly RequestDelegate _next;
    private readonly ILogger<TenantResolutionMiddleware> _logger;

    public TenantResolutionMiddleware(RequestDelegate next, ILogger<TenantResolutionMiddleware> logger) {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext,
        ITenantContext tenantContext, IDistributedCache cache) {
        var host = context.Request.Host.Host;
        var subdomain = ExtractSubdomain(host);
        if (IsReservedOrEmpty(subdomain)) {
            subdomain = context.Request.Headers[TenantHeaderNames.Subdomain].FirstOrDefault();
        }

        context.Items["TenantContext"] = tenantContext;

        if (!string.IsNullOrEmpty(subdomain) &&
            !subdomain.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !ReservedSubdomains.Contains(subdomain)) {
            await ResolveBySubdomainAsync(subdomain, dbContext, tenantContext, cache, context.RequestAborted);
        } else {
            _logger.LogDebug("No tenant subdomain detected before authentication");
        }

        await _next(context);

        // After auth middleware runs in the pipeline we cannot see claims here; claims are available
        // only after UseAuthentication. A follow-up middleware handles claim-based resolution.
    }

    internal static async Task ResolveBySubdomainAsync(
        string subdomain,
        ApplicationDbContext dbContext,
        ITenantContext tenantContext,
        IDistributedCache cache,
        CancellationToken cancellationToken) {
        var cached = await cache.GetStringAsync(TenantCache.Key(subdomain), cancellationToken);
        if (TenantCache.TryRead(cached, out var tenantId, out var cachedSubdomain)) {
            tenantContext.SetTenant(tenantId, cachedSubdomain);
            return;
        }

        var tenant = await dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Subdomain == subdomain && t.IsActive, cancellationToken);

        if (tenant != null) {
            tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
            await TenantCache.SetAsync(cache, tenant.Id, tenant.Subdomain, cancellationToken);
        }
    }

    private static bool IsReservedOrEmpty(string? subdomain) {
        return string.IsNullOrEmpty(subdomain) || ReservedSubdomains.Contains(subdomain);
    }

    private static string? ExtractSubdomain(string host) {
        if (System.Net.IPAddress.TryParse(host, out _)) {
            return null;
        }

        var parts = host.Split('.');
        if (parts.Length >= 3 && !host.Contains("localhost", StringComparison.OrdinalIgnoreCase)) {
            return parts[0];
        }
        return null;
    }
}

public class ClaimTenantResolutionMiddleware {
    private readonly RequestDelegate _next;
    private readonly ILogger<ClaimTenantResolutionMiddleware> _logger;

    public ClaimTenantResolutionMiddleware(RequestDelegate next, ILogger<ClaimTenantResolutionMiddleware> logger) {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(
        HttpContext context,
        ApplicationDbContext dbContext,
        ITenantContext tenantContext,
        IDistributedCache cache) {
        if (!tenantContext.IsResolved && context.User.Identity?.IsAuthenticated == true) {
            var subdomain = context.User.FindFirstValue("tenant_subdomain");
            if (!string.IsNullOrWhiteSpace(subdomain)) {
                await TenantResolutionMiddleware.ResolveBySubdomainAsync(
                    subdomain, dbContext, tenantContext, cache, context.RequestAborted);
                _logger.LogDebug("Resolved tenant from auth claims: {Subdomain}", subdomain);
            } else {
                var tenantIdValue = context.User.FindFirstValue("tenant_id");
                if (Guid.TryParse(tenantIdValue, out var tenantId)) {
                    var tenant = await dbContext.Tenants.AsNoTracking()
                        .FirstOrDefaultAsync(t => t.Id == tenantId && t.IsActive, context.RequestAborted);
                    if (tenant is not null) {
                        tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
                    }
                }
            }
        }

        await _next(context);
    }
}
