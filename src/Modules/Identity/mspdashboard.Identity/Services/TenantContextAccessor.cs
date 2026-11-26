using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Data;
using mspdashboard.Core.Infrastructure;

namespace mspdashboard.Identity.Services;

public sealed class TenantContextAccessor : ITenantContextAccessor {
    private readonly ITenantContext _tenantContext;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ApplicationDbContext _db;
    private readonly IDistributedCache _cache;

    public TenantContextAccessor(
        ITenantContext tenantContext,
        IHttpContextAccessor httpContextAccessor,
        ApplicationDbContext db,
        IDistributedCache cache) {
        _tenantContext = tenantContext;
        _httpContextAccessor = httpContextAccessor;
        _db = db;
        _cache = cache;
    }

    public ITenantContext Current => _tenantContext;

    public bool EnsureResolved() {
        if (_tenantContext.IsResolved) {
            return true;
        }

        var http = _httpContextAccessor.HttpContext;
        if (http is null) {
            return false;
        }

        var header = http.Request.Headers[TenantHeaderNames.Subdomain].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(header)) {
            var fromHeader = LookupBySubdomain(header).GetAwaiter().GetResult();
            if (fromHeader is not null) {
                // Do not adopt a header tenant that conflicts with the caller's tenant claims (#14).
                if (!TenantClaimMatching.MatchesResolvedTenant(
                        http.User,
                        fromHeader.Value.TenantId,
                        fromHeader.Value.Subdomain)) {
                    return false;
                }

                _tenantContext.SetTenant(fromHeader.Value.TenantId, fromHeader.Value.Subdomain);
                return true;
            }
        }

        if (http.User.Identity?.IsAuthenticated == true) {
            var subdomain = http.User.FindFirstValue(TenantClaimMatching.TenantSubdomainClaimType);
            if (!string.IsNullOrWhiteSpace(subdomain)) {
                var fromClaim = LookupBySubdomain(subdomain).GetAwaiter().GetResult();
                if (fromClaim is not null) {
                    _tenantContext.SetTenant(fromClaim.Value.TenantId, fromClaim.Value.Subdomain);
                    return true;
                }
            }

            var tenantIdValue = http.User.FindFirstValue(TenantClaimMatching.TenantIdClaimType);
            if (Guid.TryParse(tenantIdValue, out var tenantId)) {
                var tenant = _db.Tenants.AsNoTracking()
                    .FirstOrDefault(t => t.Id == tenantId && t.IsActive);
                if (tenant is not null) {
                    _tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
                    return true;
                }
            }
        }

        return _tenantContext.IsResolved;
    }

    private async Task<(Guid TenantId, string Subdomain)?> LookupBySubdomain(string subdomain) {
        var cached = await _cache.GetStringAsync(TenantCache.Key(subdomain));
        if (TenantCache.TryRead(cached, out var tenantId, out var cachedSubdomain)) {
            return (tenantId, cachedSubdomain);
        }

        var tenant = await _db.Tenants.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Subdomain == subdomain && t.IsActive);
        if (tenant is not null) {
            await TenantCache.SetAsync(_cache, tenant.Id, tenant.Subdomain, CancellationToken.None);
            return (tenant.Id, tenant.Subdomain);
        }

        return null;
    }
}
