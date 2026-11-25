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
            ResolveBySubdomain(header).GetAwaiter().GetResult();
            if (_tenantContext.IsResolved) {
                return true;
            }
        }

        if (http.User.Identity?.IsAuthenticated == true) {
            var subdomain = http.User.FindFirstValue("tenant_subdomain");
            if (!string.IsNullOrWhiteSpace(subdomain)) {
                ResolveBySubdomain(subdomain).GetAwaiter().GetResult();
                if (_tenantContext.IsResolved) {
                    return true;
                }
            }

            var tenantIdValue = http.User.FindFirstValue("tenant_id");
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

    private async Task ResolveBySubdomain(string subdomain) {
        var cached = await _cache.GetStringAsync(TenantCache.Key(subdomain));
        if (TenantCache.TryRead(cached, out var tenantId, out var cachedSubdomain)) {
            _tenantContext.SetTenant(tenantId, cachedSubdomain);
            return;
        }

        var tenant = await _db.Tenants.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Subdomain == subdomain && t.IsActive);
        if (tenant is not null) {
            _tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
            await TenantCache.SetAsync(_cache, tenant.Id, tenant.Subdomain, CancellationToken.None);
        }
    }
}
