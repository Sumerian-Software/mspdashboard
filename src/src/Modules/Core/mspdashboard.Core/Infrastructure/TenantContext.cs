using mspdashboard.Core.Contracts;

namespace mspdashboard.Core.Infrastructure;

public class TenantContext : ITenantContext {
    public Guid? TenantId { get; private set; }
    public string? Subdomain { get; private set; }
    public bool IsResolved => TenantId.HasValue;

    public void SetTenant(Guid tenantId, string subdomain) {
        TenantId = tenantId;
        Subdomain = subdomain;
    }

    public void Clear() {
        TenantId = null;
        Subdomain = null;
    }
}
