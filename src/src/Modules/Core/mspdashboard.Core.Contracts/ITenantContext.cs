namespace mspdashboard.Core.Contracts;

public interface ITenantContext {
    Guid? TenantId { get; }
    string? Subdomain { get; }
    bool IsResolved { get; }
    void SetTenant(Guid tenantId, string subdomain);
}
