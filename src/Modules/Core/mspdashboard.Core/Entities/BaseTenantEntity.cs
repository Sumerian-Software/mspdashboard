namespace mspdashboard.Core.Entities;

public abstract class BaseTenantEntity : BaseEntity {
    public Guid TenantId { get; set; }
}
