namespace mspdashboard.Core.Entities;

public class TenantEmailDomain : BaseEntity {
    public Guid TenantId { get; set; }
    public required string Domain { get; set; }
}
