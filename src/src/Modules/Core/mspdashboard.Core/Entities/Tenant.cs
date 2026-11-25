namespace mspdashboard.Core.Entities;

public class Tenant : BaseEntity {
    public required string Subdomain { get; set; }
    public required string CompanyName { get; set; }
    public bool IsActive { get; set; } = true;
    public string? ContactEmail { get; set; }
    public string? ContactPhone { get; set; }
}
