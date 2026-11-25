using Microsoft.AspNetCore.Identity;

namespace mspdashboard.Core.Entities;

public class ApplicationUser : IdentityUser<Guid> {
    public Guid TenantId { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool IsActive { get; set; } = true;
}
