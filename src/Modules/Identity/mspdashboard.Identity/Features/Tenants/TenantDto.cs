namespace mspdashboard.Identity.Features.Tenants;

public record TenantDto(
    Guid Id,
    string Subdomain,
    string CompanyName,
    bool IsActive,
    DateTime CreatedAt,
    string? ContactEmail,
    string? ContactPhone
);
