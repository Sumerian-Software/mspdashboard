namespace mspdashboard.Identity.Features.Tenants;

public record CreateTenantCommand(
    string Subdomain,
    string CompanyName,
    string? ContactEmail,
    string? ContactPhone
);
