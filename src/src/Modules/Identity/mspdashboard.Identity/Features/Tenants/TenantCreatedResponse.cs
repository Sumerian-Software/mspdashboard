namespace mspdashboard.Identity.Features.Tenants;

public record TenantCreatedResponse(Guid TenantId, string Subdomain, string CompanyName);
