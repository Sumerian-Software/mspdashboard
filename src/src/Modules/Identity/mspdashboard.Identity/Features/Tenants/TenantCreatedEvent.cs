namespace mspdashboard.Identity.Features.Tenants;

public record TenantCreatedEvent(Guid TenantId, string Subdomain, string CompanyName);
