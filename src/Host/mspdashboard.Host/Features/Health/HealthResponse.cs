namespace mspdashboard.Host.Features.Health;

public record HealthResponse(
    string Status,
    DateTime Timestamp,
    bool TenantResolved,
    Guid? TenantId,
    string? Subdomain,
    string Cache
);
