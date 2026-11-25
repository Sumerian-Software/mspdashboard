using mspdashboard.Shared;

namespace mspdashboard.Identity.Features.Auth;

public sealed record ResolveTenantRequest(string? Email, string? Subdomain);

public sealed record ResolveTenantResponse(
    Guid TenantId,
    string Subdomain,
    string CompanyName,
    IReadOnlyList<SsoProviderPublicDto> SsoProviders);

public sealed record SsoProviderPublicDto(
    Guid Id,
    string DisplayName,
    SsoProviderType ProviderType);

public sealed record LoginRequest(string Email, string Password, string? TenantSubdomain);

public sealed record AuthUserResponse(
    Guid Id,
    string Email,
    Guid TenantId,
    string? TenantSubdomain,
    string? FirstName,
    string? LastName,
    IReadOnlyList<string> Roles);

public sealed record LoginResponse(AuthUserResponse User);
