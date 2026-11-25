using mspdashboard.Shared;

namespace mspdashboard.Identity.Features.Sso;

public sealed record SsoProviderDto(
    Guid Id,
    Guid TenantId,
    SsoProviderType ProviderType,
    string DisplayName,
    string Authority,
    string ClientId,
    string Scopes,
    bool IsEnabled,
    bool HasClientSecret);

public sealed record CreateSsoProviderRequest(
    SsoProviderType ProviderType,
    string DisplayName,
    string Authority,
    string ClientId,
    string ClientSecret,
    string? Scopes,
    bool IsEnabled = true);

public sealed record UpdateSsoProviderRequest(
    SsoProviderType ProviderType,
    string DisplayName,
    string Authority,
    string ClientId,
    string? ClientSecret,
    string? Scopes,
    bool IsEnabled);
