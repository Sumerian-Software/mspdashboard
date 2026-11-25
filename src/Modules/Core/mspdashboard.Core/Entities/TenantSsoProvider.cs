using mspdashboard.Shared;

namespace mspdashboard.Core.Entities;

public class TenantSsoProvider : BaseTenantEntity {
    public SsoProviderType ProviderType { get; set; }
    public required string DisplayName { get; set; }
    public required string Authority { get; set; }
    public required string ClientId { get; set; }
    public required string ClientSecretProtected { get; set; }
    public string Scopes { get; set; } = "openid profile email";
    public bool IsEnabled { get; set; } = true;
}
