using mspdashboard.Identity.Features.Sso;

namespace mspdashboard.Identity.Services;

public interface ISsoAdminService {
    Task<IReadOnlyList<SsoProviderDto>> ListAsync(CancellationToken cancellationToken);
    Task<SsoProviderDto?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<SsoProviderDto> CreateAsync(CreateSsoProviderRequest request, CancellationToken cancellationToken);
    Task<SsoProviderDto?> UpdateAsync(Guid id, UpdateSsoProviderRequest request, CancellationToken cancellationToken);
    Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken);
    bool HasTenantContext { get; }
}
