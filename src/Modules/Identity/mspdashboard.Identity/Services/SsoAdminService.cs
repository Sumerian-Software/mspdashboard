using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity.Features.Sso;
using mspdashboard.Identity.Security;

namespace mspdashboard.Identity.Services;

public sealed class SsoAdminService : ISsoAdminService {
    private readonly ApplicationDbContext _db;
    private readonly ITenantContextAccessor _tenantAccessor;
    private readonly SsoSecretProtector _secretProtector;
    private readonly ISsoOidcSchemeInvalidator _schemeInvalidator;

    public SsoAdminService(
        ApplicationDbContext db,
        ITenantContextAccessor tenantAccessor,
        SsoSecretProtector secretProtector,
        ISsoOidcSchemeInvalidator schemeInvalidator) {
        _db = db;
        _tenantAccessor = tenantAccessor;
        _secretProtector = secretProtector;
        _schemeInvalidator = schemeInvalidator;
    }

    public bool HasTenantContext => _tenantAccessor.EnsureResolved();

    public async Task<IReadOnlyList<SsoProviderDto>> ListAsync(CancellationToken cancellationToken) {
        var tenantId = _tenantAccessor.Current.TenantId!.Value;
        return await _db.TenantSsoProviders.AsNoTracking()
            .Where(p => p.TenantId == tenantId)
            .OrderBy(p => p.DisplayName)
            .Select(p => ToDto(p))
            .ToListAsync(cancellationToken);
    }

    public async Task<SsoProviderDto?> GetAsync(Guid id, CancellationToken cancellationToken) {
        var tenantId = _tenantAccessor.Current.TenantId!.Value;
        var entity = await _db.TenantSsoProviders.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id && p.TenantId == tenantId, cancellationToken);
        return entity is null ? null : ToDto(entity);
    }

    public async Task<SsoProviderDto> CreateAsync(
        CreateSsoProviderRequest request, CancellationToken cancellationToken) {
        var entity = new TenantSsoProvider {
            Id = Guid.NewGuid(),
            TenantId = _tenantAccessor.Current.TenantId!.Value,
            ProviderType = request.ProviderType,
            DisplayName = request.DisplayName.Trim(),
            Authority = request.Authority.Trim().TrimEnd('/'),
            ClientId = request.ClientId.Trim(),
            ClientSecretProtected = _secretProtector.Protect(request.ClientSecret),
            Scopes = string.IsNullOrWhiteSpace(request.Scopes) ? "openid profile email" : request.Scopes.Trim(),
            IsEnabled = request.IsEnabled,
            CreatedAt = DateTime.UtcNow
        };

        _db.TenantSsoProviders.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        return ToDto(entity);
    }

    public async Task<SsoProviderDto?> UpdateAsync(
        Guid id, UpdateSsoProviderRequest request, CancellationToken cancellationToken) {
        var tenantId = _tenantAccessor.Current.TenantId!.Value;
        var entity = await _db.TenantSsoProviders
            .FirstOrDefaultAsync(p => p.Id == id && p.TenantId == tenantId, cancellationToken);
        if (entity is null) {
            return null;
        }

        entity.ProviderType = request.ProviderType;
        entity.DisplayName = request.DisplayName.Trim();
        entity.Authority = request.Authority.Trim().TrimEnd('/');
        entity.ClientId = request.ClientId.Trim();
        entity.Scopes = string.IsNullOrWhiteSpace(request.Scopes) ? entity.Scopes : request.Scopes.Trim();
        entity.IsEnabled = request.IsEnabled;
        entity.UpdatedAt = DateTime.UtcNow;

        if (!string.IsNullOrWhiteSpace(request.ClientSecret)) {
            entity.ClientSecretProtected = _secretProtector.Protect(request.ClientSecret);
        }

        await _db.SaveChangesAsync(cancellationToken);
        _schemeInvalidator.Invalidate(id);
        return ToDto(entity);
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken) {
        var tenantId = _tenantAccessor.Current.TenantId!.Value;
        var entity = await _db.TenantSsoProviders
            .FirstOrDefaultAsync(p => p.Id == id && p.TenantId == tenantId, cancellationToken);
        if (entity is null) {
            return false;
        }

        _db.TenantSsoProviders.Remove(entity);
        await _db.SaveChangesAsync(cancellationToken);
        _schemeInvalidator.Invalidate(id);
        return true;
    }

    private static SsoProviderDto ToDto(TenantSsoProvider entity) {
        return new SsoProviderDto(
            entity.Id,
            entity.TenantId,
            entity.ProviderType,
            entity.DisplayName,
            entity.Authority,
            entity.ClientId,
            entity.Scopes,
            entity.IsEnabled,
            true);
    }
}
