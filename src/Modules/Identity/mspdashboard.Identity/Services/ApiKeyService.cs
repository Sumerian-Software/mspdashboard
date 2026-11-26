using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity.Features.ApiKeys;
using mspdashboard.Identity.Security;

namespace mspdashboard.Identity.Services;

public sealed class ApiKeyService : IApiKeyService {
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;

    public ApiKeyService(ApplicationDbContext db, UserManager<ApplicationUser> userManager) {
        _db = db;
        _userManager = userManager;
    }

    public async Task<CreateApiKeyResponse?> CreateAsync(
        ClaimsPrincipal principal,
        CreateApiKeyRequest request,
        CancellationToken cancellationToken) {
        var user = await ResolveActiveUserAsync(principal, cancellationToken);
        if (user is null) {
            return null;
        }

        var expiresAt = ApiKeyExpiresAt.ToUtc(request.ExpiresAt);
        var (fullKey, prefix, secretHash) = ApiKeyFormat.Generate();
        var entity = new ApiKey {
            Id = Guid.NewGuid(),
            TenantId = user.TenantId,
            UserId = user.Id,
            Name = request.Name.Trim(),
            Prefix = prefix,
            SecretHash = secretHash,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow
        };

        _db.ApiKeys.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new CreateApiKeyResponse(
            entity.Id,
            entity.Name,
            entity.Prefix,
            fullKey,
            entity.CreatedAt,
            entity.ExpiresAt);
    }

    public async Task<IReadOnlyList<ApiKeyListItemDto>> ListAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken) {
        var userId = _userManager.GetUserId(principal);
        if (userId is null || !Guid.TryParse(userId, out var id)) {
            return [];
        }

        var now = DateTime.UtcNow;
        return await _db.ApiKeys.AsNoTracking()
            .Where(k => k.UserId == id)
            .OrderByDescending(k => k.CreatedAt)
            .Select(k => new ApiKeyListItemDto(
                k.Id,
                k.Name,
                k.Prefix,
                k.CreatedAt,
                k.ExpiresAt,
                k.LastUsedAt,
                k.RevokedAt,
                k.RevokedAt == null && (k.ExpiresAt == null || k.ExpiresAt > now)))
            .ToListAsync(cancellationToken);
    }

    public async Task<bool> RevokeAsync(
        ClaimsPrincipal principal,
        Guid id,
        CancellationToken cancellationToken) {
        var userId = _userManager.GetUserId(principal);
        if (userId is null || !Guid.TryParse(userId, out var ownerId)) {
            return false;
        }

        var entity = await _db.ApiKeys
            .FirstOrDefaultAsync(k => k.Id == id && k.UserId == ownerId, cancellationToken);
        if (entity is null) {
            return false;
        }

        if (entity.RevokedAt is null) {
            entity.RevokedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(cancellationToken);
        }

        return true;
    }

    private async Task<ApplicationUser?> ResolveActiveUserAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken) {
        var user = await _userManager.GetUserAsync(principal);
        if (user is null || !user.IsActive) {
            return null;
        }

        return user;
    }
}
