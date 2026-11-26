using System.Security.Claims;
using mspdashboard.Identity.Features.ApiKeys;

namespace mspdashboard.Identity.Services;

public interface IApiKeyService {
    Task<CreateApiKeyResponse?> CreateAsync(
        ClaimsPrincipal principal,
        CreateApiKeyRequest request,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ApiKeyListItemDto>> ListAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken);

    /// <summary>
    /// Soft-revokes the caller's key. Returns false when the key is missing or not owned.
    /// Already-revoked keys return true (idempotent).
    /// </summary>
    Task<bool> RevokeAsync(
        ClaimsPrincipal principal,
        Guid id,
        CancellationToken cancellationToken);
}
