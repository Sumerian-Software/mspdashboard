using mspdashboard.Identity.Features.Auth;

namespace mspdashboard.Identity.Services;

public interface IPortalAuthService {
    Task<AuthAttemptResult> LoginAsync(LoginRequest request, CancellationToken cancellationToken);
    Task LogoutAsync();
    Task<AuthUserResponse?> GetCurrentUserAsync(System.Security.Claims.ClaimsPrincipal principal);
}

public sealed record AuthAttemptResult(
    bool Succeeded,
    bool LockedOut,
    bool BadRequest,
    string? Error,
    AuthUserResponse? User);
