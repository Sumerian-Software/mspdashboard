using mspdashboard.Identity.Features.Auth;

namespace mspdashboard.Identity.Services;

public interface IPortalAuthService {
    /// <summary>
    /// Validates email/password (tenant resolution, lockout, IsActive) and signs in a cookie session.
    /// </summary>
    Task<AuthAttemptResult> LoginAsync(LoginRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Same credential checks as login, but does not create a cookie session.
    /// Used by API token issuance.
    /// </summary>
    Task<AuthAttemptResult> AuthenticateCredentialsAsync(
        LoginRequest request,
        CancellationToken cancellationToken);

    Task LogoutAsync();
    Task<AuthUserResponse?> GetCurrentUserAsync(System.Security.Claims.ClaimsPrincipal principal);
}

public sealed record AuthAttemptResult(
    bool Succeeded,
    bool LockedOut,
    bool BadRequest,
    string? Error,
    AuthUserResponse? User);
