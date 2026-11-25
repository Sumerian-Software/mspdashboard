using mspdashboard.Identity.Features.Auth;
using mspdashboard.Identity.Features.Setup;

namespace mspdashboard.Identity.Services;

public interface ISetupService {
    Task<bool> IsSetupRequiredAsync(CancellationToken cancellationToken);

    /// <summary>Runs the configured Identity password rules. Returns the error text, or null when valid.</summary>
    Task<string?> ValidatePasswordAsync(string email, string password);

    Task<SetupCompletion> CompleteAsync(CompleteSetupRequest request, CancellationToken cancellationToken);
}

public sealed record SetupCompletion(
    bool Succeeded,
    bool AlreadySetUp,
    bool Disabled,
    bool BadRequest,
    string? Error,
    AuthUserResponse? User);
