namespace mspdashboard.Identity.Services;

/// <summary>
/// Clears a dynamically registered OIDC authentication scheme so the next challenge
/// reloads options from the database. Implemented by the Host.
/// </summary>
public interface ISsoOidcSchemeInvalidator {
    void Invalidate(Guid providerId);
}
