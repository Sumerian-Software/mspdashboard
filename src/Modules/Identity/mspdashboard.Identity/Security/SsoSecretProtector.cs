using Microsoft.AspNetCore.DataProtection;

namespace mspdashboard.Identity.Security;

public sealed class SsoSecretProtector {
    private const string Purpose = "mspdashboard.sso.client-secret.v1";
    private readonly IDataProtector _protector;

    public SsoSecretProtector(IDataProtectionProvider provider) {
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(string plaintext) {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);
        return _protector.Protect(plaintext);
    }

    public string Unprotect(string protectedValue) {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedValue);
        return _protector.Unprotect(protectedValue);
    }
}
