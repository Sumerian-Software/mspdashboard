using mspdashboard.Host.Authentication;

namespace mspdashboard.Host.Tests.Auth;

public sealed class JwtSigningKeyRulesTests {
    private const string ValidKey = "test-signing-key-at-least-32-characters";

    [Fact]
    public void Missing_key_fails_outside_development() {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            DashboardAuthenticationExtensions.ResolveSigningKey(isDevelopment: false, configuredSecret: null));

        Assert.Contains("JwtSettings:Secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Placeholder_key_fails_outside_development() {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            DashboardAuthenticationExtensions.ResolveSigningKey(
                isDevelopment: false,
                DashboardAuthenticationExtensions.RemovedPlaceholderSecret));

        Assert.Contains("JwtSettings:Secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Short_key_fails() {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            DashboardAuthenticationExtensions.ResolveSigningKey(isDevelopment: true, configuredSecret: "too-short"));

        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Development_starts_without_a_signing_key() {
        Assert.Null(DashboardAuthenticationExtensions.ResolveSigningKey(isDevelopment: true, configuredSecret: null));
        Assert.Null(DashboardAuthenticationExtensions.ResolveSigningKey(
            isDevelopment: true,
            DashboardAuthenticationExtensions.RemovedPlaceholderSecret));
    }

    [Fact]
    public void Valid_key_is_returned() {
        Assert.Equal(ValidKey, DashboardAuthenticationExtensions.ResolveSigningKey(isDevelopment: false, ValidKey));
    }
}
