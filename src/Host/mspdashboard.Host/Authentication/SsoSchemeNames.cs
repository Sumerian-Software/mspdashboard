namespace mspdashboard.Host.Authentication;

public static class SsoSchemeNames {
    public const string Prefix = "sso:";
    public const string CorrelationCookie = "mspdashboard.sso";

    public static string ForProvider(Guid providerId) => Prefix + providerId.ToString("N");
}
