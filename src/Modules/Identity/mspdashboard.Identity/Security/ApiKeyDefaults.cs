namespace mspdashboard.Identity.Security;

public static class ApiKeyDefaults {
    public const string AuthenticationScheme = "ApiKey";
    public const string HeaderName = "X-Api-Key";
    public const string AuthorizationScheme = "ApiKey";
    public const string ApiKeyIdClaimType = "api_key_id";
}
