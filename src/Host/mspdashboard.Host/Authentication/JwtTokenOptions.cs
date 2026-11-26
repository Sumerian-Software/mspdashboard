namespace mspdashboard.Host.Authentication;

/// <summary>
/// Shared JWT issuer/audience/signing settings used by both validation and token issuance
/// so the two cannot drift.
/// </summary>
public sealed class JwtTokenOptions {
    public const string SectionName = "JwtSettings";
    public const int DefaultExpirationMinutes = 15;

    public required string? Issuer { get; init; }
    public required string? Audience { get; init; }
    public required string? SigningKey { get; init; }
    public required int ExpirationMinutes { get; init; }

    public bool CanIssue => !string.IsNullOrWhiteSpace(SigningKey);
}
