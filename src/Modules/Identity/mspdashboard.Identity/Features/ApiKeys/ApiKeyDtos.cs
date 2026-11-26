namespace mspdashboard.Identity.Features.ApiKeys;

public sealed record CreateApiKeyRequest(string Name, DateTime? ExpiresAt);

public sealed record CreateApiKeyResponse(
    Guid Id,
    string Name,
    string Prefix,
    string Key,
    DateTime CreatedAt,
    DateTime? ExpiresAt);

public sealed record ApiKeyListItemDto(
    Guid Id,
    string Name,
    string Prefix,
    DateTime CreatedAt,
    DateTime? ExpiresAt,
    DateTime? LastUsedAt,
    DateTime? RevokedAt,
    bool IsActive);

/// <summary>
/// Normalizes API key expiration for Postgres <c>timestamptz</c> (Npgsql rejects Unspecified/Local).
/// </summary>
public static class ApiKeyExpiresAt {
    public static DateTime? ToUtc(DateTime? value) {
        if (value is null) {
            return null;
        }

        return value.Value.Kind switch {
            DateTimeKind.Utc => value.Value,
            DateTimeKind.Local => value.Value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)
        };
    }
}
