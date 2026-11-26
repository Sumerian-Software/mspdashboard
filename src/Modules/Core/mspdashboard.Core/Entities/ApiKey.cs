namespace mspdashboard.Core.Entities;

public class ApiKey : BaseTenantEntity {
    public Guid UserId { get; set; }
    public required string Name { get; set; }
    /// <summary>Non-secret public identifier (unique); part of the full key string.</summary>
    public required string Prefix { get; set; }
    /// <summary>SHA-256 of the secret segment; never store the plaintext secret.</summary>
    public required byte[] SecretHash { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}
