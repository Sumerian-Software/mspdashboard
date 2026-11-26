using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace mspdashboard.Identity.Security;

/// <summary>
/// Full key format: <c>msp_{prefix}_{secret}</c>. Only the secret segment is hashed (SHA-256 / UTF-8).
/// </summary>
public static class ApiKeyFormat {
    public const string KeyMarker = "msp";
    public const int PrefixHexLength = 12;
    public const int SecretByteLength = 32;

    public static (string FullKey, string Prefix, byte[] SecretHash) Generate() {
        Span<byte> prefixBytes = stackalloc byte[PrefixHexLength / 2];
        RandomNumberGenerator.Fill(prefixBytes);
        var prefix = Convert.ToHexString(prefixBytes).ToLowerInvariant();

        var secretBytes = new byte[SecretByteLength];
        RandomNumberGenerator.Fill(secretBytes);
        var secret = WebEncoders.Base64UrlEncode(secretBytes);
        var fullKey = $"{KeyMarker}_{prefix}_{secret}";
        return (fullKey, prefix, HashSecret(secret));
    }

    public static bool TryParse(string? fullKey, out string prefix, out string secret) {
        prefix = string.Empty;
        secret = string.Empty;
        if (string.IsNullOrWhiteSpace(fullKey)) {
            return false;
        }

        var parts = fullKey.Split('_', 3);
        if (parts.Length != 3) {
            return false;
        }

        if (!string.Equals(parts[0], KeyMarker, StringComparison.Ordinal)) {
            return false;
        }

        if (parts[1].Length != PrefixHexLength || string.IsNullOrEmpty(parts[2])) {
            return false;
        }

        prefix = parts[1];
        secret = parts[2];
        return true;
    }

    public static byte[] HashSecret(string secret) {
        return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }
}
