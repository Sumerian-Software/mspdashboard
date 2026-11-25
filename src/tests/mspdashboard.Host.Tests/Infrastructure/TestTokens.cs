using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using mspdashboard.Identity;

namespace mspdashboard.Host.Tests.Infrastructure;

public static class TestTokens {
    public const string SigningKey = "test-signing-key-at-least-32-characters";
    public const string Issuer = "mspdashboard.io";
    public const string Audience = "mspdashboard.io";
    public const string DevJwtIssuer = "dotnet-user-jwts";
    public const string DevJwtAudience = "http://localhost:5080";

    public static readonly byte[] DevJwtKeyMaterial =
        Encoding.UTF8.GetBytes("dev-user-jwts-key-material-32b!!");

    public static string CreatePlatformAdmin() {
        return Create(SigningKey, Issuer, Audience, AuthorizationPolicies.PlatformAdmin);
    }

    public static string Create(string signingKey, string issuer, string audience, string? role) {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        return Create(key, issuer, audience, role);
    }

    public static string Create(SymmetricSecurityKey key, string issuer, string audience, string? role) {
        var claims = new List<Claim> {
            new(JwtRegisteredClaimNames.Sub, "test-user"),
            new(ClaimTypes.Name, "test-user")
        };
        if (role is not null) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
