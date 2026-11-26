using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using mspdashboard.Identity;
using mspdashboard.Identity.Features.Auth;

namespace mspdashboard.Host.Authentication;

public interface IJwtAccessTokenIssuer {
    bool CanIssue { get; }

    AccessTokenResponse Issue(AuthUserResponse user);
}

/// <summary>
/// Issues short-lived HMAC-SHA256 JWTs using the same settings JwtBearer validates against.
/// Claim short names (sub, name, email, role) are chosen so MapInboundClaims=true maps them to
/// ClaimTypes.NameIdentifier / Name / Email / Role for UserManager and role policies.
/// </summary>
public sealed class JwtAccessTokenIssuer : IJwtAccessTokenIssuer {
    private readonly JwtTokenOptions _options;

    public JwtAccessTokenIssuer(IOptions<JwtTokenOptions> options) {
        _options = options.Value;
    }

    public bool CanIssue => _options.CanIssue;

    public AccessTokenResponse Issue(AuthUserResponse user) {
        if (!_options.CanIssue || string.IsNullOrWhiteSpace(_options.SigningKey)) {
            throw new InvalidOperationException("JWT signing key is not configured.");
        }

        var lifetimeMinutes = _options.ExpirationMinutes > 0
            ? _options.ExpirationMinutes
            : JwtTokenOptions.DefaultExpirationMinutes;
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(lifetimeMinutes);
        var name = BuildDisplayName(user);

        // Short JWT names so JwtBearer MapInboundClaims maps to ClaimTypes.* for Identity APIs.
        var claims = new List<Claim> {
            new("sub", user.Id.ToString()),
            new("name", name),
            new("email", user.Email),
            new("jti", Guid.NewGuid().ToString("N")),
            new(TenantClaimMatching.TenantIdClaimType, user.TenantId.ToString()),
            new(TenantClaimMatching.TenantSubdomainClaimType, user.TenantSubdomain ?? string.Empty)
        };
        foreach (var role in user.Roles) {
            claims.Add(new Claim("role", role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        var descriptor = new SecurityTokenDescriptor {
            Subject = new ClaimsIdentity(claims),
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };

        var token = new JsonWebTokenHandler().CreateToken(descriptor);
        return new AccessTokenResponse(
            token,
            "Bearer",
            (int)TimeSpan.FromMinutes(lifetimeMinutes).TotalSeconds,
            expiresAt);
    }

    private static string BuildDisplayName(AuthUserResponse user) {
        var full = $"{user.FirstName} {user.LastName}".Trim();
        return string.IsNullOrWhiteSpace(full) ? user.Email : full;
    }
}
