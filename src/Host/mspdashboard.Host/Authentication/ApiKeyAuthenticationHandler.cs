using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity;
using mspdashboard.Identity.Security;

namespace mspdashboard.Host.Authentication;

public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
    private static readonly TimeSpan LastUsedUpdateThreshold = TimeSpan.FromMinutes(5);

    private readonly ApplicationDbContext _db;
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsFactory;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApplicationDbContext db,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory)
        : base(options, logger, encoder) {
        _db = db;
        _claimsFactory = claimsFactory;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
        var rawKey = ExtractKey(Request);
        if (rawKey is null) {
            return AuthenticateResult.NoResult();
        }

        if (!ApiKeyFormat.TryParse(rawKey, out var prefix, out var secret)) {
            return AuthenticateResult.Fail("Malformed API key.");
        }

        var apiKey = await _db.ApiKeys
            .IgnoreQueryFilters()
            .AsNoTracking()
            .FirstOrDefaultAsync(k => k.Prefix == prefix, Context.RequestAborted);

        if (apiKey is null) {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        var computedHash = ApiKeyFormat.HashSecret(secret);
        if (apiKey.SecretHash.Length != computedHash.Length ||
            !CryptographicOperations.FixedTimeEquals(apiKey.SecretHash, computedHash)) {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        if (apiKey.RevokedAt is not null) {
            return AuthenticateResult.Fail("API key has been revoked.");
        }

        if (apiKey.ExpiresAt is not null && apiKey.ExpiresAt.Value <= DateTime.UtcNow) {
            return AuthenticateResult.Fail("API key has expired.");
        }

        var user = await _db.Users
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.Id == apiKey.UserId, Context.RequestAborted);

        if (user is null || !user.IsActive) {
            return AuthenticateResult.Fail("API key user is inactive or missing.");
        }

        var tenant = await _db.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == user.TenantId && t.IsActive, Context.RequestAborted);

        if (tenant is null) {
            return AuthenticateResult.Fail("API key tenant is inactive or missing.");
        }

        var principal = await _claimsFactory.CreateAsync(user);
        var sourceIdentity = (ClaimsIdentity)principal.Identity!;
        var identity = new ClaimsIdentity(
            sourceIdentity.Claims,
            ApiKeyDefaults.AuthenticationScheme,
            sourceIdentity.NameClaimType,
            sourceIdentity.RoleClaimType);

        identity.AddClaim(new Claim(TenantClaimMatching.TenantIdClaimType, user.TenantId.ToString()));
        identity.AddClaim(new Claim(TenantClaimMatching.TenantSubdomainClaimType, tenant.Subdomain));
        identity.AddClaim(new Claim(ApiKeyDefaults.ApiKeyIdClaimType, apiKey.Id.ToString()));

        await TryTouchLastUsedAsync(apiKey.Id, apiKey.LastUsedAt);

        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            ApiKeyDefaults.AuthenticationScheme);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = ApiKeyDefaults.AuthenticationScheme;
        return Task.CompletedTask;
    }

    private static string? ExtractKey(HttpRequest request) {
        if (request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var headerValues)) {
            var header = headerValues.ToString();
            if (!string.IsNullOrWhiteSpace(header)) {
                return header.Trim();
            }
        }

        var authorization = request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authorization) &&
            authorization.StartsWith(
                ApiKeyDefaults.AuthorizationScheme + " ",
                StringComparison.OrdinalIgnoreCase)) {
            return authorization[(ApiKeyDefaults.AuthorizationScheme.Length + 1)..].Trim();
        }

        return null;
    }

    private async Task TryTouchLastUsedAsync(Guid apiKeyId, DateTime? lastUsedAt) {
        var threshold = DateTime.UtcNow - LastUsedUpdateThreshold;
        if (lastUsedAt is not null && lastUsedAt.Value > threshold) {
            return;
        }

        try {
            var now = DateTime.UtcNow;
            await _db.ApiKeys
                .IgnoreQueryFilters()
                .Where(k => k.Id == apiKeyId)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(k => k.LastUsedAt, now),
                    Context.RequestAborted);
        } catch (Exception ex) {
            Logger.LogDebug(ex, "Failed to update LastUsedAt for API key {ApiKeyId}", apiKeyId);
        }
    }
}
