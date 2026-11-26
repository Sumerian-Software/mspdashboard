using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Host.Authentication;
using Wolverine.Http;

namespace mspdashboard.Host.Features.Auth;

public static class SsoChallengeHandler {
    [AllowAnonymous]
    [WolverineGet("/api/auth/sso/{providerId:guid}/challenge")]
    public static async Task<IResult> Handle(
        Guid providerId,
        [FromQuery] string? returnUrl,
        HttpContext httpContext,
        ApplicationDbContext db,
        DynamicOidcSchemeManager schemeManager,
        CancellationToken cancellationToken) {
        var provider = await db.TenantSsoProviders.AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(p => p.Id == providerId && p.IsEnabled, cancellationToken);
        if (provider is null) {
            return Results.NotFound(new { error = "SSO provider not found." });
        }

        if (!await schemeManager.EnsureSchemeAsync(providerId, cancellationToken)) {
            return Results.NotFound(new { error = "SSO provider not found." });
        }

        var safeReturn = string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith('/')
            ? "/"
            : returnUrl;

        var properties = new AuthenticationProperties {
            RedirectUri = $"/api/auth/sso/complete?returnUrl={Uri.EscapeDataString(safeReturn)}"
        };
        properties.Items["providerId"] = providerId.ToString("N");
        properties.Items["tenantId"] = provider.TenantId.ToString("N");

        var scheme = SsoSchemeNames.ForProvider(providerId);
        return Results.Challenge(properties, [scheme]);
    }
}
