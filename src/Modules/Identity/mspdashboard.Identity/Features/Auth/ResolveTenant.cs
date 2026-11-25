using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Auth;

public static class ResolveTenantHandler {
    [AllowAnonymous]
    [WolverinePost("/api/auth/resolve-tenant")]
    public static async Task<IResult> Handle(
        ResolveTenantRequest request,
        ApplicationDbContext db,
        CancellationToken cancellationToken) {
        var subdomain = request.Subdomain?.Trim().ToLowerInvariant();
        string? emailDomain = null;
        if (!string.IsNullOrWhiteSpace(request.Email)) {
            var at = request.Email.Trim().LastIndexOf('@');
            if (at < 0 || at == request.Email.Trim().Length - 1) {
                return Results.BadRequest(new { error = "Email must include a domain." });
            }

            emailDomain = request.Email.Trim()[(at + 1)..].ToLowerInvariant();
        }

        if (string.IsNullOrWhiteSpace(subdomain) && string.IsNullOrWhiteSpace(emailDomain)) {
            return Results.BadRequest(new { error = "Provide an email or tenant subdomain." });
        }

        Guid? tenantId = null;
        if (!string.IsNullOrWhiteSpace(subdomain)) {
            var bySubdomain = await db.Tenants.AsNoTracking()
                .FirstOrDefaultAsync(t => t.Subdomain == subdomain && t.IsActive, cancellationToken);
            if (bySubdomain is null) {
                return Results.NotFound(new { error = "Tenant not found." });
            }

            tenantId = bySubdomain.Id;
        } else if (!string.IsNullOrWhiteSpace(emailDomain)) {
            var mapping = await db.TenantEmailDomains.AsNoTracking()
                .FirstOrDefaultAsync(d => d.Domain == emailDomain, cancellationToken);
            if (mapping is null) {
                return Results.NotFound(new { error = "No tenant is mapped to that email domain." });
            }

            tenantId = mapping.TenantId;
        }

        var tenant = await db.Tenants.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tenantId && t.IsActive, cancellationToken);
        if (tenant is null) {
            return Results.NotFound(new { error = "Tenant not found." });
        }

        var providers = await db.TenantSsoProviders.AsNoTracking()
            .Where(p => p.TenantId == tenant.Id && p.IsEnabled)
            .OrderBy(p => p.DisplayName)
            .Select(p => new SsoProviderPublicDto(p.Id, p.DisplayName, p.ProviderType))
            .ToListAsync(cancellationToken);

        return Results.Ok(new ResolveTenantResponse(tenant.Id, tenant.Subdomain, tenant.CompanyName, providers));
    }
}
