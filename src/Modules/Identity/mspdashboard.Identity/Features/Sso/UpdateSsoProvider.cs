using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class UpdateSsoProviderHandler {
    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverinePut("/api/admin/sso-providers/{id:guid}")]
    public static async Task<IResult> Handle(
        Guid id,
        UpdateSsoProviderRequest request,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        if (!sso.HasTenantContext) {
            return Results.BadRequest(new { error = "Tenant context is required." });
        }

        try {
            var updated = await sso.UpdateAsync(id, request, cancellationToken);
            return updated is null ? Results.NotFound() : Results.Ok(updated);
        } catch (ArgumentException ex) {
            return Results.BadRequest(new { error = ex.Message });
        }
    }
}
