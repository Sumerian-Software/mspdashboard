using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class DeleteSsoProviderHandler {
    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverineDelete("/api/admin/sso-providers/{id:guid}")]
    public static async Task<IResult> Handle(
        Guid id,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        if (!sso.HasTenantContext) {
            return Results.BadRequest(new { error = "Tenant context is required." });
        }

        return await sso.DeleteAsync(id, cancellationToken) ? Results.NoContent() : Results.NotFound();
    }
}
