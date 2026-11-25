using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class GetSsoProviderHandler {
    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverineGet("/api/admin/sso-providers/{id:guid}")]
    public static async Task<IResult> Handle(
        Guid id,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        if (!sso.HasTenantContext) {
            return Results.BadRequest(new { error = "Tenant context is required." });
        }

        var item = await sso.GetAsync(id, cancellationToken);
        return item is null ? Results.NotFound() : Results.Ok(item);
    }
}
