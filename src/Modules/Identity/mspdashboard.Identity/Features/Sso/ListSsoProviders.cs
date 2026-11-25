using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class ListSsoProvidersHandler {
    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverineGet("/api/admin/sso-providers")]
    public static async Task<IResult> Handle(ISsoAdminService sso, CancellationToken cancellationToken) {
        if (!sso.HasTenantContext) {
            return Results.BadRequest(new { error = "Tenant context is required." });
        }

        return Results.Ok(await sso.ListAsync(cancellationToken));
    }
}
