using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class CreateSsoProviderHandler {
    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverinePost("/api/admin/sso-providers")]
    public static async Task<IResult> Handle(
        CreateSsoProviderRequest request,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        if (!sso.HasTenantContext) {
            return Results.BadRequest(new { error = "Tenant context is required." });
        }

        var created = await sso.CreateAsync(request, cancellationToken);
        if (created is null) {
            return Results.BadRequest(new {
                error = "DisplayName, Authority, ClientId, and ClientSecret are required."
            });
        }

        return Results.Created($"/api/admin/sso-providers/{created.Id}", created);
    }
}
