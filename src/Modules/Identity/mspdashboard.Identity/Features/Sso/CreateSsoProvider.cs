using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mspdashboard.Identity.Infrastructure;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class CreateSsoProviderHandler {
    /// <summary>Tenant-context check; request shape is covered by CreateSsoProviderRequestValidator.</summary>
    public static ProblemDetails Validate(ISsoAdminService sso) {
        return sso.HasTenantContext
            ? WolverineContinue.NoProblems
            : Problems.BadRequest("Tenant context is required.");
    }

    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverinePost("/api/admin/sso-providers")]
    public static async Task<IResult> Handle(
        CreateSsoProviderRequest request,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        var created = await sso.CreateAsync(request, cancellationToken);
        return Results.Created($"/api/admin/sso-providers/{created.Id}", created);
    }
}
