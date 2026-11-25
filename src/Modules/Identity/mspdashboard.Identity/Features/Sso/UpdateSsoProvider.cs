using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mspdashboard.Identity.Infrastructure;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Sso;

public static class UpdateSsoProviderHandler {
    /// <summary>Tenant-context check; request shape is covered by UpdateSsoProviderRequestValidator.</summary>
    public static ProblemDetails Validate(ISsoAdminService sso) {
        return sso.HasTenantContext
            ? WolverineContinue.NoProblems
            : Problems.BadRequest("Tenant context is required.");
    }

    [Authorize(Roles = AppRoles.TenantAdmin + "," + AppRoles.PlatformAdmin)]
    [WolverinePut("/api/admin/sso-providers/{id:guid}")]
    public static async Task<IResult> Handle(
        Guid id,
        UpdateSsoProviderRequest request,
        ISsoAdminService sso,
        CancellationToken cancellationToken) {
        var updated = await sso.UpdateAsync(id, request, cancellationToken);
        return updated is null ? Results.NotFound() : Results.Ok(updated);
    }
}
