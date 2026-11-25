using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Auth;

public static class GetMeHandler {
    [Authorize]
    [WolverineGet("/api/auth/me")]
    public static async Task<IResult> Handle(ClaimsPrincipal principal, IPortalAuthService auth) {
        var user = await auth.GetCurrentUserAsync(principal);
        if (user is null) {
            return Results.Unauthorized();
        }

        return Results.Ok(user);
    }
}
