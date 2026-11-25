using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Auth;

public static class LogoutHandler {
    [Authorize]
    [WolverinePost("/api/auth/logout")]
    public static async Task<IResult> Handle(IPortalAuthService auth) {
        await auth.LogoutAsync();
        return Results.Ok(new { success = true });
    }
}
