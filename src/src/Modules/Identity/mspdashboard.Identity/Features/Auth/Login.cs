using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Auth;

public static class LoginHandler {
    [AllowAnonymous]
    [WolverinePost("/api/auth/login")]
    public static async Task<IResult> Handle(
        LoginRequest request,
        IPortalAuthService auth,
        CancellationToken cancellationToken) {
        var result = await auth.LoginAsync(request, cancellationToken);
        if (result.BadRequest) {
            return Results.BadRequest(new { error = result.Error });
        }

        if (result.LockedOut) {
            return Results.Json(new { error = result.Error }, statusCode: StatusCodes.Status423Locked);
        }

        if (!result.Succeeded || result.User is null) {
            return Results.Unauthorized();
        }

        return Results.Ok(new LoginResponse(result.User));
    }
}
