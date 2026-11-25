using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mspdashboard.Host.Services;
using Wolverine.Http;

namespace mspdashboard.Host.Features.Auth;

public static class SsoCompleteHandler {
    [AllowAnonymous]
    [WolverineGet("/api/auth/sso/complete")]
    public static async Task<IResult> Handle(
        [FromQuery] string? returnUrl,
        HttpContext httpContext,
        IExternalLoginService externalLogin) {
        var redirect = await externalLogin.CompleteExternalLoginAsync(httpContext, returnUrl);
        return Results.Redirect(redirect);
    }
}
