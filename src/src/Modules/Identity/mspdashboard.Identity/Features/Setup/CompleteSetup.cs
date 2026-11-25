using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Features.Auth;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Setup;

public static class CompleteSetupHandler {
    [AllowAnonymous]
    [WolverinePost("/api/setup")]
    public static async Task<IResult> Handle(
        CompleteSetupRequest? request,
        ISetupService setup,
        CancellationToken cancellationToken) {
        if (request is null) {
            return Results.BadRequest(new { error = "Organization name, email, and password are required." });
        }

        var result = await setup.CompleteAsync(request, cancellationToken);
        if (result.Disabled) {
            return Results.NotFound();
        }

        if (result.AlreadySetUp) {
            return Results.Conflict(new { error = "This instance is already set up." });
        }

        if (result.BadRequest || !result.Succeeded || result.User is null) {
            return Results.BadRequest(new { error = result.Error ?? "Setup failed." });
        }

        return Results.Ok(new LoginResponse(result.User));
    }
}
