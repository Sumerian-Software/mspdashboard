using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using mspdashboard.Identity.Features.Auth;
using mspdashboard.Identity.Infrastructure;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Setup;

public static class CompleteSetupHandler {
    /// <summary>
    /// Instance-state and password-policy checks that need services. Request shape is covered by
    /// CompleteSetupRequestValidator. SetupService repeats the state checks under its lock to
    /// cover concurrent first-run requests.
    /// </summary>
    public static async Task<ProblemDetails> ValidateAsync(
        CompleteSetupRequest request,
        ISetupService setup,
        IOptions<SetupOptions> options,
        CancellationToken cancellationToken) {
        if (!options.Value.AllowFirstRun) {
            return Problems.NotFound("First-run setup is not enabled on this instance.");
        }

        if (!await setup.IsSetupRequiredAsync(cancellationToken)) {
            return Problems.Conflict("This instance is already set up.");
        }

        var passwordError = await setup.ValidatePasswordAsync(request.Email!.Trim(), request.Password!);
        return passwordError is null
            ? WolverineContinue.NoProblems
            : Problems.Validation(nameof(CompleteSetupRequest.Password), passwordError);
    }

    [AllowAnonymous]
    [WolverinePost("/api/setup")]
    public static async Task<IResult> Handle(
        CompleteSetupRequest request,
        ISetupService setup,
        CancellationToken cancellationToken) {
        var result = await setup.CompleteAsync(request, cancellationToken);
        if (result.Disabled) {
            return Results.Problem(
                title: "Not found",
                detail: "First-run setup is not enabled on this instance.",
                statusCode: StatusCodes.Status404NotFound);
        }

        if (result.AlreadySetUp) {
            return Results.Problem(
                title: "Conflict",
                detail: "This instance is already set up.",
                statusCode: StatusCodes.Status409Conflict);
        }

        if (result.BadRequest || !result.Succeeded || result.User is null) {
            return Results.Problem(
                title: "Setup failed",
                detail: result.Error ?? "Setup failed.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return Results.Ok(new LoginResponse(result.User));
    }
}
