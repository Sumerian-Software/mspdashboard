using Microsoft.AspNetCore.Authorization;
using mspdashboard.Host.Authentication;
using mspdashboard.Identity.Features.Auth;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Host.Features.Auth;

public static class IssueTokenHandler {
    [AllowAnonymous]
    [WolverinePost("/api/auth/token")]
    public static async Task<IResult> Handle(
        IssueTokenRequest? request,
        HttpContext httpContext,
        IPortalAuthService auth,
        IJwtAccessTokenIssuer tokens,
        CancellationToken cancellationToken) {
        // Refuse Bearer renewal before anything else (including an otherwise-valid cookie).
        if (HasBearerAuthorization(httpContext.Request)) {
            return Results.Problem(
                title: "Bearer renewal not allowed",
                detail: "API tokens cannot be used to issue new tokens. Sign in with a cookie session or email and password.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        if (!tokens.CanIssue) {
            return Results.Problem(
                title: "JWT signing not configured",
                detail:
                    "JwtSettings:Secret is not set. Set a signing secret of at least 32 characters to issue API tokens.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        request ??= new IssueTokenRequest(null, null, null);
        var hasCredentials = !string.IsNullOrWhiteSpace(request.Email) ||
                             !string.IsNullOrWhiteSpace(request.Password);

        AuthUserResponse? user;
        if (hasCredentials) {
            var loginRequest = new LoginRequest(
                request.Email ?? string.Empty,
                request.Password ?? string.Empty,
                request.TenantSubdomain);
            var result = await auth.AuthenticateCredentialsAsync(loginRequest, cancellationToken);
            if (result.LockedOut) {
                return Results.Problem(
                    title: "Account locked",
                    detail: result.Error,
                    statusCode: StatusCodes.Status423Locked);
            }

            if (!result.Succeeded || result.User is null) {
                return Results.Unauthorized();
            }

            user = result.User;
        }
        else if (httpContext.User.Identity?.IsAuthenticated == true) {
            // Cookie (or other non-Bearer) session — Bearer was already rejected above.
            user = await auth.GetCurrentUserAsync(httpContext.User);
            if (user is null) {
                return Results.Unauthorized();
            }
        }
        else {
            return Results.Unauthorized();
        }

        var token = tokens.Issue(user);
        return Results.Ok(token);
    }

    private static bool HasBearerAuthorization(HttpRequest request) {
        var header = request.Headers.Authorization.ToString();
        return !string.IsNullOrEmpty(header) &&
               header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
    }
}
