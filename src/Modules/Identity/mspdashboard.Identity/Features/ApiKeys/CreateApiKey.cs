using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Infrastructure;
using mspdashboard.Identity.Security;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.ApiKeys;

public static class CreateApiKeyHandler {
    [Authorize]
    [WolverinePost("/api/auth/api-keys")]
    public static async Task<IResult> Handle(
        CreateApiKeyRequest request,
        HttpContext httpContext,
        IApiKeyService apiKeys,
        CancellationToken cancellationToken) {
        if (IsApiKeyRequest(httpContext)) {
            return Results.Problem(
                title: "API key cannot create API keys",
                detail: "API keys cannot mint new API keys. Sign in with a cookie session or bearer token.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        var created = await apiKeys.CreateAsync(httpContext.User, request, cancellationToken);
        if (created is null) {
            return Results.Unauthorized();
        }

        return Results.Created($"/api/auth/api-keys/{created.Id}", created);
    }

    /// <summary>
    /// Belt-and-braces: refuse when the request carries an API key header, or when the principal
    /// was authenticated with the ApiKey scheme (even if headers were stripped somehow).
    /// </summary>
    internal static bool IsApiKeyRequest(HttpContext httpContext) {
        if (httpContext.Request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var headerValues) &&
            !string.IsNullOrWhiteSpace(headerValues.ToString())) {
            return true;
        }

        var authorization = httpContext.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authorization) &&
            authorization.StartsWith(
                ApiKeyDefaults.AuthorizationScheme + " ",
                StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        return string.Equals(
            httpContext.User.Identity?.AuthenticationType,
            ApiKeyDefaults.AuthenticationScheme,
            StringComparison.Ordinal);
    }
}
