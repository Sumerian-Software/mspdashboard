using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.ApiKeys;

public static class RevokeApiKeyHandler {
    [Authorize]
    [WolverineDelete("/api/auth/api-keys/{id:guid}")]
    public static async Task<IResult> Handle(
        Guid id,
        HttpContext httpContext,
        IApiKeyService apiKeys,
        CancellationToken cancellationToken) {
        var revoked = await apiKeys.RevokeAsync(httpContext.User, id, cancellationToken);
        return revoked
            ? Results.NoContent()
            : Results.Problem(
                title: "Not found",
                detail: "API key was not found.",
                statusCode: StatusCodes.Status404NotFound);
    }
}
