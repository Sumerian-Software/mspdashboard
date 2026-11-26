using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.ApiKeys;

public static class ListApiKeysHandler {
    [Authorize]
    [WolverineGet("/api/auth/api-keys")]
    public static async Task<IResult> Handle(
        HttpContext httpContext,
        IApiKeyService apiKeys,
        CancellationToken cancellationToken) {
        var keys = await apiKeys.ListAsync(httpContext.User, cancellationToken);
        return Results.Ok(keys);
    }
}
