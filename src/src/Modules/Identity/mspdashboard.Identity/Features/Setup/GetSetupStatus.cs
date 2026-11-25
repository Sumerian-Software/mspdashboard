using Microsoft.AspNetCore.Authorization;
using mspdashboard.Identity.Services;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Setup;

public static class GetSetupStatusHandler {
    [AllowAnonymous]
    [WolverineGet("/api/setup/status")]
    public static async Task<SetupStatusResponse> Handle(
        ISetupService setup,
        CancellationToken cancellationToken) {
        var required = await setup.IsSetupRequiredAsync(cancellationToken);
        return new SetupStatusResponse(required);
    }
}
