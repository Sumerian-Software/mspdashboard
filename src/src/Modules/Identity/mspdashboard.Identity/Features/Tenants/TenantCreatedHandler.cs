using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using mspdashboard.Core.Infrastructure;

namespace mspdashboard.Identity.Features.Tenants;

public static class TenantCreatedHandler {
    public static async Task Handle(
        TenantCreatedEvent message,
        IDistributedCache cache,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken) {
        var logger = loggerFactory.CreateLogger(nameof(TenantCreatedHandler));
        logger.LogInformation(
            "Tenant created {TenantId} ({Subdomain})",
            message.TenantId,
            message.Subdomain);
        await TenantCache.SetAsync(cache, message.TenantId, message.Subdomain, cancellationToken);
    }
}
