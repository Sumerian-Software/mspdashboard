using Microsoft.Extensions.Caching.Distributed;

namespace mspdashboard.Core.Infrastructure;

public static class TenantCache {
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public static string Key(string subdomain) {
        return "tenant:subdomain:" + subdomain.Trim().ToLowerInvariant();
    }

    public static Task SetAsync(IDistributedCache cache, Guid tenantId, string subdomain,
        CancellationToken cancellationToken) {
        var options = new DistributedCacheEntryOptions {
            AbsoluteExpirationRelativeToNow = Ttl
        };
        var value = tenantId.ToString("D") + "|" + subdomain;
        return cache.SetStringAsync(Key(subdomain), value, options, cancellationToken);
    }

    public static bool TryRead(string? value, out Guid tenantId, out string subdomain) {
        tenantId = Guid.Empty;
        subdomain = "";
        if (string.IsNullOrEmpty(value)) {
            return false;
        }

        var split = value.IndexOf('|');
        if (split <= 0 || split >= value.Length - 1) {
            return false;
        }

        if (!Guid.TryParse(value[..split], out tenantId)) {
            return false;
        }

        subdomain = value[(split + 1)..];
        return true;
    }
}
