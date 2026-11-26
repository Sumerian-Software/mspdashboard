using System.Security.Claims;

namespace mspdashboard.Identity;

/// <summary>
/// Shared rules for whether an authenticated principal may operate in a resolved tenant context.
/// Used by claim-tenant middleware and <see cref="Services.TenantContextAccessor"/>.
/// </summary>
public static class TenantClaimMatching {
    public const string TenantIdClaimType = "tenant_id";
    public const string TenantSubdomainClaimType = "tenant_subdomain";

    /// <summary>
    /// PlatformAdmin and principals with no tenant claims are exempt from tenant-match checks.
    /// Anonymous callers are also treated as exempt (no mismatch enforcement).
    /// </summary>
    public static bool IsExempt(ClaimsPrincipal? principal) {
        if (principal?.Identity?.IsAuthenticated != true) {
            return true;
        }

        if (principal.IsInRole(AppRoles.PlatformAdmin)) {
            return true;
        }

        return !HasTenantClaims(principal);
    }

    public static bool HasTenantClaims(ClaimsPrincipal principal) {
        var id = principal.FindFirstValue(TenantIdClaimType);
        var subdomain = principal.FindFirstValue(TenantSubdomainClaimType);
        return !string.IsNullOrWhiteSpace(id) || !string.IsNullOrWhiteSpace(subdomain);
    }

    /// <summary>
    /// True when the principal is exempt or all present tenant claims match the given tenant.
    /// When both id and subdomain claims exist, both must match. Prefers id comparison when present.
    /// </summary>
    public static bool MatchesResolvedTenant(
        ClaimsPrincipal principal,
        Guid tenantId,
        string subdomain) {
        if (IsExempt(principal)) {
            return true;
        }

        return ClaimsMatch(principal, tenantId, subdomain);
    }

    public static bool ClaimsMatch(ClaimsPrincipal principal, Guid tenantId, string subdomain) {
        var idValue = principal.FindFirstValue(TenantIdClaimType);
        var subdomainValue = principal.FindFirstValue(TenantSubdomainClaimType);

        var hasIdClaim = !string.IsNullOrWhiteSpace(idValue);
        var hasSubdomainClaim = !string.IsNullOrWhiteSpace(subdomainValue);

        if (!hasIdClaim && !hasSubdomainClaim) {
            return true;
        }

        if (hasIdClaim) {
            if (!Guid.TryParse(idValue, out var claimTenantId) || claimTenantId != tenantId) {
                return false;
            }
        }

        if (hasSubdomainClaim &&
            !string.Equals(subdomainValue, subdomain, StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        return true;
    }
}
