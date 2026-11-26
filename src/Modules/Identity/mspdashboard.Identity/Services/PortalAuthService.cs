using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity.Features.Auth;

namespace mspdashboard.Identity.Services;

public sealed class PortalAuthService : IPortalAuthService {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _db;
    private readonly ITenantContext _tenantContext;

    public PortalAuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext db,
        ITenantContext tenantContext) {
        _userManager = userManager;
        _signInManager = signInManager;
        _db = db;
        _tenantContext = tenantContext;
    }

    public async Task<AuthAttemptResult> LoginAsync(LoginRequest request, CancellationToken cancellationToken) {
        var authenticated = await TryAuthenticateAsync(request, cancellationToken);
        if (!authenticated.Result.Succeeded || authenticated.User is null) {
            return authenticated.Result;
        }

        var claims = BuildTenantClaims(authenticated.User, authenticated.TenantSubdomain);
        await _signInManager.SignInWithClaimsAsync(authenticated.User, isPersistent: true, claims);
        return authenticated.Result;
    }

    public async Task<AuthAttemptResult> AuthenticateCredentialsAsync(
        LoginRequest request,
        CancellationToken cancellationToken) {
        var authenticated = await TryAuthenticateAsync(request, cancellationToken);
        return authenticated.Result;
    }

    public Task LogoutAsync() {
        return _signInManager.SignOutAsync();
    }

    public async Task<AuthUserResponse?> GetCurrentUserAsync(ClaimsPrincipal principal) {
        var user = await _userManager.GetUserAsync(principal);
        if (user is null || !user.IsActive) {
            return null;
        }

        var roles = await _userManager.GetRolesAsync(user);
        var subdomain = principal.FindFirstValue("tenant_subdomain");
        return new AuthUserResponse(
            user.Id,
            user.Email ?? string.Empty,
            user.TenantId,
            subdomain,
            user.FirstName,
            user.LastName,
            roles.ToList());
    }

    private async Task<(AuthAttemptResult Result, ApplicationUser? User, string? TenantSubdomain)>
        TryAuthenticateAsync(LoginRequest request, CancellationToken cancellationToken) {
        // Required fields are checked by LoginRequestValidator / IssueTokenRequestValidator before this runs.
        var email = request.Email.Trim();
        Guid? tenantId = _tenantContext.TenantId;
        string? tenantSubdomain = _tenantContext.Subdomain;

        if (!tenantId.HasValue && !string.IsNullOrWhiteSpace(request.TenantSubdomain)) {
            var subdomain = request.TenantSubdomain.Trim().ToLowerInvariant();
            var tenant = await _db.Tenants.AsNoTracking()
                .FirstOrDefaultAsync(t => t.Subdomain == subdomain && t.IsActive, cancellationToken);
            if (tenant is null) {
                return Fail();
            }

            tenantId = tenant.Id;
            tenantSubdomain = tenant.Subdomain;
            _tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
        }

        if (!tenantId.HasValue) {
            var at = email.LastIndexOf('@');
            if (at > 0) {
                var domain = email[(at + 1)..].ToLowerInvariant();
                var mapping = await _db.TenantEmailDomains.AsNoTracking()
                    .FirstOrDefaultAsync(d => d.Domain == domain, cancellationToken);
                if (mapping is not null) {
                    var tenant = await _db.Tenants.AsNoTracking()
                        .FirstOrDefaultAsync(t => t.Id == mapping.TenantId && t.IsActive, cancellationToken);
                    if (tenant is not null) {
                        tenantId = tenant.Id;
                        tenantSubdomain = tenant.Subdomain;
                        _tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
                    }
                }
            }
        }

        if (!tenantId.HasValue) {
            return Fail();
        }

        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.NormalizedEmail == _userManager.NormalizeEmail(email)
                && u.TenantId == tenantId.Value, cancellationToken);

        if (user is null || !user.IsActive) {
            return Fail();
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (result.IsLockedOut) {
            return (new AuthAttemptResult(false, true, false, "Account locked. Try again later.", null), null, null);
        }

        if (!result.Succeeded) {
            return Fail();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var response = new AuthUserResponse(
            user.Id,
            user.Email ?? email,
            user.TenantId,
            tenantSubdomain,
            user.FirstName,
            user.LastName,
            roles.ToList());
        return (new AuthAttemptResult(true, false, false, null, response), user, tenantSubdomain);
    }

    private static List<Claim> BuildTenantClaims(ApplicationUser user, string? tenantSubdomain) {
        return [
            new("tenant_id", user.TenantId.ToString()),
            new("tenant_subdomain", tenantSubdomain ?? string.Empty)
        ];
    }

    private static (AuthAttemptResult Result, ApplicationUser? User, string? TenantSubdomain) Fail() {
        return (new AuthAttemptResult(false, false, false, null, null), null, null);
    }
}
