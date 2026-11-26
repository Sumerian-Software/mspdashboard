using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;

namespace mspdashboard.Host.Services;

public sealed class ExternalLoginService : IExternalLoginService {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _db;

    public ExternalLoginService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext db) {
        _userManager = userManager;
        _signInManager = signInManager;
        _db = db;
    }

    public async Task<string> CompleteExternalLoginAsync(HttpContext httpContext, string? returnUrl) {
        var result = await httpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
        if (!result.Succeeded || result.Principal is null) {
            return "/login?error=sso";
        }

        if (result.Properties?.Items.TryGetValue("providerId", out var providerValue) == true &&
            Guid.TryParseExact(providerValue, "N", out var providerId)) {
            var providerEnabled = await _db.TenantSsoProviders.AsNoTracking()
                .IgnoreQueryFilters()
                .AnyAsync(p => p.Id == providerId && p.IsEnabled);
            if (!providerEnabled) {
                await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                return "/login?error=sso";
            }
        }

        var external = result.Principal;
        var email = external.FindFirstValue(ClaimTypes.Email)
            ?? external.FindFirstValue("email")
            ?? external.FindFirstValue("preferred_username");
        if (string.IsNullOrWhiteSpace(email)) {
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return "/login?error=sso_email";
        }

        var loginInfo = await _signInManager.GetExternalLoginInfoAsync();
        if (loginInfo is null) {
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return "/login?error=sso";
        }

        var existingLogin = await _userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);
        ApplicationUser? user = existingLogin;

        Guid? tenantId = null;
        if (result.Properties?.Items.TryGetValue("tenantId", out var tenantValue) == true &&
            Guid.TryParseExact(tenantValue, "N", out var parsedTenant)) {
            tenantId = parsedTenant;
        }

        if (user is null) {
            if (!tenantId.HasValue) {
                await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                return "/login?error=sso_tenant";
            }

            user = await _userManager.Users.IgnoreQueryFilters()
                .FirstOrDefaultAsync(u =>
                    u.NormalizedEmail == _userManager.NormalizeEmail(email) && u.TenantId == tenantId.Value);

            if (user is null) {
                user = new ApplicationUser {
                    Id = Guid.NewGuid(),
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    TenantId = tenantId.Value,
                    IsActive = true
                };
                var create = await _userManager.CreateAsync(user);
                if (!create.Succeeded) {
                    await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                    return "/login?error=sso_create";
                }
            }

            var link = await _userManager.AddLoginAsync(user, loginInfo);
            if (!link.Succeeded && !link.Errors.All(e => e.Code == "LoginAlreadyAssociated")) {
                await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                return "/login?error=sso_link";
            }
        }

        if (!user.IsActive) {
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return "/login?error=sso_inactive";
        }

        var tenant = await _db.Tenants.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == user.TenantId);
        var claims = new List<Claim> {
            new("tenant_id", user.TenantId.ToString()),
            new("tenant_subdomain", tenant?.Subdomain ?? string.Empty)
        };

        await _signInManager.SignInWithClaimsAsync(user, isPersistent: true, claims);
        await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        return string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith('/')
            ? "/"
            : returnUrl;
    }
}
