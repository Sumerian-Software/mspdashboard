using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity.Features.Auth;
using mspdashboard.Identity.Features.Setup;
using mspdashboard.Identity.Infrastructure;

namespace mspdashboard.Identity.Services;

public sealed class SetupService : ISetupService {
    private static readonly SemaphoreSlim Gate = new(1, 1);

    private static readonly HashSet<string> ReservedSubdomains = new(StringComparer.OrdinalIgnoreCase) {
        "www", "api", "portal", "app", "admin", "static", "assets", "localhost"
    };

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _db;
    private readonly ITenantContext _tenantContext;
    private readonly SetupOptions _options;

    public SetupService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext db,
        ITenantContext tenantContext,
        IOptions<SetupOptions> options) {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _db = db;
        _tenantContext = tenantContext;
        _options = options.Value;
    }

    public async Task<bool> IsSetupRequiredAsync(CancellationToken cancellationToken) {
        if (!_options.AllowFirstRun) {
            return false;
        }

        return !await _db.Tenants.AnyAsync(cancellationToken);
    }

    public async Task<SetupCompletion> CompleteAsync(
        CompleteSetupRequest request, CancellationToken cancellationToken) {
        await Gate.WaitAsync(cancellationToken);
        try {
            if (!_options.AllowFirstRun) {
                return Disabled();
            }

            if (await _db.Tenants.AnyAsync(cancellationToken)) {
                return AlreadySetUp();
            }

            var companyName = request.CompanyName?.Trim() ?? string.Empty;
            var email = request.Email?.Trim() ?? string.Empty;
            var password = request.Password ?? string.Empty;
            var validationError = Validate(companyName, email, password, out var domain);
            if (validationError is not null) {
                return Bad(validationError);
            }

            var passwordError = await ValidatePasswordAsync(email, password);
            if (passwordError is not null) {
                return Bad(passwordError);
            }

            return await CreateOrganizationAsync(
                companyName, email, password, domain, cancellationToken);
        } catch (DbUpdateException) {
            return AlreadySetUp();
        } finally {
            Gate.Release();
        }
    }

    private async Task<SetupCompletion> CreateOrganizationAsync(
        string companyName,
        string email,
        string password,
        string domain,
        CancellationToken cancellationToken) {
        var subdomain = ToSubdomain(companyName);
        var tenant = new Tenant {
            Id = Guid.NewGuid(),
            Subdomain = subdomain,
            CompanyName = companyName,
            ContactEmail = email,
            IsActive = true
        };

        // Wolverine already enlists this DbContext in a transaction for the HTTP handler.
        if (await _db.Tenants.AnyAsync(cancellationToken)) {
            return AlreadySetUp();
        }

        _db.Tenants.Add(tenant);
        _db.TenantEmailDomains.Add(new TenantEmailDomain {
            Id = Guid.NewGuid(),
            TenantId = tenant.Id,
            Domain = domain
        });
        await _db.SaveChangesAsync(cancellationToken);
        _tenantContext.SetTenant(tenant.Id, tenant.Subdomain);
        await EnsureRolesAsync();

        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            TenantId = tenant.Id,
            IsActive = true
        };
        var created = await _userManager.CreateAsync(user, password);
        if (!created.Succeeded) {
            throw new InvalidOperationException(JoinErrors(created.Errors));
        }

        var roleResult = await _userManager.AddToRoleAsync(user, AppRoles.TenantAdmin);
        if (!roleResult.Succeeded) {
            throw new InvalidOperationException(JoinErrors(roleResult.Errors));
        }

        var response = new AuthUserResponse(
            user.Id,
            user.Email ?? email,
            user.TenantId,
            tenant.Subdomain,
            user.FirstName,
            user.LastName,
            new List<string> { AppRoles.TenantAdmin });

        await _signInManager.SignInWithClaimsAsync(user, isPersistent: true, new List<Claim> {
            new("tenant_id", user.TenantId.ToString()),
            new("tenant_subdomain", tenant.Subdomain)
        });

        return new SetupCompletion(true, false, false, false, null, response);
    }

    private async Task<string?> ValidatePasswordAsync(string email, string password) {
        var probe = new ApplicationUser { UserName = email, Email = email };
        foreach (var validator in _userManager.PasswordValidators) {
            var valid = await validator.ValidateAsync(_userManager, probe, password);
            if (!valid.Succeeded) {
                return JoinErrors(valid.Errors);
            }
        }

        return null;
    }

    private async Task EnsureRolesAsync() {
        foreach (var role in new[] { AppRoles.TenantAdmin, AppRoles.PlatformAdmin }) {
            if (!await _roleManager.RoleExistsAsync(role)) {
                await _roleManager.CreateAsync(new IdentityRole<Guid> {
                    Id = Guid.NewGuid(),
                    Name = role,
                    NormalizedName = role.ToUpperInvariant()
                });
            }
        }
    }

    internal static string ToSubdomain(string companyName) {
        var builder = new StringBuilder();
        var pendingHyphen = false;
        foreach (var c in companyName.Trim().ToLowerInvariant()) {
            var isSlugChar = c is >= 'a' and <= 'z' or >= '0' and <= '9';
            if (isSlugChar) {
                if (pendingHyphen && builder.Length > 0) {
                    builder.Append('-');
                }

                pendingHyphen = false;
                builder.Append(c);
            } else {
                pendingHyphen = true;
            }

            if (builder.Length >= 40) {
                break;
            }
        }

        var slug = builder.ToString().Trim('-');
        if (slug.Length < 2) {
            slug = "org";
        }

        if (ReservedSubdomains.Contains(slug)) {
            slug += "-msp";
        }

        return slug;
    }

    private static string? Validate(string companyName, string email, string password, out string domain) {
        domain = string.Empty;
        if (companyName.Length == 0) {
            return "Organization name is required.";
        }

        if (companyName.Length > 200) {
            return "Organization name must be 200 characters or fewer.";
        }

        if (email.Length == 0 || password.Length == 0) {
            return "Email and password are required.";
        }

        var at = email.LastIndexOf('@');
        if (at <= 0 || at == email.Length - 1) {
            return "Email must include a domain.";
        }

        domain = email[(at + 1)..].Trim().ToLowerInvariant();
        if (domain.Length == 0 || domain.Length > 255 || domain.Contains(' ') || domain.Contains('@')) {
            return "Email must include a domain.";
        }

        return null;
    }

    private static string JoinErrors(IEnumerable<IdentityError> errors) {
        return string.Join(" ", errors.Select(error => error.Description));
    }

    private static SetupCompletion Bad(string error) {
        return new SetupCompletion(false, false, false, true, error, null);
    }

    private static SetupCompletion AlreadySetUp() {
        return new SetupCompletion(false, true, false, false, null, null);
    }

    private static SetupCompletion Disabled() {
        return new SetupCompletion(false, false, true, false, null, null);
    }
}
