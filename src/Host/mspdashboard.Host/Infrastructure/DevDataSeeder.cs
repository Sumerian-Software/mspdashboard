using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity;

namespace mspdashboard.Host.Infrastructure;

public static class DevDataSeeder {
    public const string DemoSubdomain = "demo";
    public const string DemoEmailDomain = "demo.local";
    public const string AdminEmail = "admin@demo.local";
    public const string AdminPassword = "DevAdmin!234";

    public static async Task SeedAsync(IServiceProvider services, ILogger logger) {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

        foreach (var role in new[] { AppRoles.TenantAdmin, AppRoles.PlatformAdmin }) {
            if (!await roleManager.RoleExistsAsync(role)) {
                await roleManager.CreateAsync(new IdentityRole<Guid> {
                    Id = Guid.NewGuid(),
                    Name = role,
                    NormalizedName = role.ToUpperInvariant()
                });
            }
        }

        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Subdomain == DemoSubdomain);
        if (tenant is null) {
            tenant = new Tenant {
                Id = Guid.NewGuid(),
                Subdomain = DemoSubdomain,
                CompanyName = "Demo MSP",
                ContactEmail = AdminEmail,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };
            db.Tenants.Add(tenant);
            await db.SaveChangesAsync();
            logger.LogInformation("Seeded demo tenant {Subdomain}", DemoSubdomain);
        }

        var domain = await db.TenantEmailDomains.FirstOrDefaultAsync(d => d.Domain == DemoEmailDomain);
        if (domain is null) {
            db.TenantEmailDomains.Add(new TenantEmailDomain {
                Id = Guid.NewGuid(),
                TenantId = tenant.Id,
                Domain = DemoEmailDomain,
                CreatedAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var admin = await userManager.Users.IgnoreQueryFilters()
            .FirstOrDefaultAsync(u => u.NormalizedEmail == userManager.NormalizeEmail(AdminEmail));
        if (admin is null) {
            admin = new ApplicationUser {
                Id = Guid.NewGuid(),
                UserName = AdminEmail,
                Email = AdminEmail,
                EmailConfirmed = true,
                TenantId = tenant.Id,
                FirstName = "Demo",
                LastName = "Admin",
                IsActive = true
            };
            var created = await userManager.CreateAsync(admin, AdminPassword);
            if (!created.Succeeded) {
                throw new InvalidOperationException(
                    "Failed to seed admin user: " + string.Join("; ", created.Errors.Select(e => e.Description)));
            }

            await userManager.AddToRoleAsync(admin, AppRoles.TenantAdmin);
            logger.LogInformation("Seeded demo admin {Email}", AdminEmail);
        }
    }
}
