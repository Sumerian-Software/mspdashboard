using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity;
using Wolverine;

namespace mspdashboard.Host.Tests.Infrastructure;

public sealed class ApiFactory : WebApplicationFactory<Program>, IAsyncLifetime {
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly Dictionary<string, string?> _extraSettings;

    public ApiFactory() : this(null) {
    }

    public static ApiFactory Create(IReadOnlyDictionary<string, string?> extraSettings) {
        return new ApiFactory(extraSettings);
    }

    private ApiFactory(IReadOnlyDictionary<string, string?>? extraSettings) {
        _extraSettings = extraSettings is null
            ? new Dictionary<string, string?>()
            : new Dictionary<string, string?>(extraSettings);
        _connection.Open();
        // Overrides appsettings so the host skips Postgres transport and Redis.
        foreach (var pair in TestSettings()) {
            Environment.SetEnvironmentVariable(pair.Key.Replace(":", "__"), pair.Value);
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) {
        builder.UseEnvironment("Testing");
        foreach (var pair in AllSettings()) {
            builder.UseSetting(pair.Key, pair.Value);
        }

        builder.ConfigureAppConfiguration((_, config) => {
            config.AddInMemoryCollection(AllSettings());
        });

        builder.ConfigureTestServices(services => {
            RemoveDbContextRegistrations(services);
            services.AddDbContext<ApplicationDbContext>(options => {
                options.UseSqlite(_connection);
            }, optionsLifetime: ServiceLifetime.Singleton);
            services.AddSingleton<IWolverineExtension, TestWolverineExtension>();
            services.DisableAllExternalWolverineTransports();
        });
    }

    public async Task InitializeAsync() {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();
        await EnsureRolesAsync(scope.ServiceProvider);
    }

    public async Task<(Tenant Tenant, ApplicationUser Admin)> SeedTenantAdminAsync(
        string subdomain,
        string email,
        string password,
        string? emailDomain = null) {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        await EnsureRolesAsync(scope.ServiceProvider);

        var tenant = new Tenant {
            Id = Guid.NewGuid(),
            Subdomain = subdomain,
            CompanyName = subdomain + " Co",
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };
        db.Tenants.Add(tenant);

        if (!string.IsNullOrWhiteSpace(emailDomain)) {
            db.TenantEmailDomains.Add(new TenantEmailDomain {
                Id = Guid.NewGuid(),
                TenantId = tenant.Id,
                Domain = emailDomain.ToLowerInvariant(),
                CreatedAt = DateTime.UtcNow
            });
        }

        await db.SaveChangesAsync();

        var user = new ApplicationUser {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            TenantId = tenant.Id,
            IsActive = true
        };
        var created = await userManager.CreateAsync(user, password);
        if (!created.Succeeded) {
            throw new InvalidOperationException(string.Join("; ", created.Errors.Select(e => e.Description)));
        }

        await userManager.AddToRoleAsync(user, AppRoles.TenantAdmin);
        return (tenant, user);
    }

    async Task IAsyncLifetime.DisposeAsync() {
        await DisposeAsync();
    }

    public override async ValueTask DisposeAsync() {
        try {
            await base.DisposeAsync();
        } finally {
            await _connection.DisposeAsync();
        }
    }

    private static async Task EnsureRolesAsync(IServiceProvider services) {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        foreach (var role in new[] { AppRoles.TenantAdmin, AppRoles.PlatformAdmin }) {
            if (!await roleManager.RoleExistsAsync(role)) {
                await roleManager.CreateAsync(new IdentityRole<Guid> {
                    Id = Guid.NewGuid(),
                    Name = role,
                    NormalizedName = role.ToUpperInvariant()
                });
            }
        }
    }

    private Dictionary<string, string?> AllSettings() {
        var settings = TestSettings();
        foreach (var pair in _extraSettings) {
            settings[pair.Key] = pair.Value;
        }

        return settings;
    }

    private static Dictionary<string, string?> TestSettings() {
        return new Dictionary<string, string?> {
            ["ConnectionStrings:DefaultConnection"] = "",
            ["ConnectionStrings:Redis"] = "",
            ["JwtSettings:Secret"] = TestTokens.SigningKey,
            ["JwtSettings:Issuer"] = TestTokens.Issuer,
            ["JwtSettings:Audience"] = TestTokens.Audience,
            ["Authentication:Schemes:Bearer:ValidIssuer"] = TestTokens.DevJwtIssuer,
            ["Authentication:Schemes:Bearer:ValidAudience"] = TestTokens.DevJwtAudience,
            ["Authentication:Schemes:Bearer:SigningKeys:0:Id"] = "dev-user-jwts",
            ["Authentication:Schemes:Bearer:SigningKeys:0:Issuer"] = TestTokens.DevJwtIssuer,
            ["Authentication:Schemes:Bearer:SigningKeys:0:Value"] =
                Convert.ToBase64String(TestTokens.DevJwtKeyMaterial),
            ["Authentication:Schemes:Bearer:SigningKeys:0:Length"] = "32"
        };
    }

    private static void RemoveDbContextRegistrations(IServiceCollection services) {
        var optionsConfig = typeof(IDbContextOptionsConfiguration<ApplicationDbContext>);
        var descriptors = services.Where(descriptor =>
            descriptor.ServiceType == typeof(DbContextOptions<ApplicationDbContext>)
            || descriptor.ServiceType == typeof(DbContextOptions)
            || descriptor.ServiceType == typeof(ApplicationDbContext)
            || descriptor.ServiceType == optionsConfig).ToList();

        foreach (var descriptor in descriptors) {
            services.Remove(descriptor);
        }
    }
}
