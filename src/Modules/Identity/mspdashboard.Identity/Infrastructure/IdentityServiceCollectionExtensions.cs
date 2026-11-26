using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Identity.Security;
using mspdashboard.Identity.Services;

namespace mspdashboard.Identity.Infrastructure;

public static class IdentityServiceCollectionExtensions {
    public static IServiceCollection AddDashboardIdentity(this IServiceCollection services) {
        services.AddDataProtection();
        services.AddHttpContextAccessor();
        services.AddSingleton<SsoSecretProtector>();
        services.AddScoped<IPortalAuthService, PortalAuthService>();
        services.AddScoped<ISsoAdminService, SsoAdminService>();
        services.AddScoped<IApiKeyService, ApiKeyService>();
        services.AddScoped<ISetupService, SetupService>();
        services.AddScoped<ITenantContextAccessor, TenantContextAccessor>();
        services.AddOptions<SetupOptions>().BindConfiguration(SetupOptions.SectionName);

        services
            .AddIdentity<ApplicationUser, IdentityRole<Guid>>(options => {
                options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 10;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.SignIn.RequireConfirmedAccount = false;
                options.SignIn.RequireConfirmedEmail = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options => {
            options.Cookie.Name = "mspdashboard.auth";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
            options.Events.OnRedirectToLogin = context => {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context => {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        return services;
    }
}
