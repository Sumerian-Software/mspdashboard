using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Data;

namespace mspdashboard.Core.Infrastructure;

public static class ServiceCollectionExtensions {
    public static IServiceCollection AddCoreInfrastructure(this IServiceCollection services,
        IConfiguration configuration) {
        services.AddScoped<ITenantContext, TenantContext>();

        var connectionString = configuration.GetConnectionString("DefaultConnection");
        services.AddDbContext<ApplicationDbContext>(options => {
            options.UseNpgsql(connectionString, npgsqlOptions => {
                npgsqlOptions.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.GetName().Name);
            });
        }, optionsLifetime: ServiceLifetime.Singleton);

        var redisConnection = configuration.GetConnectionString("Redis");
        if (!string.IsNullOrEmpty(redisConnection)) {
            services.AddStackExchangeRedisCache(options => {
                options.Configuration = redisConnection;
            });
        } else {
            services.AddDistributedMemoryCache();
        }

        return services;
    }
}
