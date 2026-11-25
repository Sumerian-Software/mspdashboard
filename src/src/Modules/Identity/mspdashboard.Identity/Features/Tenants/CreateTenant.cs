using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using mspdashboard.Core.Data;
using mspdashboard.Core.Entities;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Identity;
using Wolverine.Http;

namespace mspdashboard.Identity.Features.Tenants;

public static class CreateTenantHandler {
    [Authorize(Policy = AuthorizationPolicies.PlatformAdmin)]
    [WolverinePost("/api/tenants")]
    public static async Task<(TenantCreatedResponse, TenantCreatedEvent)> Handle(
        CreateTenantCommand command,
        ApplicationDbContext dbContext,
        IDistributedCache cache,
        CancellationToken cancellationToken) {
        var existingTenant = await dbContext.Tenants
            .FirstOrDefaultAsync(t => t.Subdomain == command.Subdomain, cancellationToken);

        if (existingTenant != null) {
            throw new InvalidOperationException($"Tenant with subdomain '{command.Subdomain}' already exists");
        }

        var tenant = new Tenant {
            Id = Guid.NewGuid(),
            Subdomain = command.Subdomain,
            CompanyName = command.CompanyName,
            ContactEmail = command.ContactEmail,
            ContactPhone = command.ContactPhone,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        dbContext.Tenants.Add(tenant);
        await dbContext.SaveChangesAsync(cancellationToken);
        await TenantCache.SetAsync(cache, tenant.Id, tenant.Subdomain, cancellationToken);

        var response = new TenantCreatedResponse(tenant.Id, tenant.Subdomain, tenant.CompanyName);
        var created = new TenantCreatedEvent(tenant.Id, tenant.Subdomain, tenant.CompanyName);

        return (response, created);
    }
}
