using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;

namespace mspdashboard.Identity.Features.Tenants;

public static class GetTenantHandler {
    public static async Task<TenantDto?> Handle(
        GetTenantQuery query,
        ApplicationDbContext dbContext,
        CancellationToken cancellationToken) {
        var tenant = await dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == query.TenantId, cancellationToken);

        if (tenant == null) {
            return null;
        }

        return new TenantDto(
            tenant.Id,
            tenant.Subdomain,
            tenant.CompanyName,
            tenant.IsActive,
            tenant.CreatedAt,
            tenant.ContactEmail,
            tenant.ContactPhone
        );
    }
}
