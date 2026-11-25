using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Contracts;
using mspdashboard.Core.Entities;

namespace mspdashboard.Core.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid> {
    private readonly ITenantContext _tenantContext;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, ITenantContext tenantContext)
        : base(options) {
        _tenantContext = tenantContext;
    }

    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<TenantEmailDomain> TenantEmailDomains => Set<TenantEmailDomain>();
    public DbSet<TenantSsoProvider> TenantSsoProviders => Set<TenantSsoProvider>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Tenant>(entity => {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Subdomain).IsUnique();
            entity.Property(e => e.Subdomain).HasMaxLength(100).IsRequired();
            entity.Property(e => e.CompanyName).HasMaxLength(200).IsRequired();
            entity.Property(e => e.ContactEmail).HasMaxLength(255);
            entity.Property(e => e.ContactPhone).HasMaxLength(50);
        });

        modelBuilder.Entity<TenantEmailDomain>(entity => {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Domain).HasMaxLength(255).IsRequired();
            entity.HasIndex(e => e.Domain).IsUnique();
            entity.HasIndex(e => e.TenantId);
        });

        modelBuilder.Entity<TenantSsoProvider>(entity => {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.DisplayName).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Authority).HasMaxLength(500).IsRequired();
            entity.Property(e => e.ClientId).HasMaxLength(200).IsRequired();
            entity.Property(e => e.ClientSecretProtected).HasMaxLength(2000).IsRequired();
            entity.Property(e => e.Scopes).HasMaxLength(500).IsRequired();
            entity.HasIndex(e => new { e.TenantId, e.DisplayName });
            entity.HasQueryFilter(e =>
                !_tenantContext.TenantId.HasValue || e.TenantId == _tenantContext.TenantId);
        });

        modelBuilder.Entity<ApplicationUser>(entity => {
            entity.Property(e => e.FirstName).HasMaxLength(100);
            entity.Property(e => e.LastName).HasMaxLength(100);
            entity.HasIndex(e => new { e.TenantId, e.NormalizedEmail });
            entity.HasQueryFilter(u =>
                !_tenantContext.TenantId.HasValue || u.TenantId == _tenantContext.TenantId);
        });
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) {
        SetAuditFields();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges() {
        SetAuditFields();
        return base.SaveChanges();
    }

    private void SetAuditFields() {
        var entries = ChangeTracker.Entries<BaseEntity>();
        var now = DateTime.UtcNow;

        foreach (var entry in entries) {
            if (entry.State == EntityState.Added) {
                entry.Entity.CreatedAt = now;
                if (entry.Entity is BaseTenantEntity tenantEntity && _tenantContext.TenantId.HasValue) {
                    tenantEntity.TenantId = _tenantContext.TenantId.Value;
                }
            } else if (entry.State == EntityState.Modified) {
                entry.Entity.UpdatedAt = now;
            }
        }
    }
}
