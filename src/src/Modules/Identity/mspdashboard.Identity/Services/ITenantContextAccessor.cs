using mspdashboard.Core.Contracts;

namespace mspdashboard.Identity.Services;

public interface ITenantContextAccessor {
    ITenantContext Current { get; }
    bool EnsureResolved();
}
