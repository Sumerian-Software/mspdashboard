using Wolverine;
using Wolverine.EntityFrameworkCore;
using Wolverine.Persistence;

namespace mspdashboard.Host.Tests.Infrastructure;

public sealed class TestWolverineExtension : IWolverineExtension {
    public void Configure(WolverineOptions options) {
        // Serverless drops message persistence and still accepts the cascading
        // TenantCreatedEvent. MediatorOnly rejects that publish.
        options.Durability.Mode = DurabilityMode.Serverless;
        options.UseEntityFrameworkCoreTransactions(TransactionMiddlewareMode.Lightweight);
    }
}
