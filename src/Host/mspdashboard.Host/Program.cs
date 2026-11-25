using JasperFx;
using JasperFx.CodeGeneration.Model;
using Microsoft.EntityFrameworkCore;
using mspdashboard.Core.Data;
using mspdashboard.Core.Infrastructure;
using mspdashboard.Host.Authentication;
using mspdashboard.Host.Infrastructure;
using mspdashboard.Host.Middleware;
using mspdashboard.Host.Services;
using mspdashboard.Identity.Features.Tenants;
using mspdashboard.Identity.Infrastructure;
using Wolverine;
using Wolverine.EntityFrameworkCore;
using Wolverine.Http;
using Wolverine.Postgresql;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.AddDashboardSwagger();
builder.Services.AddDashboardIdentity();
builder.AddDashboardAuthentication();
builder.Services.AddScoped<IExternalLoginService, ExternalLoginService>();
builder.Services.AddWolverineHttp();
builder.Services.AddRazorPages();

builder.Services.AddCors(options => {
    options.AddDefaultPolicy(policy => {
        policy.WithOrigins(
                "https://*.mspdashboard.io",
                "https://portal.mspdashboard.io",
                "http://localhost:8080",
                "http://localhost:5080",
                "http://localhost:5090",
                "http://localhost:5000",
                "https://localhost:5001")
            .SetIsOriginAllowedToAllowWildcardSubdomains()
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

builder.Services.AddCoreInfrastructure(builder.Configuration);

var postgres = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Host.UseWolverine(opts => {
    opts.Discovery.IncludeAssembly(typeof(Program).Assembly);
    opts.Discovery.IncludeAssembly(typeof(CreateTenantHandler).Assembly);
    // ASP.NET Identity managers resolve IServiceProvider internally.
    opts.ServiceLocationPolicy = ServiceLocationPolicy.AlwaysAllowed;

    opts.Policies.UseDurableLocalQueues();
    opts.Policies.UseDurableOutboxOnAllSendingEndpoints();
    opts.Policies.AutoApplyTransactions();
    opts.UseEntityFrameworkCoreTransactions();

    if (string.IsNullOrWhiteSpace(postgres)) {
        return;
    }

    // Self-host boots in Production against an empty database.
    // Wolverine owns this schema. EF migrations do not create it.
    opts.AutoBuildMessageStorageOnStartup = AutoCreate.CreateOrUpdate;

    opts.PersistMessagesWithPostgresql(postgres, "wolverine")
        .EnableMessageTransport(transport => {
            transport.TransportSchemaName("wolverine_queues");
            transport.EnableDeterministicQueueOrdering();
        });

    opts.PublishMessage<TenantCreatedEvent>()
        .ToPostgresqlQueue("tenant-created");

    opts.ListenToPostgresqlQueue("tenant-created")
        .Sequential()
        .UseDurableInbox();
});

var app = builder.Build();

if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

try {
    await using var scope = app.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    if (db.Database.IsRelational() &&
        db.Database.ProviderName?.Contains("Npgsql", StringComparison.Ordinal) == true) {
        await db.Database.MigrateAsync();
    } else if ((app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing")) &&
               db.Database.IsRelational() &&
               db.Database.ProviderName?.Contains("Sqlite", StringComparison.Ordinal) == true) {
        db.Database.EnsureCreated();
    }

    if (app.Environment.IsDevelopment() && app.Configuration.GetValue("SeedDemoData", true)) {
        await DevDataSeeder.SeedAsync(app.Services, app.Logger);
    }
} catch (Exception ex) when (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing")) {
    app.Logger.LogWarning(ex, "Database migration or seed skipped.");
}

app.UseHttpsRedirection();
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.UseCors();
app.UseMiddleware<TenantResolutionMiddleware>();
app.UseAuthentication();
app.UseMiddleware<ClaimTenantResolutionMiddleware>();
app.UseAuthorization();

app.MapWolverineEndpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program {
}
