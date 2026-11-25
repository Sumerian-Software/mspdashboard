namespace mspdashboard.Identity.Features.Setup;

public sealed record SetupStatusResponse(bool SetupRequired);

public sealed record CompleteSetupRequest(string? CompanyName, string? Email, string? Password);
