namespace mspdashboard.Identity.Infrastructure;

public sealed class SetupOptions {
    public const string SectionName = "Setup";

    // True on self-host so the first visitor can create the organization.
    // Hosted operators set false before the instance is reachable.
    public bool AllowFirstRun { get; set; } = true;
}
