namespace mspdashboard.Identity.Infrastructure;

public sealed class SetupOptions {
    public const string SectionName = "Setup";

    // Production defaults to false. Enable with Setup:AllowFirstRun or the
    // Setup__AllowFirstRun environment variable for first-time self-host
    // setup, then turn it off.
    public bool AllowFirstRun { get; set; } = false;
}
