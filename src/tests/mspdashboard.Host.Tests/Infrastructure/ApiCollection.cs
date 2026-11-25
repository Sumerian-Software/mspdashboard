namespace mspdashboard.Host.Tests.Infrastructure;

[CollectionDefinition(Name)]
public sealed class ApiCollection : ICollectionFixture<ApiFactory> {
    public const string Name = "api";
}
