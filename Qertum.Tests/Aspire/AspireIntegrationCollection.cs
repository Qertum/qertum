namespace Qertum.Tests.Aspire;

/// <summary>
/// Shared collection that boots the Aspire stack exactly once and shares the
/// <see cref="AspireIntegrationFixture"/> across all integration test classes.
/// Without this, xUnit creates a new fixture per class, starting the full stack
/// (identityservice + apiservice + webfrontend) once per test class.
/// </summary>
[CollectionDefinition("AspireIntegration")]
public sealed class AspireIntegrationCollection : ICollectionFixture<AspireIntegrationFixture> { }
