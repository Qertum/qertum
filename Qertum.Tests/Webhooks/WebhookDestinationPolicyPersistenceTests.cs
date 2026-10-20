using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookDestinationPolicyPersistenceTests
{
    [Fact]
    public async Task NewDatabaseHasNoInitializedPolicy()
    {
        await using var database = await PolicyDatabase.CreateAsync();
        await using var db = database.OpenContext();
        var service = new WebhookDestinationPolicyService(db);

        var policy = await service.GetEffectiveAsync(TestContext.Current.CancellationToken);

        Assert.False(policy.Initialized);
        Assert.Empty(policy.Rules);
    }

    [Fact]
    public async Task ReconciliationInitializesPublicDefaultsAndConfigurationRules()
    {
        await using var database = await PolicyDatabase.CreateAsync();
        var options = Options(InternalRule("internal.invalid", "10.0.0.7"));
        await ReconcileAsync(database, options);

        await using var other = database.OpenContext();
        var policy = await new WebhookDestinationPolicyService(other)
            .GetEffectiveAsync(TestContext.Current.CancellationToken);

        Assert.True(policy.Initialized);
        Assert.Equal(WebhookPublicMode.AnyPublic, policy.PublicMode);
        var rule = Assert.Single(policy.Rules);
        Assert.Equal("Configuration", rule.Source);
        Assert.Equal("internal.invalid", rule.Host);
        Assert.Equal("10.0.0.7", Assert.Single(rule.AllowedIpAddresses).ToString());
        Assert.True(rule.Enabled);
    }

    [Fact]
    public async Task AdminDisabledConfigurationRuleStaysDisabledAfterRestart()
    {
        await using var database = await PolicyDatabase.CreateAsync();
        var options = Options(InternalRule("internal.invalid", "10.0.0.7"));
        await ReconcileAsync(database, options);
        await using (var db = database.OpenContext())
        {
            var row = await db.WebhookDestinationRules.SingleAsync(TestContext.Current.CancellationToken);
            row.AdminDisabled = true;
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await ReconcileAsync(database, options);

        await using var other = database.OpenContext();
        var policy = await new WebhookDestinationPolicyService(other)
            .GetEffectiveAsync(TestContext.Current.CancellationToken);
        Assert.False(Assert.Single(policy.Rules).Enabled);
    }

    [Fact]
    public async Task RemovedJsonRuleLosesEffectWhileAdminRuleSurvives()
    {
        await using var database = await PolicyDatabase.CreateAsync();
        await ReconcileAsync(database, Options(InternalRule("old.invalid", "10.0.0.7")));
        await using (var db = database.OpenContext())
        {
            db.WebhookDestinationRules.Add(new WebhookDestinationRule
            {
                Id = Guid.NewGuid(), Source = "Admin", StableKey = "admin-new", Kind = WebhookDestinationRuleKind.Internal,
                Scheme = "https", Host = "new.invalid", Port = 443, AllowedIpAddressesJson = "[\"10.0.0.8\"]",
                IsPresent = true, Enabled = true
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await ReconcileAsync(database, Options());

        await using var other = database.OpenContext();
        var policy = await new WebhookDestinationPolicyService(other)
            .GetEffectiveAsync(TestContext.Current.CancellationToken);
        var rule = Assert.Single(policy.Rules);
        Assert.Equal("new.invalid", rule.Host);
        Assert.True(rule.Enabled);
    }

    [Fact]
    public async Task ConfigurationHostnameIsNormalizedAsIdn()
    {
        await using var database = await PolicyDatabase.CreateAsync();
        await ReconcileAsync(database, Options(InternalRule("bücher.example", "10.0.0.7")));

        await using var other = database.OpenContext();
        var policy = await new WebhookDestinationPolicyService(other)
            .GetEffectiveAsync(TestContext.Current.CancellationToken);
        Assert.Equal("xn--bcher-kva.example", Assert.Single(policy.Rules).Host);
    }

    [Theory]
    [InlineData("WebhookDestinationPolicy:Rules:0:Host", "*.invalid")]
    [InlineData("WebhookDestinationPolicy:Rules:0:AllowedIpAddresses:0", "169.254.169.254")]
    [InlineData("WebhookDestinationPolicy:Rules:0:AllowedIpAddresses:0", "8.8.8.8")]
    [InlineData("WebhookDestinationPolicy:Rules:0:Port", "0")]
    public void InvalidConfiguredRuleFailsOptionsValidation(string key, string value)
    {
        var values = ValidRuleConfiguration();
        values[key] = value;
        AssertInvalidOptions(values);
    }

    [Fact]
    public void DuplicateConfiguredRuleFailsOptionsValidation()
    {
        var values = ValidRuleConfiguration();
        foreach (var (key, value) in ValidRuleConfiguration())
            if (key.Contains(":Rules:0:", StringComparison.Ordinal))
                values[key.Replace(":Rules:0:", ":Rules:1:", StringComparison.Ordinal)] = value;
        AssertInvalidOptions(values);
    }

    private static Dictionary<string, string?> ValidRuleConfiguration() => new()
    {
        ["WebhookDestinationPolicy:PublicMode"] = "AnyPublic",
        ["WebhookDestinationPolicy:Rules:0:Kind"] = "Internal",
        ["WebhookDestinationPolicy:Rules:0:Scheme"] = "https",
        ["WebhookDestinationPolicy:Rules:0:Host"] = "internal.invalid",
        ["WebhookDestinationPolicy:Rules:0:Port"] = "443",
        ["WebhookDestinationPolicy:Rules:0:AllowedIpAddresses:0"] = "10.0.0.7"
    };

    private static void AssertInvalidOptions(Dictionary<string, string?> values)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        services.AddWebhookDestinationPolicyOptions();
        using var provider = services.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<WebhookDestinationPolicyOptions>>().Value);
    }

    private static WebhookDestinationPolicyOptions Options(params WebhookDestinationRuleOption[] rules)
        => new() { PublicMode = WebhookPublicMode.AnyPublic, Rules = rules };

    private static WebhookDestinationRuleOption InternalRule(string host, params string[] ips)
        => new()
        {
            Kind = WebhookDestinationRuleKind.Internal,
            Scheme = "https",
            Host = host,
            Port = 443,
            AllowedIpAddresses = ips
        };

    private static async Task ReconcileAsync(PolicyDatabase database, WebhookDestinationPolicyOptions options)
    {
        await using var db = database.OpenContext();
        await new WebhookDestinationPolicyService(db).ReconcileAsync(options, TestContext.Current.CancellationToken);
    }

    private sealed class PolicyDatabase(SqliteConnection anchor, string connectionString, IDataProtectionProvider protection)
        : IAsyncDisposable
    {
        public static async Task<PolicyDatabase> CreateAsync()
        {
            var connectionString = $"Data Source=file:destination_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
            var anchor = new SqliteConnection(connectionString);
            await anchor.OpenAsync();
            var database = new PolicyDatabase(anchor, connectionString, new EphemeralDataProtectionProvider());
            await using var db = database.OpenContext();
            await db.Database.EnsureCreatedAsync();
            return database;
        }

        public CertificateRequestDbContext OpenContext() => new(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connectionString).Options, protection);

        public async ValueTask DisposeAsync() => await anchor.DisposeAsync();
    }
}
