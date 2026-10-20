using Qertum.Services.Recovery;

namespace Qertum.Tests.Recovery;

public sealed class RestoreUsabilityCheckerTests
{
    private static RestoreCheckResult Result(RestoreUsabilityReport report, string name) => report.Results.Single(r => r.Name == name);

    [Fact]
    public async Task AGoodRestore_PassesEveryCheck_AndExitsZero()
    {
        await using var host = await RestoreUsabilityHost.CreateAsync();

        var report = await host.RunAsync();

        Assert.Equal(["database", "key-ring", "signing", "revocation"], report.Results.Select(r => r.Name));
        Assert.All(report.Results, r => Assert.Equal(RestoreCheckOutcome.Pass, r.Outcome));
        Assert.Equal(0, report.ExitCode);
    }

    [Fact]
    public async Task ACaThatWasNeverOnboarded_PassesTheDatabase_AndExercisesNothingElse()
    {
        await using var host = await RestoreUsabilityHost.CreateAsync(withCa: false);

        var report = await host.RunAsync();

        Assert.Equal(RestoreCheckOutcome.Pass, Result(report, "database").Outcome);
        Assert.Equal(RestoreCheckOutcome.NotExercised, Result(report, "key-ring").Outcome);
        Assert.Equal(RestoreCheckOutcome.NotExercised, Result(report, "signing").Outcome);
        Assert.Equal(RestoreCheckOutcome.NotExercised, Result(report, "revocation").Outcome);
        Assert.Equal(0, report.ExitCode);
    }

    [Fact]
    public async Task AReplacedKeyRing_FailsTheKeyRingCheck_NotAPassFromANullRead()
    {
        // DecryptOrPassThrough returns null for a value it cannot decrypt, so the check must treat a null read of a
        // protected row as the failure, not rely on an exception.
        await using var host = await RestoreUsabilityHost.CreateAsync();
        await host.ReopenAsync(dir => Directory.Delete(Path.Combine(dir, "DataProtection-Keys"), recursive: true));

        var report = await host.RunAsync();

        var keyRing = Result(report, "key-ring");
        Assert.Equal(RestoreCheckOutcome.Fail, keyRing.Outcome);
        Assert.Contains("cannot be decrypted", keyRing.Detail);
        Assert.Equal(1, report.ExitCode);
    }

    [Fact]
    public async Task AMissingCaKey_FailsSigning_ForAnActiveOnlineIssuer()
    {
        await using var host = await RestoreUsabilityHost.CreateAsync();
        await host.ReopenAsync(dir =>
        {
            foreach (var key in Directory.GetFiles(dir, "ca.key", SearchOption.AllDirectories))
                File.Delete(key);
        });

        var report = await host.RunAsync();

        var signing = Result(report, "signing");
        Assert.Equal(RestoreCheckOutcome.Fail, signing.Outcome);
        Assert.DoesNotContain("could not complete", signing.Detail);
        Assert.Equal(1, report.ExitCode);
    }

    [Fact]
    public async Task ADatabaseAheadOfTheImage_IsNotTestable_NotAFailure()
    {
        await using var host = await RestoreUsabilityHost.CreateAsync();
        await host.ExecuteSqlAsync(
            "INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('99991231000000_FromTheFuture', '99.0.0')");

        var report = await host.RunAsync();

        var database = Result(report, "database");
        Assert.Equal(RestoreCheckOutcome.NotTestable, database.Outcome);
        Assert.Contains("ahead", database.Detail);
        Assert.Equal(RestoreCheckOutcome.NotExercised, Result(report, "signing").Outcome);
        Assert.Equal(2, report.ExitCode);
    }

    [Fact]
    public async Task ADatabaseBehindTheImage_IsNotTestable_AndSaysToUseTheImageThatWroteIt()
    {
        await using var host = await RestoreUsabilityHost.CreateAsync();
        await host.ExecuteSqlAsync("DELETE FROM \"__EFMigrationsHistory\"");

        var database = Result(await host.RunAsync(), "database");

        Assert.Equal(RestoreCheckOutcome.NotTestable, database.Outcome);
        Assert.Contains("not applied", database.Detail);
    }

    [Fact]
    public void ExitCode_FailBeatsNotTestable_WhichBeatsPass()
    {
        static RestoreCheckResult Make(RestoreCheckOutcome o) => new("x", o, "d");

        Assert.Equal(1, new RestoreUsabilityReport([Make(RestoreCheckOutcome.NotTestable), Make(RestoreCheckOutcome.Fail)]).ExitCode);
        Assert.Equal(2, new RestoreUsabilityReport([Make(RestoreCheckOutcome.Pass), Make(RestoreCheckOutcome.NotTestable)]).ExitCode);
        Assert.Equal(0, new RestoreUsabilityReport([Make(RestoreCheckOutcome.Pass), Make(RestoreCheckOutcome.NotExercised)]).ExitCode);
    }

    [Fact]
    public void ALine_HasNoSpacesInTheOutcome_AndTheNameFirst()
    {
        Assert.Equal("check key-ring not-exercised nothing stored", new RestoreCheckResult("key-ring", RestoreCheckOutcome.NotExercised, "nothing stored").Line);
    }
}
