using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class DoctorRunnerTests
{
    private sealed class Stub(string id, Func<DoctorResult> result) : IDoctorCheck
    {
        public string Id => id;
        public Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct) => Task.FromResult(result());
    }

    private static DoctorContext Context() => DoctorTestSupport.Context(new FakeHttp());

    [Fact]
    public async Task ChecksRunInOrder_AndTheirResultsAreKept()
    {
        var order = new List<string>();
        var checks = new[]
        {
            new Stub("a", () => { order.Add("a"); return DoctorResult.Of("a", DoctorStatus.Pass, "ok"); }),
            new Stub("b", () => { order.Add("b"); return DoctorResult.Skip("b", "because"); })
        };

        var report = await DoctorRunner.RunAsync(checks, Context(), TestContext.Current.CancellationToken);

        Assert.Equal(["a", "b"], order);
        Assert.Equal(["a", "b"], report.Results.Select(r => r.Id));
    }

    [Fact]
    public async Task AnExceptionInACheck_BecomesAFail_AndTheRunContinues()
    {
        var checks = new IDoctorCheck[]
        {
            new Stub("boom", () => throw new InvalidOperationException("secret details")),
            new Stub("after", () => DoctorResult.Of("after", DoctorStatus.Pass, "ok"))
        };

        var report = await DoctorRunner.RunAsync(checks, Context(), TestContext.Current.CancellationToken);

        var boom = report.Results[0];
        Assert.Equal(DoctorStatus.Fail, boom.Status);
        Assert.Contains("InvalidOperationException", boom.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("secret details", boom.Summary, StringComparison.Ordinal);
        Assert.Equal(DoctorStatus.Pass, report.Results[1].Status);
    }

    [Fact]
    public async Task ACancelledRun_StillCancels()
    {
        using var cts = new CancellationTokenSource();
        var checks = new IDoctorCheck[] { new Stub("a", () => { cts.Cancel(); throw new OperationCanceledException(cts.Token); }) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DoctorRunner.RunAsync(checks, Context(), cts.Token));
    }

    [Theory]
    [InlineData("Pass,Skipped", 0)]
    [InlineData("Pass,Warn", 2)]
    [InlineData("Warn,Fail", 1)]
    [InlineData("Skipped,Skipped", 0)]
    public void TheExitCode_IsOneForAFailure_TwoForWarnings_ElseZero(string statuses, int expected)
    {
        var report = new DoctorReport(statuses.Split(',').Select((s, i) => DoctorResult.Of($"c{i}", Enum.Parse<DoctorStatus>(s), "x")).ToList());

        Assert.Equal(expected, report.ExitCode);
    }

    [Fact]
    public void TheCounts_AddUp()
    {
        var report = new DoctorReport(
        [
            DoctorResult.Of("a", DoctorStatus.Pass, "x"), DoctorResult.Of("b", DoctorStatus.Pass, "x"),
            DoctorResult.Of("c", DoctorStatus.Warn, "x"), DoctorResult.Of("d", DoctorStatus.Fail, "x"), DoctorResult.Skip("e", "r")
        ]);

        Assert.Equal((2, 1, 1, 1), (report.Passed, report.Warnings, report.Failed, report.Skipped));
    }

    [Fact]
    public void ASkippedResult_AlwaysCarriesItsReason() =>
        Assert.Equal("needs a login", DoctorResult.Skip("x", "needs a login").Reason);
}
