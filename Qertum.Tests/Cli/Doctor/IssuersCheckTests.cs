using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class IssuersCheckTests
{
    private const string Status = "https://ca.test/v1/ca/status";
    private const string List = "https://ca.test/v1/issuers";

    private static string Issuer(string name, string status = "Active", bool isDefault = false, string kind = "Root", DateTime? validTo = null) =>
        $$"""
        {"id":"{{Guid.NewGuid()}}","name":"{{name}}","kind":"{{kind}}","parentIssuerId":null,"keyCustody":"Online","status":"{{status}}","isDefault":{{(isDefault ? "true" : "false")}},
         "subjectDn":"CN={{name}}","serialNumber":"01","keyAlgorithm":"ECDSA-P384","validFrom":"2026-01-01T00:00:00Z","validTo":"{{(validTo ?? DoctorTestSupport.Now.UtcDateTime.AddYears(5)):yyyy-MM-ddTHH:mm:ssZ}}",
         "pathLengthConstraint":null,"permittedDnsSuffixes":[],"excludedDnsSuffixes":[],"permittedIpRanges":[],"excludedIpRanges":[],"uploadedCrlNumber":null,"uploadedCrlNextUpdateUtc":null,
         "createdAtUtc":"2026-01-01T00:00:00Z","activatedAtUtc":null,"retiredAtUtc":null,"archivedAtUtc":null,"destroyedAtUtc":null}
        """;

    private static FakeHttp Healthy(params string[] issuers) => new FakeHttp()
        .Route(Status, HttpStatusCode.OK, """{"isInitialized":true,"subjectDn":"CN=Root","algorithm":"ECDSA-P384","explicitCurveParameters":false}""")
        .Route(List, HttpStatusCode.OK, "[" + string.Join(",", issuers.Length == 0 ? [Issuer("Root", isDefault: true)] : issuers) + "]");

    private static (Task<DoctorResult> Result, DoctorContext Context) Run(FakeHttp http, bool sessionAccepted = true)
    {
        var context = DoctorTestSupport.Context(http);
        context.Shared.SessionAccepted = sessionAccepted;
        return (new IssuersCheck().RunAsync(context, TestContext.Current.CancellationToken), context);
    }

    [Fact]
    public async Task AnInitializedCaWithADefaultIssuer_Passes_AndSharesTheIssuers()
    {
        var (task, context) = Run(Healthy());
        var result = await task;

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.Verified, v => v.Contains("initialized", StringComparison.Ordinal));
        Assert.Contains(result.Verified, v => v.Contains("default issuer", StringComparison.Ordinal));
        Assert.Single(context.Shared.Issuers!);
        Assert.All(Seen(context), s => Assert.Equal("Bearer tok", s.Authorization));
    }

    private static IReadOnlyList<SeenRequest> Seen(DoctorContext context) => ((FakeHttp)context.Handler).Seen;

    [Fact]
    public async Task AnUninitializedCa_Fails()
    {
        var http = new FakeHttp().Route(Status, HttpStatusCode.OK, """{"isInitialized":false}""");

        var (task, _) = Run(http);
        var result = await task;

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("not initialized", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExplicitCurveParameters_Warn()
    {
        var http = Healthy().Route(Status, HttpStatusCode.OK, """{"isInitialized":true,"explicitCurveParameters":true}""");

        var (task, _) = Run(http);
        var result = await task;

        Assert.Equal(DoctorStatus.Warn, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("explicit", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnIssuerEndingWithin90Days_Warns_AnEndedOneFails()
    {
        var soon = Healthy(Issuer("Root", isDefault: true), Issuer("Issuing", kind: "Intermediate", validTo: DoctorTestSupport.Now.UtcDateTime.AddDays(80)));
        var ended = Healthy(Issuer("Root", isDefault: true), Issuer("Old", kind: "Intermediate", validTo: DoctorTestSupport.Now.UtcDateTime.AddDays(-1)));

        var (soonTask, _) = Run(soon);
        var (endedTask, _) = Run(ended);
        var warned = await soonTask;
        var failed = await endedTask;

        Assert.Equal(DoctorStatus.Warn, warned.Status);
        Assert.Contains(warned.Findings, f => f.Contains("Issuing", StringComparison.Ordinal));
        Assert.Equal(DoctorStatus.Fail, failed.Status);
        Assert.Contains(failed.Findings, f => f.Contains("Old", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ARetiredOrArchivedIssuerThatEnded_IsNotAProblem()
    {
        var http = Healthy(Issuer("Root", isDefault: true), Issuer("Gone", status: "Archived", kind: "Intermediate", validTo: DoctorTestSupport.Now.UtcDateTime.AddDays(-400)));

        var (task, _) = Run(http);

        Assert.Equal(DoctorStatus.Pass, (await task).Status);
    }

    [Fact]
    public async Task NoDefaultIssuer_Fails()
    {
        var (task, _) = Run(Healthy(Issuer("Root")));
        var result = await task;

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("no default issuer", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutCertificatesView_TheIssuerListIsNotVerified_NotAFailure()
    {
        var http = new FakeHttp()
            .Route(Status, HttpStatusCode.OK, """{"isInitialized":true,"algorithm":"ECDSA-P384"}""")
            .Route(List, HttpStatusCode.Forbidden);

        var (task, context) = Run(http);
        var result = await task;

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("certificates.view", StringComparison.Ordinal));
        Assert.Null(context.Shared.Issuers);
    }

    [Fact]
    public async Task NoSession_IsSkipped()
    {
        var http = new FakeHttp();

        var (task, _) = Run(http, sessionAccepted: false);
        var result = await task;

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Empty(http.Seen);
    }

    [Fact]
    public async Task ARejectedStatusCall_Fails()
    {
        var (task, _) = Run(new FakeHttp().Route(Status, HttpStatusCode.Unauthorized));

        Assert.Equal(DoctorStatus.Fail, (await task).Status);
    }
}
