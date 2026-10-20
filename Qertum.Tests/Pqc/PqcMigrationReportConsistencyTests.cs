using Qertum.Services;
using Qertum.Tests.Policies;
using static Qertum.Tests.Pqc.PqcReportTestKit;

namespace Qertum.Tests.Pqc;

/// <summary>
/// The invariant that keeps a preview honest: for every stage, each item's verdict equals what the real
/// action does once that stage is in force. A live certificate is judged as a renewal, a Pending request
/// as approval, an Approved request as the queue consumer's pre-signing check.
/// </summary>
public sealed class PqcMigrationReportConsistencyTests
{
    public static TheoryData<PqcStage> Stages => new(Enum.GetValues<PqcStage>());

    [Theory]
    [MemberData(nameof(Stages))]
    public async Task EveryItem_MatchesWhatTheRealActionDoesUnderTheSameStage(PqcStage stage)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);   // stored default stage is Off
        var now = TimeProvider.System.GetUtcNow().UtcDateTime;
        scope.Db.CertificateRequests.AddRange(
            Row("rsa.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Issued, now.AddDays(30)),
            Row("ecdsa.corp.example", CertificateKeyAlgorithm.EcdsaP256, CertificateRequestStatus.Issued, now.AddDays(30)),
            Row("covered.corp.example", CertificateKeyAlgorithm.EcdsaP384, CertificateRequestStatus.Issued, now.AddDays(30)),
            Row("pqc.corp.example", CertificateKeyAlgorithm.MlDsa65, CertificateRequestStatus.Issued, now.AddDays(30)),
            Row("pair.corp.example", CertificateKeyAlgorithm.PairMlDsa65MlKem768, CertificateRequestStatus.Issued, now.AddDays(30)),
            Row("pending.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending),
            Row("approved.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Approved));
        scope.Db.PqcExceptions.Add(new PqcException
        {
            TemplateTypeKey = "WebServer", NamePattern = "covered.corp.example", Family = PqcExceptionFamily.Ecdsa,
            ExpiresAtUtc = now.AddDays(30), Reason = "legacy", GrantedBy = "admin", CreatedAtUtc = now
        });
        await scope.Db.SaveChangesAsync(ct);

        // The proposal, judged while the stored stage is still Off ...
        var report = await new PqcMigrationReportService(scope.Db, new PqcStageService(scope.Db), new CertificateInventoryService(scope.Db),
                Microsoft.Extensions.Options.Options.Create(new Qertum.Services.Lifecycle.LifecycleEventsOptions()))
            .BuildAsync(new PqcReportQuery { ProposedStage = stage, PageSize = 500 }, ViewOnly, ct);
        Assert.Equal(5, report.Items.TotalCount);   // the ML-DSA certificate and the pair are compliant and not listed

        // ... then make it real and act.
        await TestServices.SetStageAsync(scope.Db, stage);
        var requests = scope.CreateRequestService();

        foreach (var item in report.Items.Items)
        {
            if (!item.InFlight)
            {
                bool refused;
                IReadOnlyList<string>? warnings = null;
                try { warnings = (await requests.RenewAsync(item.RequestId, "consistency", ct))!.Warnings; refused = false; }
                catch (PqcPolicyViolationException) { refused = true; }

                Assert.Equal(item.Verdict == PqcVerdictKind.Refused, refused);
                if (!refused)
                    Assert.Equal(item.Verdict is PqcVerdictKind.Warned or PqcVerdictKind.CoveredByException, warnings is { Count: > 0 });
                if (item.Verdict == PqcVerdictKind.CoveredByException)
                    Assert.Contains(item.ExceptionId!.ToString()!, warnings![0]);
            }
            else if (item.Status == CertificateRequestStatus.Pending)
            {
                var refused = false;
                try { await requests.MarkAsApprovedAsync(item.RequestId, "consistency", ct); }
                catch (PqcPolicyViolationException) { refused = true; }

                Assert.Equal(item.Verdict == PqcVerdictKind.Refused, refused);
            }
            else
            {
                var decision = await requests.CheckIssuancePolicyAsync(item.RequestId, ct);

                Assert.Equal(item.Verdict != PqcVerdictKind.Refused, decision.Allowed);
            }
        }
    }
}
