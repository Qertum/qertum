using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcStageEvaluatorTests
{
    private static readonly CertificateKeyAlgorithm[] Classical =
        [CertificateKeyAlgorithm.Rsa, CertificateKeyAlgorithm.EcdsaP256, CertificateKeyAlgorithm.EcdsaP384];

    private static readonly CertificateKeyAlgorithm[] Compliant =
        [CertificateKeyAlgorithm.MlDsa65, CertificateKeyAlgorithm.SlhDsaSha2128s,
         CertificateKeyAlgorithm.SlhDsaSha2192f, CertificateKeyAlgorithm.SlhDsaSha2256s,
         CertificateKeyAlgorithm.HybridEcdsaP256, CertificateKeyAlgorithm.MlKem768,
         CertificateKeyAlgorithm.PairMlDsa65MlKem768];

    public static TheoryData<PqcStage> AllStages => new(Enum.GetValues<PqcStage>());

    [Theory]
    [MemberData(nameof(AllStages))]
    public void CompliantAlgorithms_AreAlwaysAllowed_WithNoEvent(PqcStage stage)
    {
        foreach (var algorithm in Compliant)
        {
            foreach (var renewal in new[] { false, true })
            {
                var verdict = PqcStageEvaluator.Evaluate(stage, algorithm, renewal);
                Assert.Equal(PqcOutcome.Allowed, verdict.Outcome);
                Assert.Null(verdict.EventAction);
                Assert.Null(verdict.Reason);
            }
        }
    }

    [Fact]
    public void Composite_IsCompliant() =>
        Assert.True(PqcStageEvaluator.IsCompliant(
            CertificateKeyAlgorithmExtensions.Parse("MLDSA65-ECDSA-P256-SHA512")!.Value));

    [Theory]
    [InlineData(PqcStage.Off, PqcOutcome.Allowed, null)]
    [InlineData(PqcStage.Observe, PqcOutcome.Allowed, PqcEventActions.Observed)]
    [InlineData(PqcStage.Warn, PqcOutcome.AllowedWithWarning, PqcEventActions.Warned)]
    [InlineData(PqcStage.Pilot, PqcOutcome.Refused, null)]
    [InlineData(PqcStage.Enforce, PqcOutcome.Refused, null)]
    public void ClassicalNewRequest_FollowsTheStageTable(PqcStage stage, PqcOutcome expected, string? action)
    {
        foreach (var algorithm in Classical)
        {
            var verdict = PqcStageEvaluator.Evaluate(stage, algorithm, isRenewal: false);
            Assert.Equal(expected, verdict.Outcome);
            Assert.Equal(action, verdict.EventAction);
            Assert.Equal(stage, verdict.Stage);
            if (expected != PqcOutcome.Allowed || action is not null)
                Assert.False(string.IsNullOrWhiteSpace(verdict.Reason));
        }
    }

    [Theory]
    [InlineData(PqcStage.Off, PqcOutcome.Allowed)]
    [InlineData(PqcStage.Observe, PqcOutcome.Allowed)]
    [InlineData(PqcStage.Warn, PqcOutcome.AllowedWithWarning)]
    [InlineData(PqcStage.Pilot, PqcOutcome.AllowedWithWarning)]
    [InlineData(PqcStage.Enforce, PqcOutcome.Refused)]
    public void ClassicalRenewal_IsOnlyRefusedAtEnforce(PqcStage stage, PqcOutcome expected) =>
        Assert.Equal(expected, PqcStageEvaluator.Evaluate(stage, CertificateKeyAlgorithm.Rsa, isRenewal: true).Outcome);

    [Theory]
    [InlineData(PqcStage.Pilot)]
    [InlineData(PqcStage.Enforce)]
    public void AnException_TurnsARefusalIntoAWarning_AndNamesItself(PqcStage stage)
    {
        var verdict = PqcStageEvaluator.Evaluate(stage, CertificateKeyAlgorithm.Rsa, isRenewal: false,
            exceptionReference: "exception 3f2c");

        Assert.Equal(PqcOutcome.AllowedWithWarning, verdict.Outcome);
        Assert.Equal(PqcEventActions.ExceptionApplied, verdict.EventAction);
        Assert.Contains("exception 3f2c", verdict.Reason);
    }

    [Theory]
    [InlineData(PqcStage.Off)]
    [InlineData(PqcStage.Observe)]
    [InlineData(PqcStage.Warn)]
    public void AnException_DoesNotChangeStagesThatAlreadyAllow(PqcStage stage)
    {
        var without = PqcStageEvaluator.Evaluate(stage, CertificateKeyAlgorithm.Rsa, false);
        var with = PqcStageEvaluator.Evaluate(stage, CertificateKeyAlgorithm.Rsa, false, "exception x");

        Assert.Equal(without, with);
    }

    [Fact]
    public void EnforceRefusalKeepsTheHistoricalMessagePrefix() =>
        Assert.StartsWith("PQC enforce stage refuses classical keys; 'RSA' is a classical RSA or ECDSA algorithm",
            PqcStageEvaluator.Evaluate(PqcStage.Enforce, CertificateKeyAlgorithm.Rsa, false).Reason);
}
