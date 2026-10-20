using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

internal sealed partial class PolicyTestDb
{
    /// <summary>A request service wired to the real policy service over this database, auditing into <see cref="Audit"/>.</summary>
    public CertificateRequestService CreateRequestService() =>
        new(Db, Audit, new NullPolicyWebhookService(), new IssuancePolicyService(Db, new IssuancePolicyEvaluator()));

    /// <summary>A preview service over the same database, so preview and create see identical state.</summary>
    public CertificateRequestPreviewService CreatePreviewService() =>
        new(Db, new IssuancePolicyService(Db, new IssuancePolicyEvaluator()), Audit, new PqcStageService(Db));

    /// <summary>An enrollment options service over this database, with no ACME or EST display URLs.</summary>
    public Qertum.Services.Enrollment.EnrollmentOptionsService CreateEnrollmentOptionsService() =>
        new(Db, new Qertum.Services.Enrollment.EnrollmentDisplayUrls(
            Microsoft.Extensions.Options.Options.Create(new Qertum.Services.Enrollment.EnrollmentOptions()),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<Qertum.Services.Enrollment.EnrollmentDisplayUrls>.Instance));
}
