using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Pqc;

internal static class PqcReportTestKit
{
    public static readonly DateTime Now = new(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);

    public static FakeTimeProvider Clock() => new(new DateTimeOffset(Now));

    public static PqcMigrationReportService Service(CertificateRequestDbContext db, TimeProvider? clock = null, int retentionDays = 30) =>
        new(db, new PqcStageService(db, null, clock), new CertificateInventoryService(db),
            Options.Create(new LifecycleEventsOptions { DiagnosticRetentionDays = retentionDays }), clock);

    public static readonly PqcReportAccess ViewOnly = new(CanViewObserved: false);
    public static readonly PqcReportAccess WithObserved = new(CanViewObserved: true);

    /// <summary>A request row as the report reads it. Issued rows get a validity; the PEM is left empty (facts stay Unknown).</summary>
    public static CertificateRequest Row(string cn, CertificateKeyAlgorithm? algorithm, CertificateRequestStatus status,
        DateTime? validTo = null, string type = "WebServer", string? subject = null, CertificateRequestId? renewedFrom = null,
        string? propertiesJson = null) => new()
    {
        CommonName = cn, RequestedBy = "seed", RequestedBySubject = subject, Type = type, Status = status,
        KeyAlgorithm = algorithm, ValidTo = validTo, RenewedFromId = renewedFrom,
        PropertiesJson = propertiesJson ?? "{}",
        CertificatePem = status is CertificateRequestStatus.Issued or CertificateRequestStatus.Revoked
            or CertificateRequestStatus.PendingRevocation ? "" : null
    };
}
