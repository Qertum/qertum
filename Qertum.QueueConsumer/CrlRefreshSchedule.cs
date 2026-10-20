using System.Globalization;
using Qertum.Services;

namespace Qertum.QueueConsumer;

/// <summary>When a full-CRL refresh is due: the base is missing or older than a fraction of its validity.</summary>
internal static class CrlRefreshSchedule
{
    public static TimeSpan Threshold(int crlValidityHours, double fraction) =>
        TimeSpan.FromHours(CrlPublisher.EffectiveValidityHours(crlValidityHours) * fraction);

    public static bool IsDue(DateTime? baseThisUpdateUtc, int crlValidityHours, double fraction, DateTime nowUtc) =>
        baseThisUpdateUtc is not DateTime published || nowUtc - published >= Threshold(crlValidityHours, fraction);

    public static string Describe(DateTime? baseThisUpdateUtc, int crlValidityHours, double fraction, DateTime nowUtc) =>
        baseThisUpdateUtc is not DateTime published
            ? "no base CRL published yet"
            : string.Create(CultureInfo.InvariantCulture,
                $"base age {(nowUtc - published).TotalHours:0.0} h >= {Threshold(crlValidityHours, fraction).TotalHours:0.0} h");
}
