using Qertum.Services;

namespace Qertum.Web.Components.Pages;

/// <summary>Wording for the PQC enforcement stages: what each one refuses, allows and records.</summary>
public static class PqcStageGuidance
{
    /// <summary>One sentence stating the consequence of <paramref name="stage"/>.</summary>
    public static string Sentence(PqcStage stage) => stage switch
    {
        PqcStage.Off =>
            "Classical RSA and ECDSA keys are accepted without comment, and nothing is recorded.",
        PqcStage.Observe =>
            "Classical keys are still accepted. Each one is recorded as a diagnostic event so you can see who would be affected; requesters are not told.",
        PqcStage.Warn =>
            "Classical keys are still accepted and recorded. Requesters are warned where the protocol has a channel (this web app, the CLI and the REST API); ACME and EST clients see nothing.",
        PqcStage.Pilot =>
            "New requests with a classical key are refused. Renewals of existing classical certificates are still allowed, with a warning.",
        PqcStage.Enforce =>
            "Every request, renewal, approval and CA import with a classical key is refused. There is no grace period and no per-request override; only an administrator-granted, time-limited exception admits a classical key.",
        _ => throw new ArgumentOutOfRangeException(nameof(stage), stage, null)
    };

    /// <summary>True when a brand new request with a classical key would be refused.</summary>
    public static bool RefusesNewClassical(PqcStage stage) => stage is PqcStage.Pilot or PqcStage.Enforce;

    /// <summary>True when a requester is warned (where the protocol allows) about a classical key.</summary>
    public static bool WarnsRequester(PqcStage stage) => stage is PqcStage.Warn or PqcStage.Pilot;
}
