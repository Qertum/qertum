using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>
/// What a requester needs to choose how to enroll: purposes, template summaries and the enrollment
/// facts that decide which custody routes apply. An explicit allowlist — adding a field is a reviewed
/// change pinned by a test, never a projection of <see cref="CaSettings"/>.
/// </summary>
public sealed class EnrollmentOptionsResponse
{
    /// <summary>Purposes that have at least one template, in <see cref="EnrollmentPurpose"/> order.</summary>
    public IReadOnlyList<EnrollmentPurposeOption> Purposes { get; init; } = [];

    /// <summary>Every template a requester can file under, ordered by name.</summary>
    public IReadOnlyList<EnrollmentTemplateSummary> Templates { get; init; } = [];

    /// <summary>The CA-wide default PQC stage; templates may override it (see each template's <c>PqcStage</c>).</summary>
    public PqcStage PqcStage { get; init; } = PqcStage.Enforce;

    /// <summary>The ACME route, or null when no public directory URL is configured.</summary>
    public AcmeEnrollmentRoute? Acme { get; init; }

    /// <summary>The EST route, or null when no public EST base URL is configured.</summary>
    public EstEnrollmentRoute? Est { get; init; }
}

/// <summary>One purpose and the templates that serve it.</summary>
public sealed class EnrollmentPurposeOption
{
    /// <summary>The task the requester wants to accomplish.</summary>
    public EnrollmentPurpose Purpose { get; init; }

    /// <summary>Type keys of the templates classified under this purpose.</summary>
    public IReadOnlyList<string> TemplateTypeKeys { get; init; } = [];
}

/// <summary>The parts of a certificate template the enrollment wizard shows.</summary>
public sealed class EnrollmentTemplateSummary
{
    /// <summary>Machine key stored on the request's <c>Type</c>.</summary>
    public string TypeKey { get; init; } = "";

    /// <summary>Display name.</summary>
    public string Name { get; init; } = "";

    /// <summary>Optional description of what the template is for.</summary>
    public string? Description { get; init; }

    /// <summary>SAN kinds the template accepts: <c>dns</c>, <c>ip</c>, <c>email</c>, <c>upn</c>.</summary>
    public IReadOnlyList<string> SanTypes { get; init; } = [];

    /// <summary>Validity a request gets when it asks for none, as the generator computes it.</summary>
    public int DefaultValidityDays { get; init; }

    /// <summary>Purposes this template serves.</summary>
    public IReadOnlyList<EnrollmentPurpose> Purposes { get; init; } = [];

    /// <summary>The stage that governs this template: its override, else the CA default.</summary>
    public PqcStage PqcStage { get; init; } = PqcStage.Enforce;
}

/// <summary>ACME enrollment facts; the client keeps its own key.</summary>
public sealed class AcmeEnrollmentRoute
{
    /// <summary>Template ACME requests are filed under.</summary>
    public string TemplateTypeKey { get; init; } = "";

    /// <summary>Public ACME directory URL for display.</summary>
    public string DirectoryUrl { get; init; } = "";

    /// <summary>Whether new accounts must present external account binding.</summary>
    public bool ExternalAccountBindingRequired { get; init; }

    /// <summary>Whether finalized orders are approved without an approver.</summary>
    public bool AutoApprove { get; init; }
}

/// <summary>EST enrollment facts; the device keeps its own key.</summary>
public sealed class EstEnrollmentRoute
{
    /// <summary>Template EST requests are filed under.</summary>
    public string TemplateTypeKey { get; init; } = "";

    /// <summary>Public EST base URL (<c>…/.well-known/est</c>) for display.</summary>
    public string BaseUrl { get; init; } = "";

    /// <summary>Whether enrollments are approved without an approver.</summary>
    public bool AutoApprove { get; init; }
}

/// <summary>Task-level reason a requester wants a certificate.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EnrollmentPurpose
{
    /// <summary>TLS server certificate.</summary>
    WebServer,
    /// <summary>Client or device authentication.</summary>
    ClientAuthentication,
    /// <summary>S/MIME email protection.</summary>
    Email,
    /// <summary>Software and script signing.</summary>
    CodeSigning,
    /// <summary>Subordinate certificate authority.</summary>
    SubordinateCa,
    /// <summary>No recognized purpose.</summary>
    Other
}
