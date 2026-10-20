namespace Qertum.Services;

public static class AppRoles
{
    public const string Admin = "admin";
}

public static class AppPermissions
{
    public const string CertificatesView = "certificates.view";
    public const string CertificatesCreate = "certificates.create";
    public const string CertificatesManage = "certificates.manage";
    public const string SettingsEdit = "settings.edit";

    /// <summary>
    /// Changing which issuance policy is enforced: publishing a draft, or re-linking a template.
    /// Separate from settings.edit so authoring a policy and putting it into force can belong to
    /// different people.
    /// </summary>
    public const string PoliciesPublish = "policies.publish";

    /// <summary>
    /// Requesting and approving certificates that can sign other certificates (templates with
    /// <c>KeyCertSign</c>, such as SubordinateCA). Separate from certificates.create/manage so
    /// operating leaf certificates does not carry the ability to mint a CA.
    /// </summary>
    public const string CertificatesCa = "certificates.ca";

    public static readonly IReadOnlyList<string> All =
    [
        CertificatesView,
        CertificatesCreate,
        CertificatesManage,
        SettingsEdit,
        PoliciesPublish,
        CertificatesCa
    ];

    /// <summary>
    /// One plain-language sentence per permission, shown by the Web matrix, "My access" and the CLI.
    /// Derived from the endpoint gates; update the wording when a gate moves.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Descriptions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [CertificatesView] = "See certificate requests, issued certificates, templates and issuance policies.",
            [CertificatesCreate] = "File new certificate requests and renewals, preview them, and use the enrollment wizard.",
            [CertificatesManage] = "Approve, reject, revoke, edit and delete certificate requests.",
            [SettingsEdit] = "Change CA settings, generate or import the root CA, manage templates, policy drafts, webhooks, secret storage and the CRL base.",
            [PoliciesPublish] = "Put issuance policies into force: publish drafts, link templates to policies, and change the ACME/EST template keys.",
            [CertificatesCa] = "Request and approve certificates that can sign other certificates, such as subordinate CAs."
        };
}
