namespace Qertum.Services.Approvals;

/// <summary>The operations two-person approval can gate: their keys, as stored and sent over the API.</summary>
public static class ApprovalOperations
{
    /// <summary>Download of a certificate's private key by someone who is not its owner.</summary>
    public const string KeyExport = "key-export";

    /// <summary>PKCS#12 export of a certificate's private key by someone who is not its owner.</summary>
    public const string PfxExport = "pfx-export";

    /// <summary>Creating an intermediate issuer.</summary>
    public const string IssuerCreateIntermediate = "issuer-create-intermediate";

    /// <summary>Installing an issuer's signed certificate.</summary>
    public const string IssuerInstallCertificate = "issuer-install-certificate";

    /// <summary>Renewing an intermediate CA with a new key.</summary>
    public const string IssuerRenew = "issuer-renew";

    /// <summary>Uploading an offline issuer's CRL.</summary>
    public const string IssuerUploadCrl = "issuer-upload-crl";

    /// <summary>Making an issuer the default.</summary>
    public const string IssuerMakeDefault = "issuer-make-default";

    /// <summary>Retiring an issuer.</summary>
    public const string IssuerRetire = "issuer-retire";

    /// <summary>Archiving an issuer.</summary>
    public const string IssuerArchive = "issuer-archive";

    /// <summary>Deleting an issuer.</summary>
    public const string IssuerDelete = "issuer-delete";

    /// <summary>Downloading an online issuer's private key.</summary>
    public const string IssuerKeyExport = "issuer-key-export";

    /// <summary>PKCS#12 export of an online issuer's private key.</summary>
    public const string IssuerPfxExport = "issuer-pfx-export";

    /// <summary>Executing a bulk revocation.</summary>
    public const string BulkRevoke = "bulk-revoke";

    /// <summary>Publishing an issuance policy version.</summary>
    public const string PolicyPublish = "policy-publish";

    private static readonly HashSet<string> All = new(StringComparer.Ordinal)
    {
        KeyExport, PfxExport, IssuerCreateIntermediate, IssuerRenew, IssuerInstallCertificate, IssuerUploadCrl,
        IssuerMakeDefault, IssuerRetire, IssuerArchive, IssuerDelete, IssuerKeyExport, IssuerPfxExport, BulkRevoke, PolicyPublish
    };

    /// <summary>True when <paramref name="operation"/> is one of the gated operations.</summary>
    public static bool IsKnown(string? operation) => operation is not null && All.Contains(operation);

    /// <summary>False only for creating an intermediate, which acts on nothing that exists yet.</summary>
    public static bool NeedsTarget(string operation) => operation != IssuerCreateIntermediate;

    /// <summary>Every operation key, in declaration order of the spec table.</summary>
    public static IReadOnlyCollection<string> Keys => All;
}
