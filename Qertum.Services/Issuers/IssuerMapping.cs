using Qertum.Services.Policies;

namespace Qertum.Services.Issuers;

/// <summary>Row → API shape. The only place an <see cref="Issuer"/> becomes an <see cref="IssuerResponse"/>.</summary>
public static class IssuerMapping
{
    public static IssuerResponse ToResponse(Issuer issuer) => new(
        issuer.Id, issuer.Name, issuer.Kind, issuer.ParentIssuerId, issuer.KeyCustody, issuer.Status, issuer.IsDefault,
        issuer.SubjectDn, issuer.SerialNumber, issuer.KeyAlgorithm?.ToCanonicalString(),
        issuer.ValidFrom, issuer.ValidTo, issuer.PathLengthConstraint,
        IssuancePolicyEvaluator.ReadList(issuer.PermittedDnsSuffixesJson),
        IssuancePolicyEvaluator.ReadList(issuer.ExcludedDnsSuffixesJson),
        IssuancePolicyEvaluator.ReadList(issuer.PermittedIpRangesJson),
        IssuancePolicyEvaluator.ReadList(issuer.ExcludedIpRangesJson),
        issuer.UploadedCrlNumber, issuer.UploadedCrlNextUpdateUtc,
        issuer.CreatedAtUtc, issuer.ActivatedAtUtc, issuer.RetiredAtUtc, issuer.ArchivedAtUtc, issuer.DestroyedAtUtc,
        issuer.RevokedAtUtc);
}
