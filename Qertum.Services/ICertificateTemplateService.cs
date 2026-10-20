namespace Qertum.Services;

public interface ICertificateTemplateService
{
    Task<IReadOnlyList<CertificateTemplate>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<CertificateTemplate?> GetByIdAsync(CertificateTemplateId id, CancellationToken cancellationToken = default);
    Task<CertificateTemplate?> GetByTypeKeyAsync(string typeKey, CancellationToken cancellationToken = default);
    Task<CertificateTemplate> CreateAsync(CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default);
    Task<CertificateTemplate?> UpdateAsync(CertificateTemplateId id, CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default);
    /// <summary>Sets or clears the template's issuance policy link. Callers validate the link first.</summary>
    Task<CertificateTemplate?> SetIssuancePolicyAsync(CertificateTemplateId id, IssuancePolicyId? policyId, string performedBy, CancellationToken cancellationToken = default);
    /// <summary>Pins the template to an issuer; null returns it to the default issuer. Audited as <c>TemplateIssuerChanged</c>.</summary>
    Task<CertificateTemplate?> SetIssuerAsync(CertificateTemplateId id, IssuerId? issuerId, string performedBy, CancellationToken cancellationToken = default);
    /// <summary>
    /// Sets the template's PQC stage override; null follows the CA default. Audited as
    /// <c>TemplatePqcStageChanged</c>. Callers must have checked the admin role.
    /// </summary>
    Task<CertificateTemplate?> SetPqcStageAsync(CertificateTemplateId id, PqcStage? stage, string performedBy, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(CertificateTemplateId id, string performedBy, CancellationToken cancellationToken = default);
}
