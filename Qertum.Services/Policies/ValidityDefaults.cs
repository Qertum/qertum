namespace Qertum.Services.Policies;

public static class ValidityDefaults
{
    /// <summary>
    /// Validity a certificate gets when the request does not ask for one: the template's value,
    /// else the CA-wide setting, else 365 days. <see cref="CertificateGenerator"/> and the policy
    /// evaluator both call this so they cannot disagree about what will be issued.
    /// </summary>
    /// <summary>
    /// Validity the request will actually get: what it asked for, else the template/global default.
    /// The policy evaluator is what stops a request asking for more than the default allows, so the
    /// generator can honour the stored value directly.
    /// </summary>
    public static int EffectiveValidityDays(CertificateRequest request, CertificateTemplate? template, CaSettings? settings) =>
        request.ValidityDays > 0 ? request.ValidityDays!.Value : EffectiveValidityDays(template, settings);

    public static int EffectiveValidityDays(CertificateTemplate? template, CaSettings? settings) =>
        template?.ValidityDays > 0
            ? template.ValidityDays.Value
            : settings?.CertificateValidityDays > 0
                ? settings.CertificateValidityDays
                : 365;
}
