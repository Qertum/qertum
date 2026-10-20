namespace Qertum.Services;

/// <summary>
/// Optional body of <c>POST /v1/certificate-requests/{id}/approve</c>: what the approver's client says
/// its approval preview showed. Recorded in the audit as reported by the client, never as verified.
/// </summary>
public sealed class ApproveCertificateRequestRequest
{
    /// <summary>The <see cref="ApprovalPreviewResponse.PolicyVersionId"/> the preview displayed (null when no policy governed it).</summary>
    public Guid? PreviewedPolicyVersionId { get; init; }

    /// <summary>The verdict the preview displayed; null means no preview is reported.</summary>
    public bool? PreviewedAllowed { get; init; }
}
