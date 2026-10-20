using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class ApprovalAuditDetailTests
{
    private static readonly Guid V5 = Guid.NewGuid();
    private static readonly Guid V3 = Guid.NewGuid();

    private static PolicyDecision Admitted(Guid? id = null, int? number = 5) =>
        new(true, id ?? V5, "Web servers", number, []);

    private static PolicyDecision Refused() =>
        new(false, V5, "Web servers", 5,
            [new IssuancePolicyViolation(PolicyRules.DnsSuffix, "a.other.net", "Name 'a.other.net' is not under an allowed suffix."),
             new IssuancePolicyViolation(PolicyRules.MaxValidity, "400", "Validity 400 days exceeds 365.")]);

    [Fact]
    public void Preview_Admitted_NamesPolicyAndSameVersion() =>
        Assert.Equal("Approval preview: policy 'Web servers' v5 admits this request (same version as its last evaluation).",
            ApprovalAuditDetail.ForPreview(Admitted(), new PolicyVersionRef(V5, 5, "Web servers")));

    [Fact]
    public void Preview_Refused_ListsViolationsWithoutDoubledPeriods() =>
        Assert.Equal("Approval preview: policy 'Web servers' v5 refuses this request (last evaluated under policy 'Web servers' v3; the policy has changed since): " +
                     "Name 'a.other.net' is not under an allowed suffix; Validity 400 days exceeds 365.",
            ApprovalAuditDetail.ForPreview(Refused(), new PolicyVersionRef(V3, 3, "Web servers")));

    [Fact]
    public void Preview_NoPolicy_SaysNothingGovernsIt() =>
        Assert.Equal("Approval preview: no issuance policy governs this request.",
            ApprovalAuditDetail.ForPreview(PolicyDecision.Unrestricted, null));

    [Fact]
    public void Created_WhenNothingWasRecorded_SaysSo() =>
        Assert.Equal("Approval preview: policy 'Web servers' v5 admits this request (no policy version was recorded when it was last evaluated).",
            ApprovalAuditDetail.ForPreview(Admitted(), null));

    [Fact]
    public void Created_TemplateMovedToAnotherPolicy_NamesTheEarlierPolicy() =>
        // Another policy's v5: same number, different version — the name is what tells them apart.
        Assert.Equal("Approval preview: policy 'Web servers' v5 admits this request (last evaluated under policy 'Legacy' v5; the policy has changed since).",
            ApprovalAuditDetail.ForPreview(Admitted(), new PolicyVersionRef(Guid.NewGuid(), 5, "Legacy")));

    [Fact]
    public void Approval_WithoutReport_SaysNoPreviewReported() =>
        Assert.Equal("Approved under policy 'Web servers' v5 (same version as its last evaluation). The approver's client reported no preview.",
            ApprovalAuditDetail.ForApproval(Admitted(), new PolicyVersionRef(V5, 5, "Web servers"), null));

    [Fact]
    public void Approval_ReportMatchingVersion_SaysWhatWasShown() =>
        Assert.Equal("Approved under policy 'Web servers' v5 (same version as its last evaluation). " +
                     "The approver's client reported a preview of policy 'Web servers' v5 that admitted it.",
            ApprovalAuditDetail.ForApproval(Admitted(), new PolicyVersionRef(V5, 5, "Web servers"), new ReportedPreview(true, V5, 5, "Web servers", true)));

    [Fact]
    public void Approval_ReportOfOlderVersion_SaysThePolicyChangedBeforeApproval() =>
        Assert.Equal("Approved under policy 'Web servers' v5 (last evaluated under policy 'Web servers' v3; the policy has changed since). " +
                     "The approver's client reported a preview of policy 'Web servers' v4 that refused it; the governing version changed to policy 'Web servers' v5 before approval.",
            ApprovalAuditDetail.ForApproval(Admitted(), new PolicyVersionRef(V3, 3, "Web servers"), new ReportedPreview(false, Guid.NewGuid(), 4, "Web servers", false)));

    [Fact]
    public void Approval_NoPolicy_NamesNoPolicyOnBothSides() =>
        Assert.Equal("Approved under no issuance policy. The approver's client reported a preview of no policy that admitted it.",
            ApprovalAuditDetail.ForApproval(PolicyDecision.Unrestricted, null, new ReportedPreview(true, null, null, null, true)));

    [Fact]
    public void BlockedApproval_ListsViolationsAndTheReport() =>
        Assert.Equal("Approval refused by policy 'Web servers' v5 (same version as its last evaluation): " +
                     "Name 'a.other.net' is not under an allowed suffix; Validity 400 days exceeds 365. " +
                     "The approver's client reported no preview.",
            ApprovalAuditDetail.ForBlockedApproval(Refused(), new PolicyVersionRef(V5, 5, "Web servers"), null));

    [Fact]
    public void AutoApproval_NamesTheSettingAndPolicy() =>
        Assert.Equal("Auto-approved at creation by AcmeAutoApprove under policy 'Web servers' v5.",
            ApprovalAuditDetail.ForAutoApproval("AcmeAutoApprove", Admitted()));

    [Fact]
    public void RefusedWithoutPolicy_NamesTheIssuanceRules() =>
        Assert.StartsWith("Approval preview: the issuance rules refuse this request",
            ApprovalAuditDetail.ForPreview(new PolicyDecision(false, null, null, null,
                [new IssuancePolicyViolation(PolicyRules.Template, "Nope", "No template 'Nope'.")]), null));

    [Fact]
    public void Approval_ReportOfAnotherPolicy_NamesBothPolicies() =>
        Assert.Equal("Approved under policy 'Web servers' v2 (last evaluated under policy 'Legacy' v2; the policy has changed since). " +
                     "The approver's client reported a preview of policy 'Legacy' v2 that admitted it; the governing version changed to policy 'Web servers' v2 before approval.",
            ApprovalAuditDetail.ForApproval(Admitted(number: 2), new PolicyVersionRef(V3, 2, "Legacy"),
                new ReportedPreview(true, V3, 2, "Legacy", false)));

    [Fact]
    public void Preview_WhenTheVersionListsRequesterRoles_SaysTheyAreCheckedAtSubmission() =>
        Assert.Equal("Approval preview: policy 'Web servers' v5 admits this request (same version as its last evaluation). " +
                     "Requester roles are checked at submission, not at approval.",
            ApprovalAuditDetail.ForPreview(Admitted() with { RequesterRolesListed = true }, new PolicyVersionRef(V5, 5, "Web servers")));
}
