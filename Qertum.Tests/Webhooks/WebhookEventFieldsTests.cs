using Qertum.Services;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookEventFieldsTests
{
    [Fact]
    public void CommonFieldsAreAvailableToEveryFamilyExceptWhereSuppressed()
    {
        foreach (var family in Enum.GetValues<WebhookEventFamily>())
        {
            var all = WebhookEventFields.All(family);

            foreach (var common in WebhookEventFields.Common)
            {
                if (WebhookEventFields.IsSuppressed(family, common))
                    Assert.DoesNotContain(common, all);
                else
                    Assert.Contains(common, all);
            }
        }
    }

    [Fact]
    public void CertificateRequestExposesItsOwnFields()
    {
        var fields = WebhookEventFields.For(WebhookEventFamily.CertificateRequest);
        Assert.Contains("commonName", fields);
        Assert.Contains("status", fields);
        Assert.Contains("certificateType", fields);
        Assert.Contains("keyAlgorithm", fields);
        Assert.Contains("serialNumber", fields);
        Assert.Contains("validTo", fields);
        Assert.Contains("failureReason", fields);
        Assert.Contains("requestedBy", fields);
        Assert.Contains("ownerTeam", fields);
        Assert.Contains("targetSystem", fields);
        Assert.Contains("ticketReference", fields);
        Assert.Contains("purpose", fields);
        Assert.Equal(12, fields.Count);
    }

    [Fact]
    public void SettingsExposesRolePermissionFieldsOnly()
        => Assert.Equal(
            new[] { "approvalMode", "expiresAtUtc", "family", "grantedPermissions", "namePattern", "previousApprovalMode", "previousRole", "previousStage", "revokedPermissions", "role", "stage", "twoPersonApproval", "typeKey" },
            WebhookEventFields.For(WebhookEventFamily.Settings).OrderBy(f => f, StringComparer.Ordinal));

    [Fact]
    public void TemplateAndPolicyExposeTheirIdentity()
    {
        Assert.Equal(
            new[] { "issuancePolicyId", "issuerId", "pqcStage", "templateName", "typeKey" },
            WebhookEventFields.For(WebhookEventFamily.Template).OrderBy(f => f, StringComparer.Ordinal));

        Assert.Equal(
            new[] { "policyName", "versionNumber", "versionStatus" },
            WebhookEventFields.For(WebhookEventFamily.Policy).OrderBy(f => f, StringComparer.Ordinal));
    }

    [Fact]
    public void KeyAccessExposesOnlyTheThumbprintAndSuppressesTheResourceIdentity()
    {
        Assert.Equal(new[] { "publicKeyThumbprint" }, WebhookEventFields.For(WebhookEventFamily.KeyAccess));

        var all = WebhookEventFields.All(WebhookEventFamily.KeyAccess);
        Assert.DoesNotContain("resourceId", all);
        Assert.DoesNotContain("resourceName", all);
        Assert.Contains("event", all);
        Assert.Contains("performedBy", all);
        Assert.Contains("timestamp", all);
    }

    [Fact]
    public void NoFieldNameSuggestsKeyMaterial()
    {
        string[] forbidden = ["key", "secret", "password", "pem", "private", "csr", "mac", "token"];

        foreach (var family in Enum.GetValues<WebhookEventFamily>())
        foreach (var field in WebhookEventFields.All(family))
        {
            // Exempt by inspection, not by accident: publicKeyThumbprint is a digest of public
            // material, keyAlgorithm is a label, and typeKey is a template's type key ("WebServer").
            if (field is "publicKeyThumbprint" or "keyAlgorithm" or "typeKey") continue;

            foreach (var word in forbidden)
                Assert.DoesNotContain(word, field, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void IsKnownRejectsAnotherFamilysField()
    {
        Assert.True(WebhookEventFields.IsKnown(WebhookEventFamily.CertificateRequest, "commonName"));
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.Settings, "commonName"));
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.KeyAccess, "commonName"));
        Assert.True(WebhookEventFields.IsKnown(WebhookEventFamily.KeyAccess, "publicKeyThumbprint"));
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.Template, "nonsense"));
    }

    [Fact]
    public void CertificateRequestFamily_CarriesTheMetadataFacts_ButNeverTheContactEmail()
    {
        var fields = WebhookEventFields.All(WebhookEventFamily.CertificateRequest);

        Assert.Superset(new HashSet<string> { "ownerTeam", "targetSystem", "ticketReference", "purpose" }, fields.ToHashSet());
        Assert.DoesNotContain("contactEmail", fields);
        Assert.DoesNotContain("compatibilityNote", fields);
        // The same set drives URL placeholders: an email address must not be substitutable into a URL.
        Assert.True(WebhookEventFields.IsKnown(WebhookEventFamily.CertificateRequest, "ownerTeam"));
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.CertificateRequest, "contactEmail"));
    }
    [Fact]
    public void TheAuditFamily_CarriesOnlyTheCheckpointFields()
    {
        Assert.Equal(["chainCount", "generatedAt", "heads"], WebhookEventFields.For(WebhookEventFamily.Audit).Order());
        Assert.Equal(WebhookEventFamily.Audit, WellKnownWebhookEvents.FamilyOf(WellKnownWebhookEvents.AuditCheckpoint));
    }
}
