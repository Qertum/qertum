using Qertum.Services;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookUrlTemplateTests
{
    [Fact]
    public void ExtractsEveryToken()
    {
        var tokens = WebhookUrlTemplate.ExtractTokens("https://h.invalid/p/{event}?cn={commonName}&x={event}");
        Assert.Equal(new[] { "commonName", "event" }, tokens.OrderBy(t => t, StringComparer.Ordinal));
    }

    [Fact]
    public void UrlWithoutTokensIsValidForEveryFamily()
    {
        foreach (var family in Enum.GetValues<WebhookEventFamily>())
        {
            Assert.True(WebhookUrlTemplate.TryValidate("https://h.invalid/hook", family, out var error));
            Assert.Null(error);
        }
    }

    [Fact]
    public void UnknownTokenIsRejectedAndTheErrorNamesTheAllowedFields()
    {
        var valid = WebhookUrlTemplate.TryValidate(
            "https://h.invalid/hook?x={nonsense}", WebhookEventFamily.Template, out var error);

        Assert.False(valid);
        Assert.Contains("nonsense", error);
        Assert.Contains("templateName", error);
    }

    [Fact]
    public void TokenFromAnotherFamilyIsRejected()
    {
        Assert.False(WebhookUrlTemplate.TryValidate(
            "https://h.invalid/hook?cn={commonName}", WebhookEventFamily.Policy, out var error));
        Assert.Contains("commonName", error);
    }

    [Fact]
    public void KeyAccessRejectsTheSuppressedCommonFields()
    {
        Assert.False(WebhookUrlTemplate.TryValidate(
            "https://h.invalid/hook?cn={commonName}", WebhookEventFamily.KeyAccess, out _));
        Assert.False(WebhookUrlTemplate.TryValidate(
            "https://h.invalid/hook?id={resourceId}", WebhookEventFamily.KeyAccess, out _));
        Assert.True(WebhookUrlTemplate.TryValidate(
            "https://h.invalid/hook?t={publicKeyThumbprint}", WebhookEventFamily.KeyAccess, out _));
    }

    [Fact]
    public void ResolveSubstitutesAndEscapes()
    {
        var resolved = WebhookUrlTemplate.Resolve(
            "https://h.invalid/hook?e={event}&cn={commonName}",
            new Dictionary<string, string?> { ["event"] = "Issued", ["commonName"] = "a b/c&d" });

        Assert.Equal("https://h.invalid/hook?e=Issued&cn=a%20b%2Fc%26d", resolved);
    }

    [Fact]
    public void ResolveSubstitutesEmptyForNullAndMissing()
    {
        var resolved = WebhookUrlTemplate.Resolve(
            "https://h.invalid/hook?r={failureReason}&i={resourceId}",
            new Dictionary<string, string?> { ["failureReason"] = null, ["resourceId"] = null });

        Assert.Equal("https://h.invalid/hook?r=&i=", resolved);
    }

    [Fact]
    public void ResolveTruncatesEachValueAt256Characters()
    {
        var resolved = WebhookUrlTemplate.Resolve(
            "https://h.invalid/hook?cn={commonName}",
            new Dictionary<string, string?> { ["commonName"] = new string('a', 400) });

        Assert.Equal("https://h.invalid/hook?cn=" + new string('a', WebhookUrlTemplate.MaxValueLength), resolved);
    }

    [Fact]
    public void ResolveMarksAnOversizedUrlInvalid()
    {
        var template = "https://h.invalid/hook?a=" + new string('x', 3990) + "&cn={commonName}";
        var resolved = WebhookUrlTemplate.Resolve(
            template, new Dictionary<string, string?> { ["commonName"] = new string('b', 200) });

        Assert.Equal(WebhookUrlTemplate.OversizedResolvedUrl, resolved);
    }

    [Fact]
    public void ResolveLeavesAnUnknownTokenAloneRatherThanThrowing()
    {
        var resolved = WebhookUrlTemplate.Resolve(
            "https://h.invalid/hook?x={nonsense}", new Dictionary<string, string?>());

        Assert.Equal("https://h.invalid/hook?x={nonsense}", resolved);
    }

    [Fact]
    public void APercentEncodedTemplateNoLongerCarriesPlaceholders()
    {
        // Uri normalisation turns {event} into %7Bevent%7D, which is why substitution must run on
        // the stored string before any Uri is constructed.
        var normalised = new Uri("https://h.invalid/hook?e={event}").AbsoluteUri;

        Assert.Equal("https://h.invalid/hook?e=%7Bevent%7D", normalised);
        Assert.Empty(WebhookUrlTemplate.ExtractTokens(normalised));
    }
}
