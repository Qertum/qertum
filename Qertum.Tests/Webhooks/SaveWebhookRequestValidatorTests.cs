using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests.Webhooks;

public sealed class SaveWebhookRequestValidatorTests
{
    private static readonly SaveWebhookRequestValidator Validator = new();

    private static SaveWebhookRequest Request(
        WebhookEventFamily family = WebhookEventFamily.CertificateRequest,
        string eventsJson = "[]",
        string url = "https://hook.invalid/receive") =>
        new() { Name = "hook", Url = url, Family = family, EventsJson = eventsJson, IsEnabled = true };

    [Fact]
    public void EmptyEventsJsonIsValid()
        => Assert.True(Validator.Validate(Request()).IsValid);

    [Fact]
    public void EventInTheChosenFamilyIsValid()
        => Assert.True(Validator.Validate(Request(WebhookEventFamily.Template, """["TemplateCreated"]""")).IsValid);

    [Fact]
    public void EventFromAnotherFamilyIsRejectedAndTheErrorNamesTheFamilysEvents()
    {
        var result = Validator.Validate(Request(WebhookEventFamily.Template, """["Issued"]"""));

        Assert.False(result.IsValid);
        var message = string.Join(" ", result.Errors.Select(e => e.ErrorMessage));
        Assert.Contains("Issued", message);
        Assert.Contains("TemplateCreated", message);
    }

    [Fact]
    public void UnknownEventIsRejected()
        => Assert.False(Validator.Validate(Request(eventsJson: """["NotAnEvent"]""")).IsValid);

    [Fact]
    public void MalformedEventsJsonIsRejected()
        => Assert.False(Validator.Validate(Request(eventsJson: "not json")).IsValid);

    [Fact]
    public void UrlPlaceholderFromTheFamilyIsValid()
        => Assert.True(Validator.Validate(Request(
            WebhookEventFamily.CertificateRequest, url: "https://h.invalid/x?cn={commonName}&e={event}")).IsValid);

    [Fact]
    public void UrlPlaceholderFromAnotherFamilyIsRejected()
    {
        var result = Validator.Validate(Request(
            WebhookEventFamily.Policy, url: "https://h.invalid/x?cn={commonName}"));

        Assert.False(result.IsValid);
        Assert.Contains("commonName", string.Join(" ", result.Errors.Select(e => e.ErrorMessage)));
    }

    [Fact]
    public void KeyAccessUrlMayNotReferenceTheSuppressedFields()
    {
        Assert.False(Validator.Validate(Request(
            WebhookEventFamily.KeyAccess, url: "https://h.invalid/k?id={resourceId}")).IsValid);
        Assert.True(Validator.Validate(Request(
            WebhookEventFamily.KeyAccess, url: "https://h.invalid/k?t={publicKeyThumbprint}")).IsValid);
    }

    [Fact]
    public void NonHttpUrlIsStillRejected()
        => Assert.False(Validator.Validate(Request(url: "ftp://hook.invalid/receive")).IsValid);

    [Theory]
    [InlineData("https://user:pass@hook.invalid/receive")]
    [InlineData("https://hook.invalid/receive#fragment")]
    [InlineData("https://{resourceName}.invalid/receive")]
    public void UnsafeAuthorityOrFragmentIsRejected(string url)
        => Assert.False(Validator.Validate(Request(url: url)).IsValid);

    [Fact]
    public void PathAndQueryPlaceholdersRemainValid()
        => Assert.True(Validator.Validate(Request(url: "https://hook.invalid/{event}?name={commonName}")).IsValid);
}
