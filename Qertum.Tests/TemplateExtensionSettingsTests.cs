using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Qertum.Services;
using Qertum.Services.Validators;
using Qertum.Tests.Issuers;

namespace Qertum.Tests;

/// <summary>
/// The four extension fields of a certificate template are JSON text. They used to be stored as
/// sent and read leniently at issuance, so a malformed EKU list issued certificates without an EKU
/// (usable for any purpose) and an unknown key-usage name fell back to the default usages. One
/// reader now decides both what a save accepts and what issuance can use.
/// </summary>
public sealed class TemplateExtensionSettingsTests
{
    private static readonly SaveCertificateTemplateRequestValidator Validator = new();

    private static SaveCertificateTemplateRequest Template(
        string keyUsages = "[]", string ekus = "[]", string sanTypes = "[]", string? custom = null) => new()
    {
        Name = "Custom",
        TypeKey = "Custom",
        KeyUsagesJson = keyUsages,
        ExtendedKeyUsagesJson = ekus,
        SanTypesJson = sanTypes,
        CustomExtensionsJson = custom
    };

    private static string ErrorFor(SaveCertificateTemplateRequest request, string property)
    {
        var result = Validator.Validate(request);
        Assert.False(result.IsValid);
        return Assert.Single(result.Errors, e => e.PropertyName == property).ErrorMessage;
    }

    [Fact]
    public void TheSeededShapesAreAccepted()
    {
        var result = Validator.Validate(Template(
            """["DigitalSignature","KeyEncipherment","KeyAgreement","KeyCertSign","CrlSign"]""",
            """["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"]""",
            """["dns","ip","email","upn"]""",
            """[{"oid":"1.3.6.1.4.1.99999.1","value":"hello","critical":false}]"""));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    public void AnAbsentCustomExtensionListIsAccepted(string? custom) =>
        Assert.True(Validator.Validate(Template(custom: custom)).IsValid);

    [Theory]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("""{"a":1}""")]
    [InlineData("[1]")]
    public void AKeyUsageListThatIsNotAnArrayOfNamesIsRefused(string json) =>
        Assert.Contains("JSON array", ErrorFor(Template(keyUsages: json), nameof(SaveCertificateTemplateRequest.KeyUsagesJson)));

    [Theory]
    [InlineData("keyCertSign")]
    [InlineData("ServerAuth")]
    [InlineData("")]
    public void AnUnknownKeyUsageNameIsRefusedAndNamed(string name)
    {
        var error = ErrorFor(Template(keyUsages: $"""["DigitalSignature","{name}"]"""), nameof(SaveCertificateTemplateRequest.KeyUsagesJson));

        Assert.Contains($"'{name}'", error);
    }

    [Theory]
    [InlineData("""["1.3.6.1.5.5.7.3.1""")]
    [InlineData("""["serverAuth"]""")]
    [InlineData("""["1.3.6.1.5.5.7.3.01"]""")]
    [InlineData("""["3.1.2"]""")]
    [InlineData("""["1"]""")]
    [InlineData("""[""]""")]
    public void AMalformedExtendedKeyUsageListIsRefused(string json) =>
        ErrorFor(Template(ekus: json), nameof(SaveCertificateTemplateRequest.ExtendedKeyUsagesJson));

    [Fact]
    public void AnExtendedKeyUsageListedTwiceIsRefused() =>
        Assert.Contains("twice", ErrorFor(Template(ekus: """["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.1"]"""),
            nameof(SaveCertificateTemplateRequest.ExtendedKeyUsagesJson)));

    [Theory]
    [InlineData("""["DNS"]""")]
    [InlineData("""["uri"]""")]
    [InlineData("dns")]
    public void AnUnknownSanTypeIsRefused(string json) =>
        ErrorFor(Template(sanTypes: json), nameof(SaveCertificateTemplateRequest.SanTypesJson));

    [Theory]
    [InlineData("""{"oid":"1.2.3.4","value":"x"}""")]
    [InlineData("""[{"oid":"not-an-oid","value":"x"}]""")]
    [InlineData("""[{"oid":"1.2.3.4","value":""}]""")]
    [InlineData("""[{"oid":"","value":"x"}]""")]
    [InlineData("""[{"oid":"1.2.3.4","value":"x"},{"oid":"1.2.3.4","value":"y"}]""")]
    [InlineData("""[null]""")]
    public void AMalformedCustomExtensionListIsRefused(string json) =>
        ErrorFor(Template(custom: json), nameof(SaveCertificateTemplateRequest.CustomExtensionsJson));

    [Theory]
    [InlineData("2.5.29.19")] // basic constraints
    [InlineData("2.5.29.37")] // extended key usage
    [InlineData("2.5.29.17")] // subject alternative name
    public void ACustomExtensionInTheX509ArcIsRefused(string oid) =>
        Assert.Contains("2.5.29", ErrorFor(Template(custom: $$"""[{"oid":"{{oid}}","value":"x"}]"""),
            nameof(SaveCertificateTemplateRequest.CustomExtensionsJson)));

    [Fact]
    public async Task TheTemplateApiRefusesAMalformedFieldWithAValidationProblem()
    {
        await using var host = new IssuerApiHost();

        var response = await host.Admin().PostAsJsonAsync("/v1/certificate-templates",
            Template(ekus: """["1.3.6.1.5.5.7.3.1"""), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<HttpValidationProblemDetails>(TestContext.Current.CancellationToken);
        Assert.Contains(nameof(SaveCertificateTemplateRequest.ExtendedKeyUsagesJson), problem!.Errors.Keys);
    }

    [Fact]
    public void ReadingAStoredTemplateNamesTheTemplateAndTheFieldThatCannotBeRead()
    {
        var template = new CertificateTemplate { TypeKey = "Broken", Name = "Broken", ExtendedKeyUsagesJson = "[\"1.3.6" };

        var ex = Assert.Throws<InvalidOperationException>(() => TemplateExtensionSettings.Read(template));

        Assert.Contains("'Broken'", ex.Message);
        Assert.Contains("ExtendedKeyUsagesJson", ex.Message);
    }

    [Fact]
    public void ReadingAValidStoredTemplateReturnsItsValues()
    {
        var template = new CertificateTemplate
        {
            TypeKey = "Ok",
            Name = "Ok",
            KeyUsagesJson = """["DigitalSignature"]""",
            ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.2"]""",
            SanTypesJson = """["dns"]""",
            CustomExtensionsJson = """[{"oid":"1.3.6.1.4.1.99999.1","value":"v","critical":true}]"""
        };

        var read = TemplateExtensionSettings.Read(template);

        Assert.Equal(["DigitalSignature"], read.KeyUsages);
        Assert.Equal(["1.3.6.1.5.5.7.3.2"], read.ExtendedKeyUsages);
        Assert.Equal(["dns"], read.SanTypes);
        var custom = Assert.Single(read.CustomExtensions);
        Assert.Equal(("1.3.6.1.4.1.99999.1", "v", true), (custom.Oid, custom.Value, custom.Critical));
    }
}
