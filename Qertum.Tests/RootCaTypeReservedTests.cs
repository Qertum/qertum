using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests;

/// <summary>
/// <c>RootCA</c> is the type the CA-generation route files (settings.edit, step-up, independent
/// approval). Policy evaluation treats it as unrestricted and the consumer turns it into a new root,
/// so a template with that type key let a <c>certificates.create</c> caller file one through the
/// ordinary request route. The type key is reserved and the request routes refuse the type.
/// </summary>
public sealed class RootCaTypeReservedTests
{
    [Theory]
    [InlineData("RootCA")]
    [InlineData("rootca")]
    [InlineData("ROOTCA")]
    public void ATemplateCannotUseTheRootCaTypeKey(string typeKey)
    {
        var result = new SaveCertificateTemplateRequestValidator().Validate(
            new SaveCertificateTemplateRequest { Name = "Root", TypeKey = typeKey });

        var error = Assert.Single(result.Errors, e => e.PropertyName == nameof(SaveCertificateTemplateRequest.TypeKey));
        Assert.Contains("reserved", error.ErrorMessage);
    }

    [Theory]
    [InlineData("RootCA")]
    [InlineData("rootca")]
    public void ARequestCannotBeFiledWithTheRootCaType(string type)
    {
        var result = new CreateCertificateRequestValidator().Validate(new CreateCertificateRequestRequest
        {
            CommonName = "root.example.test",
            Type = type,
            PropertiesJson = "{}"
        });

        Assert.Contains(result.Errors, e => e.PropertyName == nameof(CreateCertificateRequestRequest.Type));
    }

    [Fact]
    public void ARequestCannotBeChangedToTheRootCaType()
    {
        var result = new UpdateCertificateRequestValidator().Validate(new UpdateCertificateRequestRequest
        {
            CommonName = "root.example.test",
            Type = "RootCA",
            PropertiesJson = "{}"
        });

        Assert.Contains(result.Errors, e => e.PropertyName == nameof(UpdateCertificateRequestRequest.Type));
    }

    [Fact]
    public void OrdinaryTypesAreStillAccepted()
    {
        Assert.True(new SaveCertificateTemplateRequestValidator().Validate(
            new SaveCertificateTemplateRequest { Name = "Root-like", TypeKey = "RootCAMirror" }).IsValid);
        Assert.DoesNotContain(new CreateCertificateRequestValidator().Validate(new CreateCertificateRequestRequest
        {
            CommonName = "web.example.test",
            Type = "WebServer",
            PropertiesJson = "{}"
        }).Errors, e => e.PropertyName == nameof(CreateCertificateRequestRequest.Type));
    }
}
