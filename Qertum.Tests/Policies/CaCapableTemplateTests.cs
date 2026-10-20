// Qertum.Tests/Policies/CaCapableTemplateTests.cs
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Enrollment;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CaCapableTemplateTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("[\"DigitalSignature\",\"KeyCertSign\",\"CrlSign\"]", true)]
    [InlineData("[\"DigitalSignature\"]", false)]
    [InlineData("[\"keycertsign\"]", false)] // ordinal, exactly as the generator's BasicConstraints decision was
    [InlineData("", false)]
    [InlineData("not json", false)]
    [InlineData(null, false)]
    public void ReadsKeyCertSignExactly(string? json, bool expected) =>
        Assert.Equal(expected, CaCapableTemplate.IsCaCapable(json));

    [Fact]
    public void ANullTemplateIsNotCaCapable() => Assert.False(CaCapableTemplate.IsCaCapable((CertificateTemplate?)null));

    [Fact]
    public async Task OnlyTheSeededSubordinateCaTemplateIsCaCapable_AndTheClassifierAgrees()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var templates = await scope.Db.CertificateTemplates.AsNoTracking().ToListAsync(Ct);

        Assert.Equal(["SubordinateCA"], templates.Where(CaCapableTemplate.IsCaCapable).Select(t => t.TypeKey).ToArray());
        foreach (var template in templates)
        {
            var purposes = EnrollmentPurposeClassifier.Classify(template.KeyUsagesJson, template.ExtendedKeyUsagesJson);
            Assert.Equal(CaCapableTemplate.IsCaCapable(template), purposes.Contains(EnrollmentPurpose.SubordinateCa));
        }
    }

    [Fact]
    public void ThePermissionIsDescribedAndListed()
    {
        Assert.Equal("certificates.ca", AppPermissions.CertificatesCa);
        Assert.Contains(AppPermissions.CertificatesCa, AppPermissions.All);
        Assert.False(string.IsNullOrWhiteSpace(AppPermissions.Descriptions[AppPermissions.CertificatesCa]));
    }
}
