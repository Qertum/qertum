using Qertum.Services;
using Qertum.Services.Enrollment;

namespace Qertum.Tests.Enrollment;

public sealed class EnrollmentPurposeClassifierTests
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string CodeSigning = "1.3.6.1.5.5.7.3.3";
    private const string EmailProtection = "1.3.6.1.5.5.7.3.4";

    [Theory]
    [InlineData("[\"DigitalSignature\",\"KeyEncipherment\"]", "[\"" + ServerAuth + "\"]", EnrollmentPurpose.WebServer)]
    [InlineData("[\"DigitalSignature\"]", "[\"" + CodeSigning + "\"]", EnrollmentPurpose.CodeSigning)]
    [InlineData("[\"DigitalSignature\",\"NonRepudiation\",\"KeyEncipherment\"]", "[\"" + EmailProtection + "\"]", EnrollmentPurpose.Email)]
    [InlineData("[\"DigitalSignature\"]", "[\"" + ClientAuth + "\"]", EnrollmentPurpose.ClientAuthentication)]
    [InlineData("[\"KeyCertSign\",\"CrlSign\",\"DigitalSignature\"]", "[]", EnrollmentPurpose.SubordinateCa)]
    public void SeededTemplates_ClassifyToTheirSinglePurpose(string keyUsages, string ekus, EnrollmentPurpose expected)
    {
        Assert.Equal([expected], EnrollmentPurposeClassifier.Classify(keyUsages, ekus));
    }

    [Fact]
    public void ServerAndClientAuth_YieldsBothInEnumOrder()
    {
        var purposes = EnrollmentPurposeClassifier.Classify("[]", $"[\"{ClientAuth}\",\"{ServerAuth}\"]");
        Assert.Equal([EnrollmentPurpose.WebServer, EnrollmentPurpose.ClientAuthentication], purposes);
    }

    [Fact]
    public void KeyCertSign_IsExclusive_EvenWithServerAuth()
    {
        var purposes = EnrollmentPurposeClassifier.Classify("[\"KeyCertSign\"]", $"[\"{ServerAuth}\"]");
        Assert.Equal([EnrollmentPurpose.SubordinateCa], purposes);
    }

    [Fact]
    public void NoRecognizedUsage_IsOther()
    {
        Assert.Equal([EnrollmentPurpose.Other], EnrollmentPurposeClassifier.Classify("[\"DigitalSignature\"]", "[\"1.2.3.4\"]"));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("not json", "{\"a\":1}")]
    [InlineData("[1,2]", "[")]
    public void MalformedOrMissingJson_IsOtherWithoutThrowing(string? keyUsages, string? ekus)
    {
        Assert.Equal([EnrollmentPurpose.Other], EnrollmentPurposeClassifier.Classify(keyUsages, ekus));
    }

    [Fact]
    public void ParseStringArray_ReturnsEmptyForMalformedJson()
    {
        Assert.Empty(EnrollmentPurposeClassifier.ParseStringArray("oops"));
        Assert.Equal(["dns", "ip"], EnrollmentPurposeClassifier.ParseStringArray("[\"dns\",\"ip\"]"));
    }
}
