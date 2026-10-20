using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests.Policies;

public sealed class SaveIssuancePolicyDraftRequestValidatorTests
{
    private readonly SaveIssuancePolicyDraftRequestValidator _validator = new();

    [Fact]
    public void EmptyRules_AreValid() =>
        Assert.True(_validator.Validate(new SaveIssuancePolicyDraftRequest()).IsValid);

    [Fact]
    public void WellFormedRules_AreValid() =>
        Assert.True(_validator.Validate(new SaveIssuancePolicyDraftRequest
        {
            AllowedDnsSuffixes = ["corp.example.com", "lab.example.org."],
            AllowedIpRanges = ["10.0.0.0/8", "192.168.1.5", "fd00::/8"],
            AllowedKeyAlgorithms = ["ECDSA-P256", "ml-dsa-65"],
            MaxValidityDays = 397
        }).IsValid);

    [Theory]
    [InlineData("*.corp.example.com")]
    [InlineData("corp example.com")]
    [InlineData("")]
    public void InvalidDnsSuffix_IsRejected(string suffix) =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedDnsSuffixes = [suffix] }).IsValid);

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("not-a-range")]
    public void InvalidIpRange_IsRejected(string range) =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedIpRanges = [range] }).IsValid);

    [Fact]
    public void UnknownOrDuplicateAlgorithm_IsRejected()
    {
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedKeyAlgorithms = ["DSA"] }).IsValid);
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedKeyAlgorithms = ["RSA", "rsa"] }).IsValid);
    }

    [Fact]
    public void ZeroMaxValidity_IsRejected() =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { MaxValidityDays = 0 }).IsValid);

    [Fact]
    public void MoreThan100Suffixes_IsRejected() =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest
        {
            AllowedDnsSuffixes = Enumerable.Range(0, 101).Select(i => $"d{i}.example.com").ToList()
        }).IsValid);

    [Fact]
    public void RequesterRoles_WellFormed_AreValid() =>
        Assert.True(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedRequesterRoles = ["ops", "pki.admins"] }).IsValid);

    [Theory]
    [InlineData("admin")]
    [InlineData("Admin")]
    [InlineData("")]
    [InlineData(" ops")]
    [InlineData("a/b")]
    public void RequesterRole_InvalidOrAdmin_IsRejected(string role) =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedRequesterRoles = [role] }).IsValid);

    [Fact]
    public void RequesterRoles_CaseDuplicates_AreRejected() =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedRequesterRoles = ["ops", "OPS"] }).IsValid);

    [Fact]
    public void RequesterRoles_MoreThan50_AreRejected() =>
        Assert.False(_validator.Validate(new SaveIssuancePolicyDraftRequest
        {
            AllowedRequesterRoles = [.. Enumerable.Range(0, 51).Select(i => $"role{i}")]
        }).IsValid);
}
