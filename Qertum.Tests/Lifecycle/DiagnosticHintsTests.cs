using System.Reflection;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class DiagnosticHintsTests
{
    [Fact]
    public void EveryCategoryHasAHint()
    {
        var categories = typeof(DiagnosticCategories)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral)
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        Assert.NotEmpty(categories);
        Assert.All(categories, c => Assert.False(string.IsNullOrWhiteSpace(DiagnosticHints.For(c)), c));
    }

    [Fact]
    public void EveryVerifierFailureIsACategory()
    {
        foreach (var failure in Enum.GetValues<AcmeChallengeFailure>().Where(f => f != AcmeChallengeFailure.None))
            Assert.NotNull(DiagnosticHints.For(failure.ToString()));
    }

    [Fact]
    public void AnUnknownCategoryHasNoHint() => Assert.Null(DiagnosticHints.For("SomethingElse"));
}
