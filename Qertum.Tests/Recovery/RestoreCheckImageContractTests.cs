namespace Qertum.Tests.Recovery;

/// <summary>
/// The restore check is an operator tool inside the deploy images, not a service. This pins that both images publish it
/// and that the multi-container entrypoint does not treat it as a service.
/// </summary>
public sealed class RestoreCheckImageContractTests
{
    private static string Read(params string[] relative)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine([dir.FullName, "deploy", .. relative]);
            if (File.Exists(path))
                return File.ReadAllText(path);
        }

        throw new FileNotFoundException(Path.Combine(relative));
    }

    [Theory]
    [InlineData("single-container", "Dockerfile")]
    [InlineData("multi-container", "Dockerfile")]
    public void BothImages_PublishTheRestoreCheck(string directory, string file)
    {
        Assert.Contains("Qertum.RestoreCheck/Qertum.RestoreCheck.csproj", Read(directory, file));
        Assert.Contains("-o /app/restorecheck", Read(directory, file));
    }

    [Fact]
    public void TheMultiContainerEntrypoint_DoesNotListTheRestoreCheckAsAService()
    {
        var validServices = Read("multi-container", "entrypoint.sh")
            .Split('\n').Single(l => l.StartsWith("VALID_SERVICES=", StringComparison.Ordinal));

        Assert.DoesNotContain("restorecheck", validServices);
    }
}
