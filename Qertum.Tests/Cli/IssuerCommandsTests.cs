using System.CommandLine;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class IssuerCommandsTests
{
    private static Command Issuers() => IssuerCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    [Fact]
    public void ExposesTheCeremonyCommands()
    {
        Assert.Equal(
            ["archive", "create-intermediate", "delete", "export-key", "export-pfx", "install", "list", "make-default", "request", "retire", "show", "trust-bundle", "upload-crl"],
            Issuers().Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CreateIntermediate_MapsEveryOption()
    {
        var parsed = Issuers().Parse(
            "create-intermediate --name \"Issuing 1\" --cn \"Issuing 1\" --o Qertum --algorithm ML-DSA-65 --validity-days 1000 " +
            "--path-length 1 --permit-dns corp.example --permit-dns lab.example --exclude-dns secret.corp.example " +
            "--permit-ip 10.0.0.0/8 --exclude-ip 10.9.0.0/16 --parent 11111111-1111-1111-1111-111111111111");
        Assert.Empty(parsed.Errors);

        var request = IssuerCommands.BuildCreateRequest(parsed);

        Assert.Equal("Issuing 1", request.Name);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65, request.KeyAlgorithm);
        Assert.Equal(1000, request.ValidityDays);
        Assert.Equal(1, request.PathLength);
        Assert.Equal(["corp.example", "lab.example"], request.PermittedDnsSuffixes);
        Assert.Equal(["secret.corp.example"], request.ExcludedDnsSuffixes);
        Assert.Equal(["10.0.0.0/8"], request.PermittedIpRanges);
        Assert.Equal(["10.9.0.0/16"], request.ExcludedIpRanges);
        Assert.Equal(new IssuerId(Guid.Parse("11111111-1111-1111-1111-111111111111")), request.ParentIssuerId);
    }

    [Fact]
    public void CreateIntermediate_PathLengthNone_MeansUnconstrained()
    {
        var parsed = Issuers().Parse("create-intermediate --name A --cn A --path-length none");

        Assert.Null(IssuerCommands.BuildCreateRequest(parsed).PathLength);
    }

    [Fact]
    public void Install_RequiresCertAndChain()
    {
        Assert.NotEmpty(Issuers().Parse("install 11111111-1111-1111-1111-111111111111 --cert a.pem").Errors);
        Assert.Empty(Issuers().Parse("install 11111111-1111-1111-1111-111111111111 --cert a.pem --chain b.pem").Errors);
    }
}
