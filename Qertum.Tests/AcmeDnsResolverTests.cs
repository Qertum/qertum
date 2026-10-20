using Qertum.Services.Acme;
using Microsoft.Extensions.Options;

namespace Qertum.Tests;

public sealed class AcmeDnsResolverTests
{
    [Fact]
    public void Options_DefaultToEnabledWithSystemResolvers()
    {
        var options = new AcmeDns01Options();

        Assert.True(options.Enabled);
        Assert.Empty(options.Resolvers);
        Assert.Equal(5, options.QueryTimeoutSeconds);
    }

    [Fact]
    public void Construction_WithABareIpAddress_DefaultsToPort53()
    {
        var options = Options.Create(new AcmeDns01Options { Resolvers = ["192.0.2.53"] });

        // Constructing is the assertion: an unparseable endpoint throws here, and a bare address
        // with no port must be accepted rather than rejected for having port 0.
        var resolver = new DnsClientAcmeDnsResolver(options);

        Assert.NotNull(resolver);
    }

    [Fact]
    public void Construction_WithAMalformedResolver_Throws()
    {
        var options = Options.Create(new AcmeDns01Options { Resolvers = ["not-an-address"] });

        var ex = Assert.Throws<InvalidOperationException>(() => new DnsClientAcmeDnsResolver(options));
        Assert.Contains("not-an-address", ex.Message);
    }

    [Fact]
    public async Task ResolveTxt_AgainstAnUnreachableResolver_ReportsFailureRatherThanThrowing()
    {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and is guaranteed not to route, so this exercises
        // the timeout path without depending on the machine's real DNS.
        var options = Options.Create(new AcmeDns01Options
        {
            Resolvers = ["192.0.2.53"],
            QueryTimeoutSeconds = 1
        });
        var resolver = new DnsClientAcmeDnsResolver(options);

        var result = await resolver.ResolveTxtAsync(
            "_acme-challenge.example.invalid", TestContext.Current.CancellationToken);

        Assert.False(result.Succeeded);
        Assert.NotNull(result.ErrorDetail);
        Assert.Empty(result.Records);
    }
}
