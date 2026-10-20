using System.Net;
using DnsClient;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Acme;

/// <summary>
/// Resolves TXT records through a fixed set of recursive resolvers.
/// </summary>
/// <remarks>
/// Egress reaches only the configured resolvers, never an address the domain owner controls, so
/// unlike the http-01 verifier this path needs no <see cref="IAcmeAddressPolicy"/> allowlist. Do
/// not "fix" that asymmetry by adding one; do reconsider it if this is ever changed to chase
/// authoritative nameservers, because that would connect to addresses the domain owner picks.
/// </remarks>
public sealed class DnsClientAcmeDnsResolver : IAcmeDnsResolver
{
    private readonly LookupClient _client;

    public DnsClientAcmeDnsResolver(IOptions<AcmeDns01Options> options)
    {
        var settings = options.Value;

        var clientOptions = settings.Resolvers.Length == 0
            ? new LookupClientOptions()
            : new LookupClientOptions([.. settings.Resolvers.Select(ParseEndpoint)]);

        // Caching off: a challenge retry has to re-query. With the cache on, a negative answer
        // observed before the client published its record would be replayed for the whole TTL and
        // every retry inside that window would fail for a record that is already live.
        clientOptions.UseCache = false;
        clientOptions.Timeout = TimeSpan.FromSeconds(settings.QueryTimeoutSeconds);

        _client = new LookupClient(clientOptions);
    }

    public async Task<DnsTxtLookupResult> ResolveTxtAsync(string name, CancellationToken ct = default)
    {
        try
        {
            var response = await _client.QueryAsync(name, QueryType.TXT, cancellationToken: ct);

            if (response.HasError)
                return new DnsTxtLookupResult(false, [], $"DNS lookup for '{name}' failed: {response.ErrorMessage}");

            var records = response.Answers.TxtRecords()
                .SelectMany(record => record.Text)
                .ToList();

            return new DnsTxtLookupResult(true, records, null);
        }
        catch (DnsResponseException ex)
        {
            return new DnsTxtLookupResult(false, [], $"DNS lookup for '{name}' failed: {ex.Message}");
        }
    }

    private static IPEndPoint ParseEndpoint(string value)
    {
        if (!IPEndPoint.TryParse(value, out var endpoint))
            throw new InvalidOperationException($"Invalid DNS resolver endpoint '{value}' in {AcmeDns01Options.SectionName}:Resolvers.");

        // IPEndPoint.TryParse yields port 0 for a bare address; DNS is port 53.
        return endpoint.Port == 0 ? new IPEndPoint(endpoint.Address, 53) : endpoint;
    }
}
