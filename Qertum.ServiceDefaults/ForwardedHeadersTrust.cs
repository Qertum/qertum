using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Qertum.ServiceDefaults;

/// <summary>
/// Which proxies a host takes <c>X-Forwarded-Proto</c> and <c>X-Forwarded-For</c> from. ASP.NET's
/// <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c> switch trusts those headers from every client, so anyone who reaches a
/// published port directly could claim https (and pass the identity provider's transport check) or any client
/// address (and escape the per-address rate limits). With the switch on, a host now refuses to start unless
/// <see cref="TrustedProxies"/> names the proxy, and then honours the headers from those addresses only.
/// </summary>
public sealed class ForwardedHeadersTrustOptions
{
    /// <summary>The configuration section.</summary>
    public const string SectionName = "ForwardedHeaders";

    /// <summary>
    /// The proxies' addresses: IP addresses or CIDR networks (<c>172.18.0.0/16</c>), separated by commas or spaces.
    /// The deploy images set it from <c>QERTUM_TRUSTED_PROXIES</c>. Empty by default; required when forwarded headers
    /// are enabled.
    /// </summary>
    public string TrustedProxies { get; set; } = "";

    /// <summary>Whether <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c> is on (read the way ASP.NET reads it).</summary>
    internal bool ForwardedHeadersEnabled { get; set; }

    /// <summary>Parses <see cref="TrustedProxies"/>; <paramref name="invalid"/> is the first entry that is neither form.</summary>
    internal IReadOnlyList<IPNetwork> Parse(out string? invalid)
    {
        invalid = null;
        var networks = new List<IPNetwork>();
        foreach (var entry in TrustedProxies.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPNetwork.TryParse(entry, out var network))
                networks.Add(network);
            else if (IPAddress.TryParse(entry, out var address))
                networks.Add(new IPNetwork(address, address.GetAddressBytes().Length * 8));
            else
            {
                invalid = entry;
                return [];
            }
        }
        return networks;
    }
}

/// <summary>Registers <see cref="ForwardedHeadersTrustOptions"/> and applies it to ASP.NET's forwarded-headers middleware.</summary>
public static class ForwardedHeadersTrust
{
    /// <summary>
    /// Validates the trusted-proxy list at startup and, when it names any, makes the forwarded-headers middleware
    /// accept the headers from those addresses only (the switch alone clears the known lists, trusting everyone).
    /// </summary>
    public static IServiceCollection AddQertumForwardedHeadersTrust(this IServiceCollection services)
    {
        services.AddOptions<ForwardedHeadersTrustOptions>()
            .Configure<IConfiguration>((options, configuration) =>
            {
                configuration.GetSection(ForwardedHeadersTrustOptions.SectionName).Bind(options);
                options.ForwardedHeadersEnabled = string.Equals(
                    configuration["FORWARDEDHEADERS_ENABLED"], "true", StringComparison.OrdinalIgnoreCase);
            })
            .Validate(options => { options.Parse(out var invalid); return invalid is null; },
                "ForwardedHeaders:TrustedProxies (QERTUM_TRUSTED_PROXIES) holds an entry that is neither an IP address nor a CIDR network.")
            .Validate(options => !options.ForwardedHeadersEnabled || options.Parse(out _).Count > 0,
                "Forwarded headers are enabled (ASPNETCORE_FORWARDEDHEADERS_ENABLED) but no proxy is trusted: set " +
                "QERTUM_TRUSTED_PROXIES (ForwardedHeaders:TrustedProxies) to the TLS proxy's IP address or network, " +
                "or anyone reaching this port directly could forge X-Forwarded-Proto and X-Forwarded-For.")
            .ValidateOnStart();

        services.AddOptions<ForwardedHeadersOptions>()
            .PostConfigure<IOptions<ForwardedHeadersTrustOptions>>((forwarded, trust) =>
            {
                var networks = trust.Value.Parse(out _);
                if (networks.Count == 0) return;
                forwarded.KnownProxies.Clear();
                forwarded.KnownIPNetworks.Clear();
                foreach (var network in networks)
                    forwarded.KnownIPNetworks.Add(network);
            });

        return services;
    }
}
