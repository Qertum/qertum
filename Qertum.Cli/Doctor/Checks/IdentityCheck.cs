using System.Net;
using System.Text.Json;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// The identity provider's OIDC discovery document must name an issuer and a JWKS, and the JWKS must hold
/// at least one key. Sends no token. It cannot tell whether a login would succeed.
/// </summary>
internal sealed class IdentityCheck : IDoctorCheck
{
    public string Id => "identity";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (context.IdentityUrl is null)
            return DoctorResult.Skip(Id, "no identity URL is known: pass --identity-url, set QERTUM_IDENTITY_URL or run 'qca auth login'");
        if (!DoctorUrls.TryHttp(context.IdentityUrl, out _))
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the identity URL '{context.IdentityUrl}' is not an http(s) URL");

        var discoveryUri = DoctorUrls.Combine(context.IdentityUrl, "/.well-known/openid-configuration");
        var discovery = await DoctorHttp.GetAsync(context, discoveryUri, bearerToken: null, 1 << 20, ct);
        if (!discovery.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(discovery, discoveryUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (discovery.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the discovery document at {discoveryUri} answered {(int)discovery.Status!.Value}",
                hint: "is --identity-url the identity provider's base URL?");

        string? issuer, jwksUri;
        try
        {
            using var document = JsonDocument.Parse(discovery.Body);
            issuer = Text(document.RootElement, "issuer");
            jwksUri = Text(document.RootElement, "jwks_uri");
        }
        catch (JsonException)
        {
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the discovery document is not valid JSON");
        }

        if (issuer is null || jwksUri is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the discovery document has no issuer or no jwks_uri",
                hint: "this does not look like an OpenID Connect provider");
        if (!DoctorUrls.TryHttp(jwksUri, out var jwks))
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the discovery document's jwks_uri is not an http(s) URL");

        var keys = await DoctorHttp.GetAsync(context, jwks, bearerToken: null, 1 << 20, ct);
        if (!keys.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(keys, jwks, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (keys.Status != HttpStatusCode.OK)
        {
            var redirect = keys.Location is { } location ? $" It redirects to {location}." : "";
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the JWKS at {jwks} answered {(int)keys.Status!.Value}",
                hint: $"check the jwks_uri the discovery document names.{redirect}");
        }

        var count = 0;
        try
        {
            using var document = JsonDocument.Parse(keys.Body);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("keys", out var array) && array.ValueKind == JsonValueKind.Array)
                count = array.GetArrayLength();
        }
        catch (JsonException)
        {
            // Counted as no keys below.
        }

        if (count == 0)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the identity provider publishes no signing keys",
                hint: "tokens cannot be validated until it has a signing key");

        return DoctorResult.Of(Id, DoctorStatus.Pass, $"identity provider reachable at {discoveryUri.GetLeftPart(UriPartial.Authority)}",
            verified: ["its discovery document names an issuer and a JWKS", $"the JWKS holds {count} signing key(s)"],
            notVerified: ["that a login would succeed", "that the API accepts this provider's tokens"]);
    }

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()
            : null;
}
