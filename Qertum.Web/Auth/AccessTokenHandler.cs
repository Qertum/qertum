using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components.Authorization;
using Qertum.Services;

namespace Qertum.Web.Auth;

/// <summary>
/// Attaches only the current request or circuit's bearer token to API calls.
/// This handler is constructed outside the pooled <see cref="IHttpClientFactory"/> pipeline.
/// </summary>
public sealed class AccessTokenHandler(
    ICircuitTokens tokens,
    AuthenticationStateProvider authenticationStateProvider,
    IStepUpNotifier? stepUp = null) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync();
        var token = state.User.Identity?.IsAuthenticated == true
            ? await tokens.GetAccessTokenAsync(cancellationToken)
            : null;
        if (!string.IsNullOrEmpty(token) && !await IsAuthenticatedAsync())
            token = null;
        request.Headers.Authorization = string.IsNullOrEmpty(token)
            ? null
            : new AuthenticationHeaderValue("Bearer", token);

        byte[]? contentBytes = null;
        var contentHeaders = new List<KeyValuePair<string, string[]>>();
        if (request.Content is not null)
        {
            contentBytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            contentHeaders.AddRange(request.Content.Headers.Select(header =>
                new KeyValuePair<string, string[]>(header.Key, header.Value.ToArray())));
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized
            && response.Headers.TryGetValues("WWW-Authenticate", out var challenges)
            && StepUpChallenge.TryParse(challenges) is { } challenge)
        {
            // The token is valid but too weak or too old: refreshing it would only repeat the refusal.
            stepUp?.Raise(challenge);
            return response;
        }
        if (response.StatusCode != HttpStatusCode.Unauthorized || string.IsNullOrEmpty(token))
            return response;
        if (!await IsAuthenticatedAsync())
            return response;

        var replacement = await tokens.RefreshAfterUnauthorizedAsync(token, cancellationToken);
        if (string.IsNullOrEmpty(replacement) || replacement == token)
            return response;
        if (!await IsAuthenticatedAsync())
            return response;

        using var retry = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy
        };
        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", replacement);
        foreach (var header in request.Headers)
        {
            if (!header.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                retry.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        foreach (var option in request.Options)
            retry.Options.Set(new HttpRequestOptionsKey<object?>(option.Key), option.Value);
        if (contentBytes is not null)
        {
            retry.Content = new ByteArrayContent(contentBytes);
            foreach (var header in contentHeaders)
                retry.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        response.Dispose();
        return await base.SendAsync(retry, cancellationToken);
    }

    private async Task<bool> IsAuthenticatedAsync() =>
        (await authenticationStateProvider.GetAuthenticationStateAsync()).User.Identity?.IsAuthenticated == true;
}
