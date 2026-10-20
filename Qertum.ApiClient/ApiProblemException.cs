using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>
/// An API call failed with a problem body. Carries the policy violations when the failure was an
/// issuance policy decision, so a page can list the exact rules that refused the request instead of
/// the bare status code <c>EnsureSuccessStatusCode</c> would throw.
/// </summary>
public sealed class ApiProblemException(HttpStatusCode statusCode, string title, string? detail,
    string? policyName, int? versionNumber, IReadOnlyList<IssuancePolicyViolation> violations,
    string? correlationId = null,
    StepUpChallenge? stepUp = null,
    ApprovalChallenge? approval = null)
    : Exception(string.IsNullOrWhiteSpace(detail) ? title : detail)
{
    /// <summary>Status code the API answered with.</summary>
    public HttpStatusCode StatusCode { get; } = statusCode;

    /// <summary>Short problem title, e.g. "Issuance Policy Violation".</summary>
    public string Title { get; } = title;

    /// <summary>Longer explanation, when the API supplied one.</summary>
    public string? Detail { get; } = detail;

    /// <summary>Name of the policy that refused the request, when the failure was a policy decision.</summary>
    public string? PolicyName { get; } = policyName;

    /// <summary>Version number of the policy that refused the request.</summary>
    public int? VersionNumber { get; } = versionNumber;

    /// <summary>The rules the request failed; empty for any other kind of failure.</summary>
    public IReadOnlyList<IssuancePolicyViolation> Violations { get; } = violations;

    /// <summary>
    /// The server's <c>X-Correlation-Id</c> for the failed request: the trace id its console log prints, so
    /// an operator can quote it and find the entry. Null when the response carried none (for example a
    /// proxy's error page); never guessed.
    /// </summary>
    public string? CorrelationId { get; } = correlationId;

    /// <summary>
    /// Set when the API refused a sensitive operation because the sign-in was too weak or too old (RFC 9470 step-up);
    /// null for every other failure.
    /// </summary>
    public StepUpChallenge? StepUp { get; } = stepUp;

    /// <summary>
    /// Set when the API refused a sensitive operation because it needs a second administrator's approval first
    /// (two-person approval); null for every other failure.
    /// </summary>
    public ApprovalChallenge? Approval { get; } = approval;
}

/// <summary>What a two-person approval refusal names: the operation and what it acts on.</summary>
/// <param name="Operation">The operation key, for example <c>bulk-revoke</c>.</param>
/// <param name="TargetId">The target's id; null for creating an intermediate issuer.</param>
public sealed record ApprovalChallenge(string Operation, string? TargetId);

/// <summary>Turns a failed response into an <see cref="ApiProblemException"/> carrying its problem body.</summary>
internal static class ApiResponseExtensions
{
    /// <summary>
    /// Replaces <c>EnsureSuccessStatusCode</c>: a failure keeps the server's title, detail and
    /// violations rather than collapsing to "Response status code does not indicate success".
    /// </summary>
    public static async Task EnsureSuccessOrThrowAsync(this HttpResponseMessage response, CancellationToken cancellationToken = default)
    {
        if (response.IsSuccessStatusCode) return;

        ProblemBody? problem = null;
        try
        {
            problem = await response.Content.ReadFromJsonAsync<ProblemBody>(cancellationToken);
        }
        catch (Exception)
        {
            // A non-JSON error body (a proxy's HTML page, an empty 500) still has to surface as a
            // problem, just without detail.
        }

        throw new ApiProblemException(
            response.StatusCode,
            problem?.Title ?? $"Request failed ({(int)response.StatusCode})",
            problem?.Detail ?? problem?.ValidationMessages(),
            problem?.PolicyName,
            problem?.VersionNumber,
            problem?.Violations ?? [],
            response.Headers.TryGetValues("X-Correlation-Id", out var ids) ? ids.FirstOrDefault() : null,
            response.Headers.TryGetValues("WWW-Authenticate", out var challenges) ? StepUpChallenge.TryParse(challenges) : null,
            problem is { Title: "Approval required", Operation: { Length: > 0 } operation } ? new ApprovalChallenge(operation, problem.TargetId) : null);
    }

    private sealed class ProblemBody
    {
        [JsonPropertyName("title")] public string? Title { get; init; }
        [JsonPropertyName("detail")] public string? Detail { get; init; }
        [JsonPropertyName("policyName")] public string? PolicyName { get; init; }
        [JsonPropertyName("versionNumber")] public int? VersionNumber { get; init; }
        [JsonPropertyName("violations")] public List<IssuancePolicyViolation>? Violations { get; init; }
        [JsonPropertyName("errors")] public Dictionary<string, string[]>? Errors { get; init; }
        [JsonPropertyName("operation")] public string? Operation { get; init; }
        [JsonPropertyName("targetId")] public string? TargetId { get; init; }

        /// <summary>The messages of a validation problem ("errors" by field), one per line; null when there are none.</summary>
        public string? ValidationMessages()
        {
            var messages = Errors?.Values.SelectMany(m => m).Where(m => !string.IsNullOrWhiteSpace(m)).Distinct().ToList();
            return messages is { Count: > 0 } ? string.Join(" ", messages) : null;
        }
    }
}
