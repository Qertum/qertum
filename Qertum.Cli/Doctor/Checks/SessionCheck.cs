using System.Net;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>The one place the token is first sent: <c>GET /v1/me/access</c> must accept it.</summary>
internal sealed class SessionCheck : IDoctorCheck
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public string Id => "session";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (context.Token is null)
            return DoctorResult.Skip(Id, context.TokenProblem ?? "not logged in");
        if (!context.Shared.ApiReachable || context.ApiUrl is null)
            return DoctorResult.Skip(Id, "needs the api check to pass");

        var uri = DoctorUrls.Combine(context.ApiUrl, "/v1/me/access");
        var response = await DoctorHttp.GetAsync(context, uri, context.Token, 1 << 20, ct);
        if (!response.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(response, uri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (response.Status == HttpStatusCode.Unauthorized)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the server rejected the token (expired, or issued for another audience or issuer)",
                notVerified: ["your permissions"], hint: "run 'qca auth login' again");
        if (response.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/me/access answered {(int)response.Status!.Value} for a token");

        MyAccessResponse? access;
        try
        {
            access = JsonSerializer.Deserialize<MyAccessResponse>(response.Body, Web);
        }
        catch (JsonException)
        {
            access = null;
        }

        if (access is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "GET /v1/me/access answered something that is not an access listing");

        context.Shared.Access = access;
        context.Shared.SessionAccepted = true;
        var granted = access.Permissions.Count(p => p.Granted);
        var roles = access.Roles.Count == 0 ? "none" : string.Join(", ", access.Roles);
        return DoctorResult.Of(Id, DoctorStatus.Pass, $"the server accepts this token; roles: {roles}; admin: {(access.IsAdmin ? "yes" : "no")}",
            verified: ["the token was accepted by GET /v1/me/access", $"{granted} of {access.Permissions.Count} permissions are granted to it"],
            notVerified: ["that the token stays valid (its expiry is read locally)"]);
    }
}
