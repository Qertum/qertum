using System.Net;
using Qertum.Services;

namespace Qertum.Tests.Engineering;

public sealed class StepUpChallengeTests
{
    private const string Header =
        "Bearer error=\"insufficient_user_authentication\", error_description=\"A recent second-factor sign-in is required\", acr_values=\"mfa\", max_age=\"300\"";

    [Fact]
    public void AStepUpChallenge_IsParsed()
    {
        var challenge = StepUpChallenge.TryParse([Header]);

        Assert.Equal(new StepUpChallenge("mfa", 300), challenge);
    }

    [Theory]
    [InlineData("Bearer realm=\"qertum\"")]
    [InlineData("Bearer error=\"invalid_token\"")]
    [InlineData("Basic error=\"insufficient_user_authentication\"")]
    [InlineData("")]
    public void AnythingElse_IsNotAChallenge(string header) => Assert.Null(StepUpChallenge.TryParse([header]));

    [Fact]
    public void AMissingOrMalformedParameter_IsNull_NotAnError()
    {
        var challenge = StepUpChallenge.TryParse(["Bearer error=\"insufficient_user_authentication\", max_age=\"soon\""]);

        Assert.Equal(new StepUpChallenge(null, null), challenge);
    }

    [Fact]
    public void ANonPositiveMaxAge_IsNull() =>
        Assert.Equal(new StepUpChallenge("mfa", null),
            StepUpChallenge.TryParse(["Bearer error=\"insufficient_user_authentication\", acr_values=\"mfa\", max_age=\"0\""]));

    [Fact]
    public void TheChallengeIsFoundAmongSeveralHeaderValues() =>
        Assert.NotNull(StepUpChallenge.TryParse(["Negotiate", Header]));

    [Fact]
    public async Task AFailedResponseWithTheHeader_ThrowsAnExceptionCarryingTheChallenge()
    {
        var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("""{"title":"Step-up authentication required","detail":"The last sign-in is too old for this operation."}""",
                    System.Text.Encoding.UTF8, "application/json")
            };
            response.Headers.TryAddWithoutValidation("WWW-Authenticate", Header);
            return response;
        });
        var client = new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") });

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetAuditCheckpointAsync(TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        Assert.Equal(new StepUpChallenge("mfa", 300), ex.StepUp);
    }

    [Fact]
    public async Task AnOrdinary401_HasNoChallenge()
    {
        var client = new CertificateRequestsApiClient(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized)))
            { BaseAddress = new Uri("https://api.test/") });

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetAuditCheckpointAsync(TestContext.Current.CancellationToken));

        Assert.Null(ex.StepUp);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
