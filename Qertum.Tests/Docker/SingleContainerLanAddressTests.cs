using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Qertum.Tests.IdpInterop;

namespace Qertum.Tests.Docker;

/// <summary>
/// The single-container image as a homelab runs it: <c>QERTUM_HOST</c> is this machine's LAN address, not
/// localhost, and every port is published on another host port with the matching <c>*_PORT</c> advertised
/// (Unraid: <c>-p 9080:8080 -e WEB_PORT=9080</c> and so on). A browser signs in through the identity service at
/// that address and lands in the web UI, which must then reach the API inside the container. Until 1.0.0-rc5 the
/// web UI called the API on the advertised port (<c>localhost:9082</c>) and every page failed with
/// "Connection refused"; localhost-only tests on the default ports could not see it.
/// </summary>
/// <remarks>
/// Needs Docker and a non-loopback IPv4 address; skipped otherwise. Builds the image from this tree unless
/// <c>QERTUM_TEST_SINGLE_IMAGE</c> names one (CI builds it in an earlier step). Runs in CI's Docker job only.
/// </remarks>
public sealed partial class SingleContainerLanAddressTests
{
    private const string Admin = "admin";
    private static readonly TimeSpan HealthyWithin = TimeSpan.FromMinutes(3);

    [Fact]
    public async Task SignInOverTheLanAddress_WithRemappedPorts_ReachesTheWebUiAndTheApi()
    {
        var ct = TestContext.Current.CancellationToken;
        Assert.SkipUnless(await DockerContainer.IsAvailableAsync(), "Docker is not available.");
        var lan = LanAddress();
        Assert.SkipWhen(lan is null, "This machine has no non-loopback IPv4 address.");
        var host = lan!.ToString();

        var image = await ImageAsync();
        var (web, identity, api, acme) = (FreePort(lan), FreePort(lan), FreePort(lan), FreePort(lan));
        var password = "Lan-" + Guid.NewGuid().ToString("N")[..16] + "!1a";
        await using var container = await DockerContainer.StartAsync("qertum-lan",
        [
            "-e", $"QERTUM_HOST={host}",
            "-e", $"WEB_PORT={web}", "-e", $"IDENTITY_PORT={identity}", "-e", $"API_PORT={api}", "-e", $"ACME_PORT={acme}",
            "-e", $"IdentityService__SeedAdminPassword={password}",
            "-p", $"{host}:{web}:8080", "-p", $"{host}:{identity}:8081", "-p", $"{host}:{api}:8082", "-p", $"{host}:{acme}:8083",
            image,
        ]);

        try
        {
            await WaitHealthyAsync(container, ct);
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true, CookieContainer = new CookieContainer() };
            using var browser = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            var webUrl = $"http://{host}:{web}";
            var identityUrl = $"http://{host}:{identity}";

            // The identity service advertises the LAN address and the published port.
            using (var discovery = JsonDocument.Parse(await browser.GetStringAsync($"{identityUrl}/.well-known/openid-configuration", ct)))
                Assert.Equal($"{identityUrl}/", discovery.RootElement.GetProperty("issuer").GetString());

            // Browse to the web UI: it sends the browser to the identity service at the same address.
            var authorize = await RedirectAsync(browser, HttpMethod.Get, $"{webUrl}/", null, ct);
            Assert.StartsWith($"{identityUrl}/connect/authorize", authorize, StringComparison.Ordinal);
            Assert.Contains("redirect_uri=" + Uri.EscapeDataString($"{webUrl}/signin-oidc"), authorize, StringComparison.Ordinal);

            // Sign in with the seeded administrator.
            var login = Absolute(identityUrl, await RedirectAsync(browser, HttpMethod.Get, authorize, null, ct));
            var loginPage = await browser.GetStringAsync(login, ct);
            var form = HiddenInputs(loginPage);
            form["Input.Username"] = Admin;
            form["Input.Password"] = password;
            var back = Absolute(identityUrl, await RedirectAsync(browser, HttpMethod.Post, login, form, ct));

            // The identity service sends the code back to the web UI (response_mode=query), which signs the user in
            // and, before rendering, asks the API whether a CA exists. With none, an administrator is sent to
            // onboarding: the browser only gets there when the web UI reached the API inside the container.
            var (page, chain) = await FollowAsync(browser, back, ct);
            Assert.True(chain.Any(url => url.StartsWith($"{webUrl}/signin-oidc?", StringComparison.Ordinal)),
                $"the code never came back to {webUrl}/signin-oidc; redirects: {string.Join(" -> ", chain)}");
            Assert.True(chain[^1] == $"{webUrl}/onboarding",
                $"the web UI did not reach the API (no onboarding redirect); redirects: {string.Join(" -> ", chain)}; page: {Text(page)}");

            // The API and ACME answer on their published ports, and ACME advertises the LAN address.
            using var apiResponse = await browser.GetAsync($"http://{host}:{api}/v1/ca/status", ct);
            Assert.True((int)apiResponse.StatusCode < 500, $"API on the published port answered {(int)apiResponse.StatusCode}");
            var directory = await browser.GetStringAsync($"http://{host}:{acme}/acme/directory", ct);
            Assert.Contains($"http://{host}:{acme}/acme/", directory, StringComparison.Ordinal);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"{ex.Message}\n--- container log (tail) ---\n{Tail(await container.LogsAsync(), 60)}", ex);
        }
    }

    /// <summary>The IPv4 address this machine uses towards other networks (a UDP connect picks the route; nothing is sent).</summary>
    internal static IPAddress? LanAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(IPAddress.Parse("192.0.2.1"), 9);
            if (socket.LocalEndPoint is IPEndPoint { Address: var routed } && !IPAddress.IsLoopback(routed) && !routed.Equals(IPAddress.Any))
                return routed;
        }
        catch (SocketException)
        {
            // No default route: fall back to an interface with a gateway.
        }

        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(nic => nic.GetIPProperties())
            .Where(ip => ip.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
            .SelectMany(ip => ip.UnicastAddresses)
            .Select(unicast => unicast.Address)
            .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address));
    }

    private static int FreePort(IPAddress address)
    {
        using var listener = new TcpListener(address, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task<string> ImageAsync()
    {
        var given = Environment.GetEnvironmentVariable("QERTUM_TEST_SINGLE_IMAGE");
        if (!string.IsNullOrWhiteSpace(given))
            return given;

        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "Qertum.sln")))
            root = root.Parent;
        Assert.NotNull(root);
        const string tag = "qertum-single:lan-test";
        var build = await DockerContainer.RunAsync(TimeSpan.FromMinutes(20),
            "build", "-q", "-f", Path.Combine(root.FullName, "deploy", "single-container", "Dockerfile"), "-t", tag, root.FullName);
        Assert.True(build.ExitCode == 0, $"docker build failed: {Tail(build.Output, 40)}");
        return tag;
    }

    private static async Task WaitHealthyAsync(DockerContainer container, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + HealthyWithin;
        var state = "";
        while (DateTimeOffset.UtcNow < deadline)
        {
            state = (await DockerContainer.RunAsync(TimeSpan.FromSeconds(20), "inspect", "-f", "{{.State.Health.Status}}", container.Name)).Output.Trim();
            if (state == "healthy")
                return;
            await Task.Delay(TimeSpan.FromSeconds(3), ct);
        }

        throw new TimeoutException($"the container was not healthy within {HealthyWithin} (last state: {state})");
    }

    /// <summary>Sends the request and returns the Location of the redirect it must answer with.</summary>
    private static async Task<string> RedirectAsync(HttpClient browser, HttpMethod method, string url, Dictionary<string, string>? form, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        if (form is not null)
            request.Content = new FormUrlEncodedContent(form);
        using var response = await browser.SendAsync(request, ct);
        var location = response.Headers.Location?.ToString();
        if ((int)response.StatusCode is < 300 or > 399 || location is null)
            throw new InvalidOperationException($"{method} {url} answered {(int)response.StatusCode} without a redirect: {Text(await response.Content.ReadAsStringAsync(ct))}");
        return location;
    }

    /// <summary>Follows GET redirects like a browser until a page answers; returns it and the URLs visited.</summary>
    private static async Task<(string Page, List<string> Chain)> FollowAsync(HttpClient browser, string url, CancellationToken ct)
    {
        var chain = new List<string>();
        for (var hop = 0; hop < 10; hop++)
        {
            chain.Add(url);
            using var response = await browser.GetAsync(url, ct);
            if ((int)response.StatusCode is >= 300 and <= 399 && response.Headers.Location is { } next)
            {
                url = Absolute(new Uri(url).GetLeftPart(UriPartial.Authority), next.ToString());
                continue;
            }

            var page = await response.Content.ReadAsStringAsync(ct);
            if (response.StatusCode != HttpStatusCode.OK)
                throw new InvalidOperationException($"GET {url} answered {(int)response.StatusCode}; redirects: {string.Join(" -> ", chain)}; page: {Text(page)}");
            return (page, chain);
        }

        throw new InvalidOperationException($"more than 10 redirects: {string.Join(" -> ", chain)}");
    }

    private static string Absolute(string origin, string location) =>
        Uri.TryCreate(location, UriKind.Absolute, out var absolute) && absolute.Scheme.StartsWith("http", StringComparison.Ordinal)
            ? absolute.ToString()
            : origin + (location.StartsWith('/') ? location : "/" + location);

    private static Dictionary<string, string> HiddenInputs(string html) =>
        HiddenInput().Matches(html)
            .GroupBy(match => WebUtility.HtmlDecode(match.Groups["name"].Value))
            .ToDictionary(group => group.Key, group => WebUtility.HtmlDecode(group.First().Groups["value"].Value));

    private static string Text(string html) => Tail(Regex.Replace(html, "<[^>]+>", " "), 15);

    private static string Tail(string text, int lines) =>
        string.Join('\n', text.Split('\n').TakeLast(lines));

    [GeneratedRegex(@"<input[^>]*type=""hidden""[^>]*name=""(?<name>[^""]+)""[^>]*value=""(?<value>[^""]*)""|<input[^>]*name=""(?<name>[^""]+)""[^>]*type=""hidden""[^>]*value=""(?<value>[^""]*)""", RegexOptions.IgnoreCase)]
    private static partial Regex HiddenInput();

}
