using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Qertum.IdentityService.Services;

namespace Qertum.Tests;

/// <summary>
/// Boots the real identity provider against a keys directory holding two valid signing
/// certificates, and checks what it does with them.
///
/// Rotation only works if both halves hold: the retiring certificate has to stay published in
/// the JWKS document (or tokens signed under it stop validating the moment a new key appears),
/// and new tokens have to be signed with the replacement (or rotation publishes a key it never
/// uses and the old one still expires underneath it). Neither is something the store can assert
/// on its own — OpenIddict decides — so it is verified here against the running host.
/// </summary>
public sealed class IdentityCertificateRotationHostTests : IDisposable
{
    private const string Authority = "https://idp.test";

    private readonly List<string> _tempDirectories = [];

    [Fact]
    public async Task PublishesEveryValidSigningKeyAndSignsWithTheNewest()
    {
        var dataPath = NewDataPath();
        var keysDir = Path.Combine(dataPath, "keys");
        Directory.CreateDirectory(keysDir);

        var now = DateTimeOffset.UtcNow;

        // The state a rotation leaves behind: an outgoing certificate still inside its overlap
        // window, and its freshly minted replacement.
        var retiring = WriteCertificate(keysDir, "signing-20200101T000000Z.pfx",
            "CN=Qertum IDM Signing", now.AddYears(-5), now.AddDays(60));
        var replacement = WriteCertificate(keysDir, "signing-20260101T000000Z.pfx",
            "CN=Qertum IDM Signing", now.AddDays(-1), now.AddDays(1825));

        using var factory = CreateFactory(dataPath);
        using var client = factory.CreateClient();
        var ct = TestContext.Current.CancellationToken;

        var jwks = await client.GetFromJsonAsync<JsonDocument>("/.well-known/jwks", ct);
        var keys = jwks!.RootElement.GetProperty("keys").EnumerateArray().ToList();

        // x5t is the base64url SHA-1 thumbprint, which maps a JWKS entry back to the file on
        // disk without depending on how OpenIddict derives "kid".
        var thumbprintsByKid = keys
            .Where(k => k.TryGetProperty("x5t", out _) && k.TryGetProperty("kid", out _))
            .ToDictionary(k => k.GetProperty("kid").GetString()!, k => k.GetProperty("x5t").GetString()!);

        var retiringThumbprint = Base64UrlThumbprint(retiring);
        var replacementThumbprint = Base64UrlThumbprint(replacement);

        Assert.Contains(retiringThumbprint, thumbprintsByKid.Values);
        Assert.Contains(replacementThumbprint, thumbprintsByKid.Values);

        // Now issue a token and see which key actually signed it.
        using var tokenResponse = await client.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "qertum-test-m2m",
                ["client_secret"] = "test-m2m-secret",
                ["scope"] = "qertum-api"
            }), ct);

        tokenResponse.EnsureSuccessStatusCode();
        var payload = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>(ct);
        var accessToken = payload!.RootElement.GetProperty("access_token").GetString()!;

        var header = JsonDocument.Parse(Base64UrlDecode(accessToken.Split('.')[0])).RootElement;

        var signingThumbprint = header.TryGetProperty("x5t", out var x5t)
            ? x5t.GetString()!
            : thumbprintsByKid[header.GetProperty("kid").GetString()!];

        Assert.Equal(replacementThumbprint, signingThumbprint);
        Assert.NotEqual(retiringThumbprint, signingThumbprint);
    }

    [Fact]
    public async Task CreatesKeysOnFirstRunAndReusesThemAcrossRestarts()
    {
        var dataPath = NewDataPath();
        var ct = TestContext.Current.CancellationToken;

        string firstRunKid;
        using (var factory = CreateFactory(dataPath))
        using (var client = factory.CreateClient())
        {
            var jwks = await client.GetFromJsonAsync<JsonDocument>("/.well-known/jwks", ct);
            firstRunKid = jwks!.RootElement.GetProperty("keys").EnumerateArray()
                .First().GetProperty("kid").GetString()!;
        }

        // A restart that minted a new key would invalidate every token already issued.
        using (var factory = CreateFactory(dataPath))
        using (var client = factory.CreateClient())
        {
            var jwks = await client.GetFromJsonAsync<JsonDocument>("/.well-known/jwks", ct);
            var kids = jwks!.RootElement.GetProperty("keys").EnumerateArray()
                .Select(k => k.GetProperty("kid").GetString()!).ToList();

            Assert.Contains(firstRunKid, kids);
        }

        Assert.Single(Directory.GetFiles(Path.Combine(dataPath, "keys"), "signing*.pfx"));
    }

    // The periodic check: an IdP that runs past its renewal window mints and publishes the
    // replacement without a restart, and signs new tokens with it.
    [Fact]
    public async Task RunningHost_RotatesWhenTheRenewalWindowOpens()
    {
        var dataPath = NewDataPath();
        var keysDir = Path.Combine(dataPath, "keys");
        Directory.CreateDirectory(keysDir);
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var now = clock.GetUtcNow();
        // Default renew-before is 90 days: not due at start, due two hours later.
        var current = WriteCertificate(keysDir, "signing-20210101T000000Z.pfx",
            "CN=Qertum IDM Signing", now.AddDays(-30), now.AddDays(90).AddHours(1));

        using var factory = CreateFactory(dataPath, clock);
        using var client = factory.CreateClient();
        var ct = TestContext.Current.CancellationToken;
        Assert.Equal([Base64UrlThumbprint(current)], await SigningThumbprintsAsync(client, ct));

        clock.Advance(TimeSpan.FromHours(2));
        var changed = await factory.Services.GetRequiredService<IdentityCertificateRotationService>().CheckOnceAsync(ct);

        Assert.True(changed);
        var thumbprints = await SigningThumbprintsAsync(client, ct);
        Assert.Equal(2, thumbprints.Count);
        Assert.Contains(Base64UrlThumbprint(current), thumbprints);
        var replacement = thumbprints.Single(t => t != Base64UrlThumbprint(current));
        Assert.Equal(replacement, await TokenSigningThumbprintAsync(client, ct));
        Assert.Equal(2, Directory.GetFiles(keysDir, "signing*.pfx").Length);
    }

    [Fact]
    public async Task RunningHost_StopsPublishingAKeyOnceItExpires()
    {
        var dataPath = NewDataPath();
        var keysDir = Path.Combine(dataPath, "keys");
        Directory.CreateDirectory(keysDir);
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var now = clock.GetUtcNow();
        var retiring = WriteCertificate(keysDir, "signing-20210101T000000Z.pfx",
            "CN=Qertum IDM Signing", now.AddYears(-5), now.AddHours(1));
        var replacement = WriteCertificate(keysDir, "signing-20260101T000000Z.pfx",
            "CN=Qertum IDM Signing", now.AddDays(-1), now.AddDays(1825));

        using var factory = CreateFactory(dataPath, clock);
        using var client = factory.CreateClient();
        var ct = TestContext.Current.CancellationToken;
        Assert.Contains(Base64UrlThumbprint(retiring), await SigningThumbprintsAsync(client, ct));

        clock.Advance(TimeSpan.FromHours(2));
        Assert.True(await factory.Services.GetRequiredService<IdentityCertificateRotationService>().CheckOnceAsync(ct));

        Assert.Equal([Base64UrlThumbprint(replacement)], await SigningThumbprintsAsync(client, ct));
    }

    [Fact]
    public async Task RunningHost_CheckWithNothingDue_ChangesNothing()
    {
        var dataPath = NewDataPath();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = CreateFactory(dataPath, clock);
        using var client = factory.CreateClient();
        var ct = TestContext.Current.CancellationToken;
        var before = await SigningThumbprintsAsync(client, ct);

        clock.Advance(TimeSpan.FromDays(1));
        Assert.False(await factory.Services.GetRequiredService<IdentityCertificateRotationService>().CheckOnceAsync(ct));

        Assert.Equal(before, await SigningThumbprintsAsync(client, ct));
        Assert.Single(Directory.GetFiles(Path.Combine(dataPath, "keys"), "signing*.pfx"));
    }

    private static async Task<List<string>> SigningThumbprintsAsync(HttpClient client, CancellationToken ct)
    {
        var jwks = await client.GetFromJsonAsync<JsonDocument>("/.well-known/jwks", ct);
        return jwks!.RootElement.GetProperty("keys").EnumerateArray()
            .Where(k => k.TryGetProperty("use", out var use) && use.GetString() == "sig" && k.TryGetProperty("x5t", out _))
            .Select(k => k.GetProperty("x5t").GetString()!)
            .ToList();
    }

    private static async Task<string> TokenSigningThumbprintAsync(HttpClient client, CancellationToken ct)
    {
        using var tokenResponse = await client.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "qertum-test-m2m",
                ["client_secret"] = "test-m2m-secret",
                ["scope"] = "qertum-api"
            }), ct);
        tokenResponse.EnsureSuccessStatusCode();
        var payload = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>(ct);
        var header = JsonDocument.Parse(Base64UrlDecode(payload!.RootElement.GetProperty("access_token").GetString()!.Split('.')[0])).RootElement;
        if (header.TryGetProperty("x5t", out var x5t)) return x5t.GetString()!;

        var jwks = await client.GetFromJsonAsync<JsonDocument>("/.well-known/jwks", ct);
        var kid = header.GetProperty("kid").GetString();
        return jwks!.RootElement.GetProperty("keys").EnumerateArray()
            .Single(k => k.GetProperty("kid").GetString() == kid).GetProperty("x5t").GetString()!;
    }

    private static X509Certificate2 WriteCertificate(
        string keysDir, string fileName, string subject, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);

        var path = Path.Combine(keysDir, fileName);
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx));

        return X509CertificateLoader.LoadPkcs12FromFile(path, null, X509KeyStorageFlags.Exportable);
    }

    private static string Base64UrlThumbprint(X509Certificate2 certificate) =>
        Base64UrlEncode(certificate.GetCertHash(HashAlgorithmName.SHA1));

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }

    private string NewDataPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-rotation-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirectories.Add(dir);
        return dir;
    }

    private static WebApplicationFactory<IdentityServiceProgram> CreateFactory(string dataPath, TimeProvider? clock = null) =>
        new WebApplicationFactory<IdentityServiceProgram>()
            .WithWebHostBuilder(builder =>
            {
                if (clock is not null)
                    builder.ConfigureTestServices(services => services.AddSingleton(clock));
                builder.UseEnvironment(Environments.Production);
                builder.UseSetting("IdentityService:Authority", Authority);
                builder.UseSetting("IdentityService:DataPath", dataPath);
                builder.UseSetting("IdentityService:DisableTransportSecurity", "true");
                // Needed for the client_credentials token below: the test clients are not
                // seeded unless asked for, because one of them is an admin whose secret is
                // committed to this repository.
                builder.UseSetting("IdentityService:SeedTestClients", "true");
                builder.UseSetting("ConnectionStrings:Identity",
                    $"Data Source={Path.Combine(dataPath, "identity.db")}");
            });

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
