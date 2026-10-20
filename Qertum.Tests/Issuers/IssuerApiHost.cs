using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

internal sealed class IssuerApiHost : IAsyncDisposable
{
    public IssuerTestKit Kit { get; } = new(createSchema: false);
    public WebApplicationFactory<ApiServiceProgram> Factory { get; }

    public IssuerApiHost(Action<IServiceCollection>? configure = null)
    {
        Factory = new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                Kit.Database.ReplaceDbContext(services);
                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                services.RemoveAll<CaDataOptions>();
                services.AddSingleton(new CaDataOptions { Directory = Kit.CaDataDirectory });
                services.RemoveAll<IssuerStorage>();
                services.AddSingleton(Kit.Storage);
                services.AddSingleton(Kit.DataProtection);
                services.RemoveAll<ICertificateGenerator>();
                services.AddSingleton<ICertificateGenerator>(Kit.Legacy);
                services.RemoveAll<IDistributedCache>();
                services.AddSingleton(Kit.Cache);
                configure?.Invoke(services);
            });
        });
        // Start now: the host migrates the empty database, so tests can seed it straight away.
        using (var scope = Factory.Services.CreateScope())
        {
            // The CA default is PQC stage Enforce; these tests issue ECDSA/RSA certificates, so they start from Off.
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            if (!db.Settings.Any())
            {
                db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
                db.SaveChanges();
            }
        }
    }

    public IIssuerRegistry Registry => Factory.Services.GetRequiredService<IIssuerRegistry>();

    public HttpClient Anonymous() => Factory.CreateClient();

    public HttpClient Admin() => WithAuth("Test");

    /// <summary>A non-admin caller holding <paramref name="role"/>; grant permissions with <see cref="GrantAsync"/>.</summary>
    public HttpClient Role(string role) => WithAuth($"Test-Role {role}");

    public async Task GrantAsync(string role, params string[] permissions)
    {
        await using var db = Kit.Database.CreateContext();
        foreach (var permission in permissions)
            db.RolePermissions.Add(new RolePermission { Role = role, Permission = permission });
        await db.SaveChangesAsync();
    }

    public async Task<IssuerId> DefaultIssuerIdAsync(CancellationToken ct) =>
        (await Registry.GetDefaultAsync(ct))!.Issuer.Id;

    /// <summary>Inserts an Issued (or Revoked) row signed by <paramref name="signer"/> and returns its serial.</summary>
    public async Task<string> SeedIssuedAsync(IssuerId? issuerId, ICertificateGenerator signer, bool revoked, CancellationToken ct,
        string? commonName = null)
    {
        commonName ??= $"{Guid.NewGuid():N}.example";
        var issued = signer.GenerateCertificate(new CertificateRequest { CommonName = commonName, Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off });
        await using var db = Kit.Database.CreateContext();
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = commonName,
            RequestedBy = "seed",
            Type = "WebServer",
            Status = revoked ? CertificateRequestStatus.Revoked : CertificateRequestStatus.Issued,
            CertificatePem = issued.CertificatePem,
            SerialNumber = issued.SerialNumber,
            ValidFrom = issued.ValidFrom,
            ValidTo = issued.ValidTo,
            RevokedAtUtc = revoked ? DateTime.UtcNow : null,
            IssuerId = issuerId
        });
        await db.SaveChangesAsync(ct);
        return issued.SerialNumber;
    }

    /// <summary>A caller with a stable subject, admin unless <paramref name="role"/> says otherwise (see <c>TestAuthHandler</c>).</summary>
    public HttpClient Sub(string subject, string role = "admin") => WithAuth($"Test-Sub {subject} {role}");

    private HttpClient WithAuth(string header)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(header);
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await Factory.DisposeAsync();
        Kit.Dispose();
    }
}
