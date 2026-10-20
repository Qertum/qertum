using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Crypto;

public sealed class PairedAlgorithmTests
{
    public static TheoryData<CertificateKeyAlgorithm, string, CertificateKeyAlgorithm, CertificateKeyAlgorithm> Pairs => new()
    {
        { CertificateKeyAlgorithm.PairMlDsa44MlKem512, "PAIR-ML-DSA-44-ML-KEM-512", CertificateKeyAlgorithm.MlDsa44, CertificateKeyAlgorithm.MlKem512 },
        { CertificateKeyAlgorithm.PairMlDsa65MlKem768, "PAIR-ML-DSA-65-ML-KEM-768", CertificateKeyAlgorithm.MlDsa65, CertificateKeyAlgorithm.MlKem768 },
        { CertificateKeyAlgorithm.PairMlDsa87MlKem1024, "PAIR-ML-DSA-87-ML-KEM-1024", CertificateKeyAlgorithm.MlDsa87, CertificateKeyAlgorithm.MlKem1024 }
    };

    [Theory]
    [MemberData(nameof(Pairs))]
    public void ThePairs_HaveTheirWireNameFamilyAndComponents(
        CertificateKeyAlgorithm algorithm, string wireName, CertificateKeyAlgorithm first, CertificateKeyAlgorithm second)
    {
        Assert.Equal(wireName, algorithm.ToCanonicalString());
        Assert.Equal(algorithm, CertificateKeyAlgorithmExtensions.Parse(wireName));
        Assert.Equal(algorithm, CertificateKeyAlgorithmExtensions.Parse(wireName.ToLowerInvariant()));
        Assert.Equal(AlgorithmFamily.Pair, algorithm.GetFamily());
        Assert.True(algorithm.IsPaired());
        // A pair holds an encryption-only key, so it can never be a CA key.
        Assert.False(algorithm.CanSign());
        Assert.Equal((first, second), PairedAlgorithms.For(algorithm));
        Assert.Equal(first, PairedAlgorithms.Leg(algorithm, secondLeg: false));
        Assert.Equal(second, PairedAlgorithms.Leg(algorithm, secondLeg: true));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, CertificateKeyAlgorithm.EcdsaP256, CertificateKeyAlgorithm.MlDsa65)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384, CertificateKeyAlgorithm.EcdsaP384, CertificateKeyAlgorithm.MlDsa87)]
    public void TheHybridRows_AreUnchanged_AndHybridCanStillSign(
        CertificateKeyAlgorithm algorithm, CertificateKeyAlgorithm first, CertificateKeyAlgorithm second)
    {
        Assert.True(algorithm.IsPaired());
        Assert.Equal(AlgorithmFamily.Hybrid, algorithm.GetFamily());
        Assert.True(algorithm.CanSign());
        Assert.Equal((first, second), PairedAlgorithms.For(algorithm));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65)]
    [InlineData(CertificateKeyAlgorithm.MlKem768)]
    public void ASingleCertificateAlgorithm_IsNotPaired_AndIsItsOwnLeg(CertificateKeyAlgorithm algorithm)
    {
        Assert.False(algorithm.IsPaired());
        Assert.Throws<ArgumentException>(() => PairedAlgorithms.For(algorithm));
        Assert.Equal(algorithm, PairedAlgorithms.Leg(algorithm, secondLeg: false));
        Assert.Equal(algorithm, PairedAlgorithms.Leg(algorithm, secondLeg: true));
    }

    // Appended after the last ML-KEM value so no persisted or compiled ordinal moves.
    [Fact]
    public void ThePairValues_AreAppendedSoNoExistingOrdinalMoves()
    {
        Assert.Equal(30, (int)CertificateKeyAlgorithm.MlKem1024);
        Assert.Equal(31, (int)CertificateKeyAlgorithm.PairMlDsa44MlKem512);
        Assert.Equal(32, (int)CertificateKeyAlgorithm.PairMlDsa65MlKem768);
        Assert.Equal(33, (int)CertificateKeyAlgorithm.PairMlDsa87MlKem1024);
    }

    [Fact]
    public void EveryValue_RoundTripsThroughItsCanonicalName()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
            Assert.Equal(algorithm, CertificateKeyAlgorithmExtensions.Parse(algorithm.ToCanonicalString()));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa44MlKem512)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa87MlKem1024)]
    public async Task APair_IsStoredAsItsName_NoColumnLimitCutsTheLongestOne(CertificateKeyAlgorithm algorithm)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.MigrateAsync(ct);

        db.CertificateRequests.Add(new CertificateRequest { CommonName = "pair.example.test", RequestedBy = "test", KeyAlgorithm = algorithm });
        await db.SaveChangesAsync(ct);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT \"KeyAlgorithm\" FROM \"CertificateRequests\"";
        Assert.Equal(algorithm.ToCanonicalString(), (string?)await command.ExecuteScalarAsync(ct));
        db.ChangeTracker.Clear();
        Assert.Equal(algorithm, (await db.CertificateRequests.SingleAsync(ct)).KeyAlgorithm);
    }
}
