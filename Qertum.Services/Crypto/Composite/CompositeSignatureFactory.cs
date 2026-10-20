using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// Lets BouncyCastle's certificate, CRL, OCSP and PKCS#10 builders sign with a composite key. The
/// algorithm identifier is the composite OID with parameters absent (§5), and the X.509 context is
/// empty.
/// </summary>
public sealed class CompositeSignatureFactory(CompositePrivateKey privateKey, SecureRandom? random = null) : ISignatureFactory
{
    public object AlgorithmDetails { get; } = new AlgorithmIdentifier(privateKey.Algorithm.Oid);

    public IStreamCalculator<IBlockResult> CreateCalculator()
    {
        var signer = new CompositeSigner(privateKey.Algorithm);
        signer.Init(true, new ParametersWithRandom(privateKey, random ?? new SecureRandom()));
        return new DefaultSignatureCalculator(signer);
    }
}

/// <summary>
/// Verifies a structure signed under a composite algorithm. A structure whose signature algorithm is
/// not exactly this key's composite OID (with parameters absent) never verifies.
/// </summary>
public sealed class CompositeVerifierProvider(CompositePublicKey publicKey) : IVerifierFactoryProvider
{
    public IVerifierFactory CreateVerifierFactory(object algorithmDetails) =>
        new VerifierFactory(publicKey, (AlgorithmIdentifier)algorithmDetails);

    private sealed class VerifierFactory(CompositePublicKey publicKey, AlgorithmIdentifier algorithm) : IVerifierFactory
    {
        public object AlgorithmDetails => algorithm;

        public IStreamCalculator<IVerifier> CreateCalculator()
        {
            var matches = algorithm.Algorithm.Equals(publicKey.Algorithm.Oid) && algorithm.Parameters is null;
            var signer = new CompositeSigner(publicKey.Algorithm);
            signer.Init(false, publicKey);
            return matches ? new DefaultVerifierCalculator(signer) : new RejectingCalculator();
        }
    }

    private sealed class RejectingCalculator : IStreamCalculator<IVerifier>, IVerifier
    {
        public Stream Stream { get; } = Stream.Null;
        public IVerifier GetResult() => this;
        public bool IsVerified(byte[] data) => false;
        public bool IsVerified(byte[] source, int off, int length) => false;
    }
}
