using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// Composite ML-DSA Sign and Verify (draft -19 §3.2, §3.3). Buffers the message, builds
/// <c>M' = Prefix || Label || len(ctx) || ctx || PH(M)</c>, signs M' with ML-DSA (context = Label)
/// and with the traditional algorithm, and outputs <c>mldsaSig || tradSig</c>. A signature verifies
/// only if both components do.
/// </summary>
public sealed class CompositeSigner : ISigner
{
    private static readonly byte[] Prefix = "CompositeAlgorithmSignatures2025"u8.ToArray();

    private readonly CompositeAlgorithm _algorithm;
    private readonly byte[] _context;
    private readonly byte[] _label;
    private readonly MemoryStream _message = new();
    private CompositePrivateKey? _privateKey;
    private CompositePublicKey? _publicKey;
    private SecureRandom? _random;

    /// <param name="context">The application context; empty for X.509 (certificates, CRLs, OCSP, CSRs).</param>
    public CompositeSigner(CompositeAlgorithm algorithm, byte[]? context = null)
    {
        if (context is { Length: > 255 })
            throw new ArgumentException("A composite ML-DSA context is at most 255 bytes.", nameof(context));
        _algorithm = algorithm;
        _context = context ?? [];
        _label = Encoding.ASCII.GetBytes(algorithm.Label);
    }

    public string AlgorithmName => _algorithm.Name;

    public void Init(bool forSigning, ICipherParameters parameters)
    {
        _random = null;
        if (parameters is ParametersWithRandom withRandom)
        {
            _random = withRandom.Random;
            parameters = withRandom.Parameters;
        }

        _privateKey = null;
        _publicKey = null;
        if (forSigning)
        {
            _privateKey = parameters as CompositePrivateKey
                ?? throw new ArgumentException("Signing needs a CompositePrivateKey.", nameof(parameters));
            if (_privateKey.Algorithm != _algorithm)
                throw new ArgumentException($"The key is {_privateKey.Algorithm.Name}, not {_algorithm.Name}.", nameof(parameters));
        }
        else
        {
            _publicKey = parameters as CompositePublicKey
                ?? throw new ArgumentException("Verification needs a CompositePublicKey.", nameof(parameters));
            if (_publicKey.Algorithm != _algorithm)
                throw new ArgumentException($"The key is {_publicKey.Algorithm.Name}, not {_algorithm.Name}.", nameof(parameters));
        }

        Reset();
    }

    public void Update(byte input) => _message.WriteByte(input);

    public void BlockUpdate(byte[] input, int inOff, int inLen) => _message.Write(input, inOff, inLen);

    public void BlockUpdate(ReadOnlySpan<byte> input) => _message.Write(input);

    public int GetMaxSignatureSize() => _algorithm.MlDsaSignatureLength + _algorithm.Traditional switch
    {
        CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15 => _algorithm.RsaKeyBits / 8,
        // DER Ecdsa-Sig-Value: two INTEGERs of at most (field bytes + 1) plus headers; 139 covers P-521.
        CompositeTraditional.Ecdsa => 139,
        CompositeTraditional.Ed25519 => 64,
        CompositeTraditional.Ed448 => 114,
        _ => throw new InvalidOperationException()
    };

    public byte[] GenerateSignature()
    {
        var privateKey = _privateKey ?? throw new InvalidOperationException("Not initialised for signing.");
        var random = _random ?? new SecureRandom();
        var messageRepresentative = MessageRepresentative();

        var mlDsa = new MLDsaSigner(_algorithm.MlDsa, deterministic: false);
        mlDsa.Init(true, new ParametersWithContext(new ParametersWithRandom(privateKey.MlDsa, random), _label));
        mlDsa.BlockUpdate(messageRepresentative);
        var mlDsaSignature = mlDsa.GenerateSignature();

        var traditional = CompositeTraditionalKeys.CreateSigner(_algorithm);
        traditional.Init(true, CompositeTraditionalKeys.SigningParameters(privateKey.Traditional, random));
        traditional.BlockUpdate(messageRepresentative);
        var traditionalSignature = traditional.GenerateSignature();

        Reset();
        return [.. mlDsaSignature, .. traditionalSignature];
    }

    public bool VerifySignature(byte[] signature)
    {
        var publicKey = _publicKey ?? throw new InvalidOperationException("Not initialised for verification.");
        try
        {
            var split = _algorithm.MlDsaSignatureLength;
            if (signature.Length <= split)
                return false;

            var messageRepresentative = MessageRepresentative();
            var mlDsaValid = VerifyComponent(
                new MLDsaSigner(_algorithm.MlDsa, deterministic: false),
                new ParametersWithContext(publicKey.MlDsa, _label),
                messageRepresentative, signature[..split]);
            var traditionalValid = VerifyComponent(
                CompositeTraditionalKeys.CreateSigner(_algorithm),
                publicKey.Traditional,
                messageRepresentative, signature[split..]);

            // §3.3: valid if and only if every component is. Both are evaluated either way.
            return mlDsaValid & traditionalValid;
        }
        finally
        {
            Reset();
        }
    }

    public void Reset() => _message.SetLength(0);

    private static bool VerifyComponent(ISigner signer, ICipherParameters key, byte[] message, byte[] signature)
    {
        try
        {
            signer.Init(false, key);
            signer.BlockUpdate(message);
            return signer.VerifySignature(signature);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or CryptoException or IOException)
        {
            // A component signature that does not even parse (bad DER, wrong length) is invalid,
            // not an error the caller should see.
            return false;
        }
    }

    private byte[] MessageRepresentative()
    {
        var message = _message.ToArray();
        return [.. Prefix, .. _label, (byte)_context.Length, .. _context, .. PreHash(message)];
    }

    private byte[] PreHash(byte[] message)
    {
        switch (_algorithm.PreHash)
        {
            case CompositePreHash.Sha256:
                return Digest(new Sha256Digest(), message);
            case CompositePreHash.Sha512:
                return Digest(new Sha512Digest(), message);
            case CompositePreHash.Shake256With64ByteOutput:
                var shake = new ShakeDigest(256);
                shake.BlockUpdate(message, 0, message.Length);
                var output = new byte[64];
                shake.OutputFinal(output, 0, output.Length);
                return output;
            default:
                throw new InvalidOperationException($"No pre-hash for {_algorithm.PreHash}.");
        }
    }

    private static byte[] Digest(IDigest digest, byte[] message)
    {
        digest.BlockUpdate(message, 0, message.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}
