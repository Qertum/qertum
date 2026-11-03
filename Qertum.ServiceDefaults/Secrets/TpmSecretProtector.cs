using System.Diagnostics;
using System.Security.Cryptography;

namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Wrapping key sealed to a TPM 2.0 device via <c>tpm2-tools</c> — the sealed blob on disk is
/// useless without the same physical TPM to unseal it, unlike <see cref="LocalFileKeySecretProtector"/>
/// where the key file alone is sufficient. No PCR policy binding: sealing is to the TPM's storage
/// hierarchy only, so a routine kernel/firmware update does not turn into an unseal failure.
/// Requires <c>tpm2-tools</c> on PATH and <c>/dev/tpm0</c> or <c>/dev/tpmrm0</c> reachable
/// (passed through explicitly in a containerized deployment).
/// </summary>
public sealed class TpmSecretProtector : ISecretProtector
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    private readonly byte[] _unsealedKey;

    public TpmSecretProtector(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        var secretStorageDir = Path.Combine(dataDirectory, "secret-storage");
        Directory.CreateDirectory(secretStorageDir);
        var sealedBlobPath = Path.Combine(secretStorageDir, "tpm-sealed.blob");

        KeyFileCreation.EnsureExists(sealedBlobPath, SealNewKey);
        _unsealedKey = Unseal(sealedBlobPath);
    }

    public byte[] Protect(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(_unsealedKey, TagSizeBytes);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, NonceSizeBytes);
        ciphertext.CopyTo(result, NonceSizeBytes + TagSizeBytes);
        return result;
    }

    public byte[] Unprotect(byte[] ciphertext)
    {
        if (ciphertext.Length < NonceSizeBytes + TagSizeBytes)
            throw new CryptographicException("Ciphertext is too short to contain a nonce and tag.");

        var nonce = ciphertext.AsSpan(0, NonceSizeBytes);
        var tag = ciphertext.AsSpan(NonceSizeBytes, TagSizeBytes);
        var cipherBytes = ciphertext.AsSpan(NonceSizeBytes + TagSizeBytes);
        var plaintext = new byte[cipherBytes.Length];

        using var aesGcm = new AesGcm(_unsealedKey, TagSizeBytes);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plaintext);
        return plaintext;
    }

    /// <summary>
    /// Probes whether a TPM 2.0 device is reachable and <c>tpm2-tools</c> is installed. Used by
    /// the secret-storage status endpoint to decide whether to offer "Local TPM" in the Web UI,
    /// and by the gated test above to decide whether to run.
    /// </summary>
    public static bool IsAvailable()
    {
        if (!File.Exists("/dev/tpmrm0") && !File.Exists("/dev/tpm0"))
            return false;

        return RunTpm2Tool("tpm2_getcap", "properties-fixed") is { ExitCode: 0 };
    }

    /// <summary>
    /// Seals a new key into <paramref name="blobPath"/> (a temporary path; <see cref="KeyFileCreation"/> renames it into
    /// place). Every intermediate file is named after it, so two processes never share one.
    /// </summary>
    private static void SealNewKey(string blobPath)
    {
        var keyFile = blobPath + ".key";
        var primaryCtx = blobPath + ".primary.ctx";
        var pub = blobPath + ".pub";
        var priv = blobPath + ".priv";
        try
        {
            // The plain key exists on disk only until tpm2_create has sealed it, and only its owner may read it.
            KeyFileCreation.WriteOwnerOnly(keyFile, RandomNumberGenerator.GetBytes(KeySizeBytes));
            Run("tpm2_createprimary", "-C", "o", "-c", primaryCtx);
            Run("tpm2_create", "-C", primaryCtx, "-i", keyFile, "-u", pub, "-r", priv);

            // The sealed blob on disk is (pub, priv) — neither is the plaintext key. Concatenate
            // with length prefixes so Unseal can split them back apart from one file.
            var pubBytes = File.ReadAllBytes(pub);
            var privBytes = File.ReadAllBytes(priv);
            using var ms = new MemoryStream();
            using (var writer = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(pubBytes.Length);
                writer.Write(pubBytes);
                writer.Write(privBytes.Length);
                writer.Write(privBytes);
            }
            File.WriteAllBytes(blobPath, ms.ToArray());
        }
        finally
        {
            foreach (var file in new[] { keyFile, primaryCtx, pub, priv })
                File.Delete(file);
        }
    }

    private static byte[] Unseal(string sealedBlobPath)
    {
        var blob = File.ReadAllBytes(sealedBlobPath);
        using var ms = new MemoryStream(blob);
        using var reader = new BinaryReader(ms);
        var pubBytes = reader.ReadBytes(reader.ReadInt32());
        var privBytes = reader.ReadBytes(reader.ReadInt32());

        var pub = Path.GetTempFileName();
        var priv = Path.GetTempFileName();
        var primaryCtx = Path.GetTempFileName();
        var loadedCtx = Path.GetTempFileName();
        var outFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(pub, pubBytes);
            File.WriteAllBytes(priv, privBytes);

            Run("tpm2_createprimary", "-C", "o", "-c", primaryCtx);
            Run("tpm2_load", "-C", primaryCtx, "-u", pub, "-r", priv, "-c", loadedCtx);
            Run("tpm2_unseal", "-c", loadedCtx, "-o", outFile);

            return File.ReadAllBytes(outFile);
        }
        finally
        {
            foreach (var f in new[] { pub, priv, primaryCtx, loadedCtx, outFile })
                File.Delete(f);
        }
    }

    private static void Run(string tool, params string[] args)
    {
        var result = RunTpm2Tool(tool, args)
            ?? throw new InvalidOperationException($"Failed to start '{tool}'. Is tpm2-tools installed?");

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"'{tool} {string.Join(' ', args)}' exited with code {result.ExitCode}: {result.StdErr}");
        }
    }

    private sealed record ToolResult(int ExitCode, string StdErr);

    private static ToolResult? RunTpm2Tool(string tool, params string[] args)
    {
        try
        {
            // One argv entry per argument: a joined string would split a temp path containing a space.
            var startInfo = new ProcessStartInfo(tool, args)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var process = new Process { StartInfo = startInfo };
            process.Start();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return new ToolResult(process.ExitCode, stderr);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Tool not found on PATH.
            return null;
        }
    }
}
