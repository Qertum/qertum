using Qertum.Services;

namespace Qertum.Tests;

public sealed class Base64UrlTextTests
{
    // 0xFB 0xFF 0xBF encodes as "+/+/" in standard base64 and "-_-_" in base64url, so it
    // exercises both substituted characters in one value.
    private static readonly byte[] BothSubstitutedChars = [0xFB, 0xFF, 0xBF];

    [Fact]
    public void Encode_EmitsUnpaddedBase64Url()
    {
        Assert.Equal("-_-_", Base64UrlText.Encode(BothSubstitutedChars));
        Assert.Equal("AQID", Base64UrlText.Encode([1, 2, 3]));
        Assert.Equal("AQI", Base64UrlText.Encode([1, 2]));
    }

    [Fact]
    public void Decode_AcceptsBase64Url()
    {
        Assert.Equal(BothSubstitutedChars, Base64UrlText.Decode("-_-_"));
        Assert.Equal([1, 2], Base64UrlText.Decode("AQI"));
    }

    // EST carries a standard-base64 PKCS#10 body (RFC 7030 §4.2.1), so '+' and '/' reach this
    // decoder on every real EST enrollment. A strict base64url decoder would reject them.
    [Fact]
    public void Decode_AcceptsStandardBase64Alphabet()
    {
        Assert.Equal(BothSubstitutedChars, Base64UrlText.Decode("+/+/"));
    }

    [Fact]
    public void Decode_AcceptsPaddedAndUnpaddedInput()
    {
        Assert.Equal([1, 2], Base64UrlText.Decode("AQI="));
        Assert.Equal([1, 2], Base64UrlText.Decode("AQI"));
        Assert.Equal([1], Base64UrlText.Decode("AQ=="));
        Assert.Equal([1], Base64UrlText.Decode("AQ"));
    }

    [Fact]
    public void EncodeThenDecode_RoundTrips()
    {
        var bytes = new byte[256];
        for (var i = 0; i < bytes.Length; i++) bytes[i] = (byte)i;
        Assert.Equal(bytes, Base64UrlText.Decode(Base64UrlText.Encode(bytes)));
    }
}
