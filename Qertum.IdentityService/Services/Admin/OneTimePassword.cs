using System.Security.Cryptography;

namespace Qertum.IdentityService.Services.Admin;

/// <summary>Server-generated password for a new or reset account; the user must change it at first sign-in.</summary>
public static class OneTimePassword
{
    public const int Length = 20;

    // No 0/O/1/l/I: the password is read off a screen and typed by hand.
    public const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    public static string Generate() => RandomNumberGenerator.GetString(Alphabet, Length);
}
