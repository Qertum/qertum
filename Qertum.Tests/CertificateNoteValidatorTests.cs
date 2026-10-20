using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Validators;

namespace Qertum.Tests;

public sealed class CertificateNoteValidatorTests
{
    private static readonly SaveCertificateNoteRequestValidator Validator = new();

    private static bool Valid(string? body) => Validator.Validate(new SaveCertificateNoteRequest { Body = body! }).IsValid;

    [Theory]
    [InlineData("Renewed after the outage, see OPS-4711.")]
    [InlineData("line one\nline two")]
    [InlineData("line one\r\nline two")]
    [InlineData("column\tseparated")]
    public void PlainText_IsAccepted(string body) => Assert.True(Valid(body));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\n\n")]
    public void AnEmptyNote_IsRefused(string body) => Assert.False(Valid(body));

    [Fact]
    public void ALengthOfExactlyTheLimit_IsAccepted_AndOneMoreIsRefused()
    {
        Assert.True(Valid(new string('a', CertificateNote.MaxBodyLength)));
        Assert.False(Valid(new string('a', CertificateNote.MaxBodyLength + 1)));
    }

    [Fact]
    public void TheLimit_CountsTheTrimmedText() =>
        Assert.True(Valid("   " + new string('a', CertificateNote.MaxBodyLength) + "   "));

    [Theory]
    [InlineData("\u001b[2J clear the screen")]
    [InlineData("nul\0byte")]
    [InlineData("bell\a")]
    public void ControlCharactersOtherThanBreaksAndTabs_AreRefused(string body) => Assert.False(Valid(body));

    [Fact]
    public void AKeyMarker_IsRefused() => Assert.False(Valid("see -----BEGIN PRIVATE KEY----- below"));

    [Theory]
    [InlineData("  hello  ", "hello")]
    [InlineData("a\r\nb\r\nc", "a\nb\nc")]
    [InlineData("ok\rFORGED", "ok\nFORGED")]
    [InlineData("a\r\nb\rc\nd", "a\nb\nc\nd")]
    public void NormalizeBody_TrimsAndUsesLineFeeds(string input, string expected) =>
        Assert.Equal(expected, CertificateNote.NormalizeBody(input));

    [Fact]
    public async Task ANote_RoundTripsThroughTheDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        host.Db.CertificateNotes.Add(new CertificateNote
        {
            RequestId = request.Id, Body = "hello\nworld", AuthorSubject = "sub-alice", AuthorName = "Alice",
            CreatedAtUtc = host.Now, UpdatedAtUtc = host.Now
        });
        await host.Db.SaveChangesAsync(ct);
        host.Db.ChangeTracker.Clear();

        var stored = await host.Db.CertificateNotes.SingleAsync(ct);

        Assert.Equal(request.Id, stored.RequestId);
        Assert.Equal("hello\nworld", stored.Body);
        Assert.Equal("sub-alice", stored.AuthorSubject);
        Assert.Equal("Alice", stored.AuthorName);
    }
}
