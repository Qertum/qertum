namespace Qertum.Tests.Recovery;

/// <summary>
/// The scripts are shell, so no unit test runs them; this pins the on-disk contract they must keep
/// (names, key spelling, atomic write, preserving the directory on restore) so an edit that drifts from
/// <c>RecoveryRecords</c> fails here. The real check is the manual run in the single-container README.
/// </summary>
public sealed class RecoveryScriptContractTests
{
    private static string Script(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "deploy", "single-container", name);
            if (File.Exists(path))
                return File.ReadAllText(path);
        }

        throw new FileNotFoundException(name);
    }

    [Theory]
    [InlineData("backup.sh")]
    [InlineData("backup.ps1")]
    public void BackupScripts_WriteTheBackupRecord_Atomically(string name)
    {
        var text = Script(name);

        foreach (var key in new[] { "schemaVersion", "completedAtUtc", "archiveName", "sizeBytes", "reportedBy" })
            Assert.Contains($"\\042{key}\\042", text);
        Assert.Contains("last-backup.json.tmp", text);
        Assert.Contains("mv /data/recovery/last-backup.json.tmp /data/recovery/last-backup.json", text);
        Assert.Contains("chmod 755 /data/recovery", text);
        Assert.Contains("chmod 644", text);
    }

    [Theory]
    [InlineData("restore.sh")]
    [InlineData("restore.ps1")]
    public void RestoreScripts_KeepTheRecoveryDirectory_AndWriteAPerformedRecord(string name)
    {
        var text = Script(name);

        foreach (var key in new[] { "schemaVersion", "kind", "completedAtUtc", "archiveName", "reportedBy" })
            Assert.Contains($"\\042{key}\\042", text);
        Assert.Contains("performed", text);
        Assert.DoesNotContain("verified", text.Replace("not verified", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Contains("! -name recovery", text);
        Assert.Contains("--exclude=data/recovery", text);
        Assert.Contains("last-restore.json.tmp", text);
        Assert.Contains("mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json", text);
        // The old clear removed everything, including the recovery directory.
        Assert.DoesNotContain("rm -rf /data/* /data/.[!.]*", text);
    }

    [Theory]
    [InlineData("backup.ps1")]
    [InlineData("restore.ps1")]
    public void PowerShellScripts_FormatTheTimestampWithTheInvariantCulture(string name)
    {
        // The default culture picks the time separator: fi-FI and da-DK write "12.00.03", which the reader
        // refuses, so every record would show as unreadable on those Windows hosts.
        var text = Script(name);

        Assert.Contains("[System.Globalization.CultureInfo]::InvariantCulture", text);
        Assert.DoesNotContain("ToString(\"yyyy-MM-ddTHH:mm:ssZ\")", text);
    }

    [Theory]
    [InlineData("backup.ps1")]
    [InlineData("restore.ps1")]
    public void PowerShellScripts_StopWhenAnArchiveStepFails_BeforeRecordingAnything(string name)
    {
        // PowerShell does not stop on a failing native command, so without a check a partial archive would be
        // recorded as a fresh backup.
        var text = Script(name);

        Assert.Contains("$LASTEXITCODE -ne 0", text);
        var firstCheck = text.IndexOf("$LASTEXITCODE -ne 0", StringComparison.Ordinal);
        var firstRecord = text.IndexOf("$helper =", StringComparison.Ordinal);
        Assert.True(firstCheck >= 0 && firstCheck < firstRecord, "the exit code check must come before the status is written");
    }

    [Fact]
    public void ManifestScript_HashesRegularFilesWithModeOwnerAndSize_SortedAndWithoutTheRecoveryDirectory()
    {
        var text = Script("manifest.sh");

        Assert.Contains("sha256sum", text);
        Assert.Contains("stat -c", text);
        foreach (var field in new[] { "%a", "%u:%g", "%s" })
            Assert.Contains(field, text);
        Assert.Contains("-type f", text);
        Assert.Contains("! -path './recovery/*'", text);
        Assert.Contains("LC_ALL=C sort", text);
        // A path with a control character cannot be written as one line, so it is refused, not skipped.
        Assert.Contains("[[:cntrl:]]", text);
        Assert.Contains("exit 3", text);
    }

    [Theory]
    [InlineData("backup.sh")]
    [InlineData("backup.ps1")]
    public void BackupScripts_WriteAManifestBesideTheArchive_BeforeArchiving_AndOnlyWarnOnFailure(string name)
    {
        var text = Script(name);

        Assert.Contains("manifest.sh", text);
        Assert.Contains(".manifest", text);
        Assert.Contains("integrity manifest could be written", text);
        var manifest = text.IndexOf("manifest.sh", StringComparison.Ordinal);
        var archive = text.IndexOf("tar czf", StringComparison.Ordinal);
        Assert.True(manifest >= 0 && manifest < archive, "the manifest must be taken before the archive, while the container is stopped");
    }

    [Fact]
    public void BackupPowerShell_WritesTheManifestAsUtf8WithoutABom_AndLfLineEndings()
    {
        // Windows PowerShell's `>` writes UTF-16; the manifest is compared byte for byte with a Linux one.
        var text = Script("backup.ps1");

        Assert.Contains("UTF8Encoding($false)", text);
        Assert.Contains("-join \"`n\"", text);
    }

    [Theory]
    [InlineData("restore-test.sh", "record usable")]
    [InlineData("restore-test.ps1", "Write-RestoreRecord 'usable'")]
    public void RestoreTestScripts_WriteTheRecords_Atomically_AndRecordUsableOnlyAfterTheComparison(string name, string usableCall)
    {
        var text = Script(name);

        foreach (var key in new[] { "schemaVersion", "kind", "completedAtUtc", "archiveName", "step", "failedCheck", "reportedBy" })
            Assert.Contains($"\\042{key}\\042", text);
        Assert.Contains("last-restore.json.tmp", text);
        Assert.Contains("mv /data/recovery/last-restore.json.tmp /data/recovery/last-restore.json", text);
        var comparison = text.IndexOf("does not match its manifest", StringComparison.Ordinal);
        var usable = text.IndexOf(usableCall, StringComparison.Ordinal);
        Assert.True(comparison >= 0 && usable > comparison, "usable may be recorded only after the manifest comparison can fail");
    }

    [Theory]
    [InlineData("restore-test.sh")]
    [InlineData("restore-test.ps1")]
    public void RestoreTestScripts_BootTheRestoredCopyOffline_AfterTheManifestComparison_AndRecordAFailure(string name)
    {
        var text = Script(name);

        Assert.Contains("--network none", text);
        Assert.Contains("--user 1654:1654", text);
        Assert.Contains("--entrypoint dotnet", text);
        Assert.Contains("/app/restorecheck/Qertum.RestoreCheck.dll", text);
        var comparison = text.IndexOf("does not match its manifest", StringComparison.Ordinal);
        Assert.True(text.IndexOf("Qertum.RestoreCheck.dll", StringComparison.Ordinal) > comparison, "the check runs after the manifest comparison");
        Assert.Contains("failed", text);
        Assert.Contains("usable", text);
    }

    [Theory]
    [InlineData("restore-test.sh", "--image")]
    [InlineData("restore-test.ps1", "$Image")]
    public void RestoreTestScripts_TakeAnImageOption(string name, string marker)
    {
        Assert.Contains(marker, Script(name));
    }

    [Fact]
    public void MultiContainerRestoreTestWrappers_PassTheirOptionsOn()
    {
        foreach (var name in new[] { "restore-test.sh", "restore-test.ps1" })
        {
            string? text = null;
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null && text is null; dir = dir.Parent)
            {
                var path = Path.Combine(dir.FullName, "deploy", "multi-container", name);
                if (File.Exists(path))
                    text = File.ReadAllText(path);
            }

            Assert.NotNull(text);
            Assert.Contains(name.EndsWith(".sh", StringComparison.Ordinal) ? "\"$@\"" : "@Rest", text);
        }
    }

    [Theory]
    [InlineData("restore-test.sh")]
    [InlineData("restore-test.ps1")]
    public void RestoreTestScripts_UseAScratchVolume_AndNeverStopOrClearTheOperatingContainer(string name)
    {
        var text = Script(name);

        Assert.Contains("volume create", text);
        Assert.Contains("volume rm", text);
        Assert.DoesNotContain("docker stop", text);
        Assert.DoesNotContain("docker start", text);
        Assert.DoesNotContain("rm -rf", text);
        Assert.Contains("exit 2", text);
        Assert.Contains("exit 1", text);
    }

    [Fact]
    public void RestoreTestPowerShell_FormatsTheTimestampInvariantly_ChecksEveryDockerCall_AndComparesPathsOrdinally()
    {
        var text = Script("restore-test.ps1");

        Assert.Contains("[System.Globalization.CultureInfo]::InvariantCulture", text);
        Assert.DoesNotContain("ToString(\"yyyy-MM-ddTHH:mm:ssZ\")", text);
        Assert.Contains("$LASTEXITCODE", text);
        // PowerShell hashtables ignore case; paths on the Linux volume do not.
        Assert.Contains("[StringComparer]::Ordinal", text);
    }

    [Fact]
    public void ManifestScript_NeverHidesAFailedHash_BehindAPipe_AndRejectsAnEmptyHash()
    {
        // `sha256sum f | cut` reports cut's status, so a failed hash became an empty one and an unreadable
        // file would match an equally unreadable copy: a false pass.
        var text = Script("manifest.sh");

        Assert.DoesNotContain("sha256sum \"$f\" |", text);
        Assert.Contains("-eq 64", text);
    }

    [Fact]
    public void RestoreTestShell_PicksTheNewestArchiveByName_NotByModifiedTime()
    {
        // The name carries the UTC time of the backup; a copy off-box or a touch changes the modified time.
        var text = Script("restore-test.sh");

        Assert.DoesNotContain("ls -1t", text);
        Assert.Contains("qertum-backup-*.tar.gz", text);
    }

    [Fact]
    public void RestoreTestPowerShell_PicksTheNewestArchiveByName_NotByModifiedTime()
    {
        var text = Script("restore-test.ps1");

        Assert.DoesNotContain("LastWriteTime", text);
        Assert.Contains("Sort-Object Name -Descending", text);
    }

    [Theory]
    [InlineData("restore-test.sh", "125|126|127")]
    [InlineData("restore-test.ps1", "125, 126, 127")]
    public void RestoreTestScripts_TreatADockerFailureAsCouldNotTest_NotAsADamagedArchive(string name, string dockerCodes)
    {
        var text = Script(name);

        Assert.Contains(dockerCodes, text);
    }

    [Theory]
    [InlineData("restore-test.sh")]
    [InlineData("restore-test.ps1")]
    public void RestoreTestScripts_WarnWhenTheScratchVolumeCannotBeRemoved(string name)
    {
        // The scratch volume holds a copy of the CA private keys; a silent failure would leave it behind.
        var text = Script(name);

        Assert.Contains("could not remove the scratch volume", text);
    }

    [Theory]
    [InlineData("restore-test.ps1")]
    [InlineData("backup.ps1")]
    [InlineData("restore.ps1")]
    public void PowerShellScripts_AreOneScript_WithBalancedBraces_NotTwoPastedTogether(string name)
    {
        // The string checks above pass on a file that PowerShell cannot parse; a duplicated body once did exactly that.
        var text = Script(name);

        Assert.Equal(text.Count(c => c == '{'), text.Count(c => c == '}'));
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(text, @"^param \(", System.Text.RegularExpressions.RegexOptions.Multiline));
        Assert.True(System.Text.RegularExpressions.Regex.Matches(text, @"^function Read-Manifest", System.Text.RegularExpressions.RegexOptions.Multiline).Count <= 1,
            "a function is defined twice");
    }

    [Theory]
    [InlineData("restore-test.sh")]
    [InlineData("restore-test.ps1")]
    public void RestoreTestScripts_NameTheChecksThatTestedNothing_WhenTheyRecordUsable(string name)
    {
        // "usable" with a never-onboarded CA, offline-only issuers or no stored secret would otherwise read as full coverage.
        Assert.Contains("not-exercised", Script(name));
        Assert.Contains("says nothing about", Script(name));
    }

    [Theory]
    [InlineData("restore-test.sh")]
    [InlineData("restore-test.ps1")]
    public void RestoreTestScripts_CapTheFailedCheckName_AndNeverStopTheOutputEarly(string name)
    {
        var text = Script(name);

        // The record reader refuses a failedCheck over 32 characters; an early awk exit under pipefail can abort the script
        // before the failed record is written.
        Assert.Contains(name.EndsWith(".sh", StringComparison.Ordinal) ? "cut -c1-32" : "Substring(0", text);
        Assert.DoesNotContain("print $2; exit", text);
    }

    [Theory]
    [InlineData("backup.ps1")]
    [InlineData("restore.ps1")]
    [InlineData("restore-test.ps1")]
    public void PowerShellScripts_RequirePowerShell7_SoWindowsPowerShell51FailsWithAClearMessage(string name)
    {
        // The supported shell is PowerShell 7 (pwsh). 5.1 treats native-command stderr as a terminating error and writes
        // UTF-16 on redirect, which these scripts do not handle; refuse to start there instead of misbehaving.
        Assert.Contains("#Requires -Version 7", Script(name));
    }
}
