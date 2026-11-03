using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class AddEmailUpnPolicyRules : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Existing policy versions back-fill to "[]" (unrestricted), so a published policy keeps issuing as before.
            migrationBuilder.AddColumn<string>(
                name: "AllowedEmailDomainsJson",
                table: "IssuancePolicyVersions",
                type: "TEXT",
                nullable: false,
                defaultValue: "[]");

            migrationBuilder.AddColumn<string>(
                name: "AllowedUpnSuffixesJson",
                table: "IssuancePolicyVersions",
                type: "TEXT",
                nullable: false,
                defaultValue: "[]");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedEmailDomainsJson",
                table: "IssuancePolicyVersions");

            migrationBuilder.DropColumn(
                name: "AllowedUpnSuffixesJson",
                table: "IssuancePolicyVersions");
        }
    }
}
