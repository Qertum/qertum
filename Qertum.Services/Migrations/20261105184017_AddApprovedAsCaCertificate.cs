using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class AddApprovedAsCaCertificate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "ApprovedAsCaCertificate",
                table: "CertificateRequests",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ApprovedAsCaCertificate",
                table: "CertificateRequests");
        }
    }
}
