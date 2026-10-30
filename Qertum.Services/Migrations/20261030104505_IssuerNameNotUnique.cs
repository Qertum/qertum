using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class IssuerNameNotUnique : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Issuers_Name",
                table: "Issuers");

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_Name",
                table: "Issuers",
                column: "Name");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Issuers_Name",
                table: "Issuers");

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_Name",
                table: "Issuers",
                column: "Name",
                unique: true);
        }
    }
}
