using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class AddIssuerRenewalOf : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "RenewalOfIssuerId",
                table: "Issuers",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Issuers_RenewalOfIssuerId",
                table: "Issuers",
                column: "RenewalOfIssuerId",
                unique: true,
                filter: "\"RenewalOfIssuerId\" IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Issuers_RenewalOfIssuerId",
                table: "Issuers");

            migrationBuilder.DropColumn(
                name: "RenewalOfIssuerId",
                table: "Issuers");
        }
    }
}
