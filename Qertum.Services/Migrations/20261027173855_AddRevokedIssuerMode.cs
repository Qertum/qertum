using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Qertum.Services.Migrations
{
    /// <inheritdoc />
    public partial class AddRevokedIssuerMode : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RevokedIssuerMode",
                table: "Settings",
                type: "TEXT",
                maxLength: 20,
                nullable: false,
                defaultValue: "HardStop");

            migrationBuilder.AddColumn<DateTime>(
                name: "RevokedAtUtc",
                table: "Issuers",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RevokedIssuerMode",
                table: "Settings");

            migrationBuilder.DropColumn(
                name: "RevokedAtUtc",
                table: "Issuers");
        }
    }
}
