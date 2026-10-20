#!/usr/bin/env bash
# Starts the stack from a clean build so CA onboarding runs again from scratch.
# Deleting every bin/ and obj/ directory also removes the SQLite DB, CA files, key ring and
# IdentityService data that Aspire keeps beside the AppHost binaries.
#
# Usage: scripts/fresh-onboarding.sh

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker info >/dev/null 2>&1 || { echo "Docker is not running (AppHost needs it for Redis)." >&2; exit 1; }

find . -type d \( -name "bin" -o -name "obj" \) -exec rm -rf {} +
dotnet run --project Qertum.AppHost/
