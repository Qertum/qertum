#!/usr/bin/env bash
# Resets the local Aspire dev environment to a fresh-clone state: deletes every runtime
# artifact the services write locally (SQLite DB, CA files, Data Protection key ring, secret
# storage material, audit logs, IdentityService's users/clients/keys) so the next
# `dotnet run --project Qertum.AppHost` starts uninitialized (CA onboarding, admin user seed,
# etc. all run again from scratch).
#
# Safe to re-run: everything it deletes lives under gitignored bin/ output directories or the
# OS-local application-data fallback path, never under source control.
#
# Usage:
#   scripts/reset-dev-environment.sh            # reset runtime data only (default, fast)
#   scripts/reset-dev-environment.sh --deep      # also remove build output (bin/, obj/) and CLI session
#   scripts/reset-dev-environment.sh --dry-run   # print what would be deleted, delete nothing

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEEP=false
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --deep) DEEP=true ;;
    --dry-run) DRY_RUN=true ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

rm_path() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    if $DRY_RUN; then
      echo "would remove: $path"
    else
      rm -rf "$path"
      echo "removed: $path"
    fi
  fi
}

echo "== Qertum dev environment reset =="
if $DRY_RUN; then echo "(dry run — nothing will actually be deleted)"; fi

# Warn if the Aspire host (or anything holding these files open) looks like it's running —
# deleting a SQLite DB out from under a live process leaves it in an undefined state.
if pgrep -f "Qertum.AppHost" >/dev/null 2>&1; then
  echo "WARNING: a Qertum.AppHost process appears to be running. Stop it first (Ctrl+C in its" >&2
  echo "terminal, or 'dotnet run' session) before resetting — deleting its open DB is unsafe." >&2
fi

echo
echo "-- Aspire dev runtime data (beside Qertum.AppHost's build output) --"
# AppHost.cs pins every service's data (DB, CaData, DataProtection-Keys, secret-storage.json,
# audit-logs, identity-data) to AppContext.BaseDirectory of the AppHost process, i.e. its own
# bin/<config>/<tfm>/ output — glob every build config that might exist.
for dir in Qertum.AppHost/bin/*/*/; do
  [ -d "$dir" ] || continue
  rm_path "${dir}certificate-requests.db"
  rm_path "${dir}certificate-requests.db-wal"
  rm_path "${dir}certificate-requests.db-shm"
  rm_path "${dir}CaData"
  rm_path "${dir}DataProtection-Keys"
  rm_path "${dir}secret-storage.json"
  rm_path "${dir}secret-storage"
  rm_path "${dir}audit-logs"
  rm_path "${dir}identity-data"
done

echo
echo "-- Stray test-run artifacts --"
# Qertum.Tests uses in-memory/EnsureCreated contexts for almost everything, but a DB file has
# been observed accumulating under its bin output from ad-hoc runs — clear it defensively.
for dir in Qertum.Tests/bin/*/*/; do
  [ -d "$dir" ] || continue
  rm_path "${dir}certificate-requests.db"
  rm_path "${dir}certificate-requests.db-wal"
  rm_path "${dir}certificate-requests.db-shm"
done

echo
echo "-- Standalone fallback data path (used when a service runs outside Aspire with no" \
     "explicit connection string, Development/Test env only) --"
case "$(uname -s)" in
  Darwin) STANDALONE_DIR="$HOME/Library/Application Support/Qertum" ;;
  Linux)  STANDALONE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/Qertum" ;;
  *)      STANDALONE_DIR="" ;;
esac
if [ -n "$STANDALONE_DIR" ]; then
  rm_path "$STANDALONE_DIR"
else
  echo "(unrecognized OS — skipping; on Windows this is %LOCALAPPDATA%\\Qertum, remove by hand)"
fi

if $DEEP; then
  echo
  echo "-- Deep clean: build output --"
  rm_path "TestResults"
  find . -type d \( -name bin -o -name obj \) -not -path "*/node_modules/*" -print0 | while IFS= read -r -d '' dir; do
    rm_path "$dir"
  done

  echo
  echo "-- Deep clean: CLI session --"
  case "$(uname -s)" in
    Darwin) rm_path "$HOME/Library/Application Support/Qertum/cli-session.json" ;;
    Linux)  rm_path "${XDG_DATA_HOME:-$HOME/.local/share}/Qertum/cli-session.json" ;;
  esac
fi

echo
if $DRY_RUN; then
  echo "Dry run complete — nothing was deleted."
else
  echo "Reset complete. Next 'dotnet run --project Qertum.AppHost' starts uninitialized:"
  echo "  - CA onboarding runs again (no root CA configured)"
  echo "  - IdentityService reseeds its admin user (password from IdentityService:SeedAdminPassword," \
       "or the JsonUserStore default, flagged MustChangePassword)"
  echo "  - Secret storage defaults back to the zero-config local file-key provider"
  $DEEP && echo "  - First build after this will be a full rebuild (bin/obj were removed)"
fi
