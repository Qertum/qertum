#!/bin/sh
#
# Print the integrity manifest of the /data mounted in this container: one line per regular file,
#   <sha256>  <mode>  <uid>:<gid>  <size>  <path relative to /data>
# sorted by path. backup.sh and restore-test.sh both run this, so the two manifests are comparable
# line for line. Run it inside the alpine helper image (busybox sha256sum and stat), never on the host.
#
# /data/recovery is left out: the backup scripts write it after the archive and a restore never touches
# it. Exit 3 means a path holds a control character (a newline would split its line), so no manifest
# can be trusted; every file Qertum writes has a plain name.
set -eu
cd /data

if [ -n "$(find . -name '*[[:cntrl:]]*' | head -n 1)" ]; then
  echo "error: a path under /data contains a control character; no manifest was written" >&2
  exit 3
fi

# Each step is its own command so a failure stops the script (set -e): a failed hash piped through cut
# would become an empty one, and an unreadable file would then match an equally unreadable copy.
list="$(mktemp)"
sorted="$(mktemp)"
trap 'rm -f "$list" "$sorted"' EXIT
find . -type f ! -path './recovery/*' > "$list"
LC_ALL=C sort "$list" > "$sorted"

while IFS= read -r f; do
  sum="$(sha256sum "$f")"
  hash="${sum%% *}"
  if [ "${#hash}" -eq 64 ]; then :; else
    echo "error: could not hash $f" >&2
    exit 4
  fi
  attributes="$(stat -c '%a  %u:%g  %s' "$f")"
  printf '%s  %s  %s\n' "$hash" "$attributes" "${f#./}"
done < "$sorted"
