#!/bin/sh
# Prepare subdirectory mounts without moving or replacing existing state. Runs once before identity and web.
set -eu
mkdir -p /data/identity /data/web
# Older layouts stored this identity-only seed secret at the volume root. Keep the old copy for rollback.
if [ -L /data/identity/.api-introspection-secret ] || { [ -e /data/identity/.api-introspection-secret ] && [ ! -f /data/identity/.api-introspection-secret ]; }; then
  echo "error: identity seed secret must be a regular file, not a symlink or directory." >&2
  exit 1
fi
if [ -f /data/.api-introspection-secret ] && [ ! -e /data/identity/.api-introspection-secret ]; then
  (
    umask 077
    # Stage outside the identity mount: only a complete private copy may become its seed secret.
    temporary=$(mktemp /data/.api-introspection-secret.tmp.XXXXXX)
    trap 'rm -f "$temporary"' 0
    trap 'exit 1' HUP INT TERM
    cat /data/.api-introspection-secret > "$temporary"
    # Same-filesystem hard-link creation is atomic and refuses to replace an existing destination.
    link "$temporary" /data/identity/.api-introspection-secret
  )
fi
chown -R 1654:1654 /data/identity /data/web
