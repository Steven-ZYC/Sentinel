#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script with sudo" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
SOURCE_DIR="$PROJECT_DIR/site"
SAFELINE_DIR=${SAFELINE_DIR:-/data/safeline}
TARGET_DIR=${SAFELINE_STATIC_DIR:-$SAFELINE_DIR/resources/nginx/static/static_1}
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_ROOT=${SENTINEL_SITE_BACKUP_DIR:-$SAFELINE_DIR/backups/sentinel/site}
BACKUP_DIR=$(python3 "$SCRIPT_DIR/harden_deployment.py" backups --webroot "$TARGET_DIR" --backup-root "$BACKUP_ROOT" | sed -n 's/^OK: legacy public backups moved to recoverable private directory: //p')
[ -d "$BACKUP_DIR" ] || { echo 'error: private backup directory unavailable' >&2; exit 1; }
BACKUP="$BACKUP_DIR/index.html.pre-split-$TIMESTAMP"

for file in index.html styles.css app.js; do
    if [ ! -f "$SOURCE_DIR/$file" ]; then
        echo "error: missing source file: $SOURCE_DIR/$file" >&2
        exit 1
    fi
done

if [ ! -f "$TARGET_DIR/index.html" ]; then
    echo "error: expected deployed index is missing: $TARGET_DIR/index.html" >&2
    exit 1
fi

if grep -Eq '<style([[:space:]>])|<script([[:space:]]*>)' "$SOURCE_DIR/index.html"; then
    echo "error: index.html contains inline CSS or JavaScript" >&2
    exit 1
fi

install -o root -g root -m 0600 "$TARGET_DIR/index.html" "$BACKUP"

CSS_TMP=$(mktemp "$TARGET_DIR/.styles.css.XXXXXX")
JS_TMP=$(mktemp "$TARGET_DIR/.app.js.XXXXXX")
HTML_TMP=$(mktemp "$TARGET_DIR/.index.html.XXXXXX")
trap 'rm -f "$CSS_TMP" "$JS_TMP" "$HTML_TMP"' EXIT HUP INT TERM

install -o root -g root -m 0644 "$SOURCE_DIR/styles.css" "$CSS_TMP"
install -o root -g root -m 0644 "$SOURCE_DIR/app.js" "$JS_TMP"
install -o root -g root -m 0644 "$SOURCE_DIR/index.html" "$HTML_TMP"

mv -f "$CSS_TMP" "$TARGET_DIR/styles.css"
mv -f "$JS_TMP" "$TARGET_DIR/app.js"
mv -f "$HTML_TMP" "$TARGET_DIR/index.html"
trap - EXIT HUP INT TERM

echo "deployed site assets"
echo "backup: $BACKUP"
