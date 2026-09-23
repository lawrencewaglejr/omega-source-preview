#!/usr/bin/env bash

set -e

STAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BASE_DIR="$HOME/omega-support-bundles"
BUNDLE_DIR="$BASE_DIR/omega-bundle-$STAMP"
ARCHIVE="$BASE_DIR/omega-bundle-$STAMP.tar.gz"
HASH_FILE="$ARCHIVE.sha256"

mkdir -p "$BUNDLE_DIR"

echo "Ω OMEGA SUPPORT BUNDLE"
echo "===================="
echo
echo "Creating bundle: $BUNDLE_DIR"
echo

echo "[1/7] Collecting omega-status..."
omega-status > "$BUNDLE_DIR/omega-status.txt" 2>&1 || true

echo "[2/7] Collecting omega-health..."
omega-health > "$BUNDLE_DIR/omega-health.txt" 2>&1 || true

echo "[3/7] Collecting omega-summary..."
omega-summary > "$BUNDLE_DIR/omega-summary.txt" 2>&1 || true

echo "[4/7] Collecting omega-alerts..."
omega-alerts > "$BUNDLE_DIR/omega-alerts.txt" 2>&1 || true

echo "[5/7] Collecting omega-report..."
omega-report > "$BUNDLE_DIR/omega-report.txt" 2>&1 || true

echo "[6/7] Collecting omega-doctor..."
omega-doctor > "$BUNDLE_DIR/omega-doctor.txt" 2>&1 || true

echo "[7/7] Collecting repo and system info..."
{
  echo "Ω Omega Bundle Metadata"
  echo "Generated: $(date)"
  echo "Host: $(hostname)"
  echo
  echo "Git branch/status:"
  cd "$HOME/omega-v1" && git status
  echo
  echo "Latest commits:"
  git log --oneline -10
  echo
  echo "Tags:"
  git tag
} > "$BUNDLE_DIR/metadata.txt" 2>&1 || true

tar -czf "$ARCHIVE" -C "$BASE_DIR" "omega-bundle-$STAMP"
sha256sum "$ARCHIVE" > "$HASH_FILE"

echo
echo "Bundle created:"
echo "$ARCHIVE"
echo
echo "SHA256:"
cat "$HASH_FILE"
echo
echo "Complete."
