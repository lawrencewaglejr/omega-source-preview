#!/usr/bin/env bash

set -e

DAYS=7
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days)
      DAYS="$2"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: omega-cleanup [--days 7] [--force]"
      exit 1
      ;;
  esac
done

REPORT_DIR="$HOME/omega-reports/output"
BUNDLE_DIR="$HOME/omega-support-bundles"

echo "Ω OMEGA CLEANUP"
echo "===================="
echo
echo "Retention: older than $DAYS days"
echo "Mode: $([ "$FORCE" = true ] && echo "DELETE" || echo "DRY RUN")"
echo

cleanup_path() {
  local path="$1"
  local label="$2"

  echo "$label"
  echo "--------------------"

  if [ ! -d "$path" ]; then
    echo "Directory not found: $path"
    echo
    return
  fi

  if [ "$FORCE" = true ]; then
    find "$path" -mindepth 1 -maxdepth 1 -mtime +"$DAYS" -print -exec rm -rf {} \;
  else
    find "$path" -mindepth 1 -maxdepth 1 -mtime +"$DAYS" -print
  fi

  echo
}

cleanup_path "$REPORT_DIR" "Old Reports"
cleanup_path "$BUNDLE_DIR" "Old Support Bundles"

echo "Cleanup complete."

if [ "$FORCE" = false ]; then
  echo
  echo "Dry run only. To delete files, run:"
  echo "omega-cleanup --days $DAYS --force"
fi
