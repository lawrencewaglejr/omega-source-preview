#!/usr/bin/env bash

valid_tailscale_ipv4() {
  local value="$1"
  local first second third fourth

  [[ "$value" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  IFS=. read -r first second third fourth <<< "$value"
  (( 10#$first == 100 )) || return 1
  (( 10#$second >= 64 && 10#$second <= 127 )) || return 1
  (( 10#$third <= 255 && 10#$fourth <= 255 )) || return 1
}

get_tailscale_ipv4() {
  local interface_output
  local candidate

  interface_output=$(ip -br a 2>/dev/null) || return 1
  candidate=$(awk '/tailscale0/ { value=$3; sub(/\/.*/, "", value); print value }' <<< "$interface_output") || return 1
  valid_tailscale_ipv4 "$candidate" || return 1
  printf '%s' "$candidate"
}

while true; do
  clear
  echo "Ω OMEGA CONTROL"
  echo "===================="
  echo
  echo "1) Status"
  echo "2) Health Check"
  echo "3) Security Report"
  echo "4) Alert Triage"
  echo "5) Plain-English Summary"
  echo "6) Omega Doctor"
  echo "7) Support Bundle"
  echo "8) Cleanup"
  echo "9) EveBox URL"
  echo "10) Exit"
  echo
  read -rp "Select option: " choice

  case "$choice" in
    1) omega-status ;;
    2) omega-health ;;
    3) omega-report ;;
    4) omega-alerts ;;
    5) omega-summary ;;
    6) omega-doctor ;;
    7) omega-bundle ;;
    8) omega-cleanup ;;
    9)
      echo
      if TS_IP=$(get_tailscale_ipv4); then
        echo "EveBox: https://${TS_IP}:5636"
      else
        echo "EveBox: unavailable (valid Tailscale IPv4 address not found)"
      fi
      ;;
    10)
      echo "Exiting Omega."
      exit 0
      ;;
    *)
      echo "Invalid option."
      ;;
  esac

  echo
  read -rp "Press Enter to return to menu..."
done
