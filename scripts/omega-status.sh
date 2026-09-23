#!/usr/bin/env bash

set -uo pipefail

EVEBOX_URL="https://localhost:5636"
RESULT_CODE=0

promote_result() {
  local code="$1"
  if (( code > RESULT_CODE )); then
    RESULT_CODE="$code"
  fi
}

result_name() {
  case "$RESULT_CODE" in
    0) echo "SUCCESS" ;;
    1) echo "WARNING" ;;
    2) echo "UNKNOWN" ;;
    3) echo "FAILURE" ;;
  esac
}

finish_result() {
  local name
  name=$(result_name)
  echo
  echo "OMEGA_RESULT=$name"
  exit "$RESULT_CODE"
}

single_line() {
  local value="$1"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  printf '%s' "$value"
}

valid_tailscale_ipv4() {
  local value="$1"
  local first second third fourth

  [[ "$value" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  IFS=. read -r first second third fourth <<< "$value"
  (( 10#$first == 100 )) || return 1
  (( 10#$second >= 64 && 10#$second <= 127 )) || return 1
  (( 10#$third <= 255 && 10#$fourth <= 255 )) || return 1
}

check_service() {
  local label="$1"
  local unit="$2"
  local status
  local status_code

  printf "%-13s" "$label:"
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "unknown (systemctl not found)"
    promote_result 2
    return
  fi

  status=$(systemctl is-active -- "$unit" 2>/dev/null)
  status_code=$?
  if [ "$status" = "active" ] && (( status_code == 0 )); then
    echo "active"
  else
    case "$status" in
      inactive|failed|deactivating)
        echo "$status"
        promote_result 3
        ;;
      activating|reloading)
        echo "$status"
        promote_result 1
        ;;
      *)
        echo "unknown"
        promote_result 2
        ;;
    esac
  fi
}

echo "Ω OMEGA STATUS"
echo "===================="
echo

LAN_IP=""
TAILSCALE_IP=""

if LAN_OUTPUT=$(hostname -I 2>/dev/null); then
  LAN_IP=$(awk '{print $1}' <<< "$LAN_OUTPUT")
  if [ -z "$LAN_IP" ]; then
    promote_result 1
  fi
else
  promote_result 2
fi

if IP_OUTPUT=$(ip -br a 2>/dev/null); then
  if ! TAILSCALE_CANDIDATE=$(awk '/tailscale0/ {print $3}' <<< "$IP_OUTPUT" | cut -d/ -f1); then
    promote_result 2
  elif [ -z "$TAILSCALE_CANDIDATE" ]; then
    promote_result 1
  elif valid_tailscale_ipv4 "$TAILSCALE_CANDIDATE"; then
    TAILSCALE_IP="$TAILSCALE_CANDIDATE"
  else
    promote_result 2
  fi
else
  promote_result 2
fi

if DEVICE=$(hostname 2>/dev/null); then
  echo "Device: $(single_line "$DEVICE")"
else
  echo "Device: Unknown"
  promote_result 2
fi
echo "LAN: $(single_line "${LAN_IP:-Not found}")"
echo "Tailscale: $(single_line "${TAILSCALE_IP:-Not found}")"
if UPTIME_OUTPUT=$(uptime -p 2>/dev/null); then
  echo "Uptime: $(single_line "$UPTIME_OUTPUT")"
else
  echo "Uptime: Unknown"
  promote_result 2
fi
echo

echo "Services"
echo "--------------------"
check_service "Pi-hole" "pihole-FTL"
check_service "Suricata" "suricata"
check_service "Wazuh Agent" "wazuh-agent"
check_service "Docker" "docker"

echo
echo "EveBox"
echo "--------------------"
if ! command -v curl >/dev/null 2>&1; then
  echo "EveBox: unknown (curl not found)"
  promote_result 2
elif EVEBOX_HEADERS=$(curl -k -s -I --max-time 10 -- "$EVEBOX_URL" 2>/dev/null); then
  if grep -Eq '^HTTP/[^ ]+ 200([[:space:]]|$)' <<< "$EVEBOX_HEADERS"; then
    echo "EveBox: active"
    if [ -n "$TAILSCALE_IP" ]; then
      echo "URL: https://$(single_line "$TAILSCALE_IP"):5636"
    else
      echo "URL: unavailable (Tailscale address not found)"
    fi
  else
    echo "EveBox: unhealthy HTTP response"
    promote_result 3
  fi
else
  echo "EveBox: not responding"
  promote_result 3
fi

echo
echo "System"
echo "--------------------"
if DISK_INFO=$(df -h / 2>/dev/null | awk 'NR==2 {print "Disk: " $5 " used, " $4 " free"}') && [ -n "$DISK_INFO" ]; then
  echo "$DISK_INFO"
else
  echo "Disk: Unknown"
  promote_result 2
fi
if MEMORY_INFO=$(free -h 2>/dev/null | awk '/Mem:/ {print "Memory: " $7 " available"}') && [ -n "$MEMORY_INFO" ]; then
  echo "$MEMORY_INFO"
else
  echo "Memory: Unknown"
  promote_result 2
fi

echo
case "$RESULT_CODE" in
  0)
    echo "Status: Omega is operational."
    ;;
  1)
    echo "Status: Omega is operational with warnings."
    ;;
  2)
    echo "Status: Omega operational state is unknown."
    ;;
  3)
    echo "Status: Omega is not fully operational."
    ;;
esac

finish_result
