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

check_service() {
  local unit="$1"
  local status
  local status_code

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

echo "===== Ω OMEGA HEALTH CHECK ====="
echo

echo "[HOST]"
if HOST_OUTPUT=$(hostname 2>/dev/null); then
  printf '%s\n' "$HOST_OUTPUT" | sed 's/^/  /'
else
  echo "Host information unavailable."
  promote_result 1
fi
if UPTIME_OUTPUT=$(uptime 2>/dev/null); then
  printf '%s\n' "$UPTIME_OUTPUT" | sed 's/^/  /'
else
  echo "Uptime unavailable."
  promote_result 1
fi
echo

echo "[NETWORK]"
if NETWORK_OUTPUT=$(ip -br a 2>/dev/null); then
  printf '%s\n' "$NETWORK_OUTPUT" | sed 's/^/  /'
else
  echo "Network interface information unavailable."
  promote_result 1
fi
echo

echo "[DISK]"
if DISK_OUTPUT=$(df -h / 2>/dev/null); then
  printf '%s\n' "$DISK_OUTPUT" | sed 's/^/  /'
else
  echo "Disk information unavailable."
  promote_result 1
fi
echo

echo "[MEMORY]"
if MEMORY_OUTPUT=$(free -h 2>/dev/null); then
  printf '%s\n' "$MEMORY_OUTPUT" | sed 's/^/  /'
else
  echo "Memory information unavailable."
  promote_result 1
fi
echo

echo "[PI-HOLE]"
check_service pihole-FTL
echo

echo "[SURICATA]"
check_service suricata
echo

echo "[WAZUH AGENT]"
check_service wazuh-agent
echo

echo "[DOCKER CONTAINERS]"
echo "Docker service:"
check_service docker
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker container state unknown: docker not found."
  promote_result 2
elif ! command -v sudo >/dev/null 2>&1; then
  echo "Docker container state unknown: sudo not found."
  promote_result 2
elif DOCKER_OUTPUT=$(sudo docker ps 2>/dev/null); then
  printf '%s\n' "$DOCKER_OUTPUT" | sed 's/^/  /'
else
  echo "Docker container state unknown: docker ps failed."
  promote_result 2
fi
echo

echo "[EVEBOX]"
if ! command -v curl >/dev/null 2>&1; then
  echo "EveBox state unknown: curl not found."
  promote_result 2
elif EVEBOX_HEADERS=$(curl -k -s -I --max-time 10 -- "$EVEBOX_URL" 2>/dev/null); then
  if grep -Eq '^HTTP/[^ ]+ 200([[:space:]]|$)' <<< "$EVEBOX_HEADERS"; then
    sed -n '1,10s/^/  /p' <<< "$EVEBOX_HEADERS"
  else
    echo "EveBox returned an unhealthy HTTP response."
    promote_result 3
  fi
else
  echo "EveBox is not responding."
  promote_result 3
fi
echo

echo "===== CHECK COMPLETE ====="

finish_result
