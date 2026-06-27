#!/bin/sh
set -u

CHECK_URL="${CHECK_URL:-https://vvn2-2w2evypk.b4a.run/chat}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-200}"
CHECK_TIMEOUT_SECONDS="${CHECK_TIMEOUT_SECONDS:-10}"
CHECK_PRINT_SUCCESS="${CHECK_PRINT_SUCCESS:-0}"

timestamp() {
  date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z'
}

while :; do
  result="$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' --max-time "$CHECK_TIMEOUT_SECONDS" "$CHECK_URL" 2>&1)"
  exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    http_code="${result%% *}"
    time_total="${result#* }"

    if [ "$CHECK_PRINT_SUCCESS" = "1" ]; then
      printf '%s curl check result: http_code=%s time_total=%ss url=%s\n' "$(timestamp)" "$http_code" "$time_total" "$CHECK_URL"
    fi

    if [ "$http_code" -ge 500 ] 2>/dev/null; then
      printf '%s curl check bad status: http_code=%s time_total=%ss url=%s\n' "$(timestamp)" "$http_code" "$time_total" "$CHECK_URL" >&2
    fi
  else
    printf '%s curl check failed: exit=%s result=%s url=%s\n' "$(timestamp)" "$exit_code" "$result" "$CHECK_URL" >&2
  fi

  sleep "$CHECK_INTERVAL_SECONDS"
done
