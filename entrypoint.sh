#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

./websocket-check.sh &
exec ./sing-box run -c config.json
