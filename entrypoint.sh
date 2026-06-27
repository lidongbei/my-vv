#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

./curl-check.sh &
exec ./sing-box run -c config.json
