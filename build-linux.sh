#!/bin/sh
# Build the SteamOS receiver as one static linux/amd64 binary.
#
# Cross-built here because SteamOS ships no compiler. Static because a SteamOS
# update replaces the whole system partition: anything installed outside the
# home folder is gone afterwards, and a binary linked against the system's
# libraries can break with it. One self-contained file in the home folder is
# the only thing that reliably survives.
set -e
cd "$(dirname "$0")"

(cd linux && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o ../out/kmlink-linux .)

echo "built: $(pwd)/out/kmlink-linux"
