#!/bin/sh
# Build the Mac side. Needs Xcode command line tools, nothing else.
set -e
cd "$(dirname "$0")"
swiftc -O -framework CoreGraphics -framework AppKit -framework Security \
       mac/kmlink.swift -o kmlink
echo "built: $(pwd)/kmlink"
