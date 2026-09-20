#!/bin/sh
# Build the Mac side as a signed .app bundle.
#
# It has to be an app, not a loose binary: macOS attaches an Accessibility
# grant to an application identity, and a bare executable has none -- the
# permission lands on your terminal instead, or cannot be granted at all.
#
# And it has to be signed with a real identity, not ad-hoc: an ad-hoc signature
# changes on every rebuild, so macOS sees a different app each time and drops
# the grant. Override with KMLINK_IDENTITY, or set it to "-" to force ad-hoc.
set -e
cd "$(dirname "$0")"

APP="kmlink.app"
BUNDLE_ID="com.gabrielbarandiaran.kmlink"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

swiftc -O -framework CoreGraphics -framework AppKit -framework Security \
       -framework ApplicationServices \
       mac/kmlink.swift -o "$APP/Contents/MacOS/kmlink"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>kmlink</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleName</key><string>kmlink</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <!-- No Dock icon: this is a background tool, not something you switch to. -->
    <key>LSUIElement</key><true/>
    <!-- App Nap would throttle timers and I/O whenever this is not in front,
         which is exactly when it is doing its job. -->
    <key>NSAppSleepDisabled</key><true/>
    <key>NSInputMonitoringUsageDescription</key>
    <string>kmlink reads this Mac's keyboard and trackpad so it can send them to your PC.</string>
</dict>
</plist>
PLIST

if [ -z "${KMLINK_IDENTITY:-}" ]; then
    KMLINK_IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
        | awk -F'"' '/"/ {print $2; exit}')
fi
if [ -n "$KMLINK_IDENTITY" ] && [ "$KMLINK_IDENTITY" != "-" ]; then
    echo "signing as: $KMLINK_IDENTITY"
else
    KMLINK_IDENTITY="-"
    echo "WARNING: no signing identity found, using ad-hoc."
    echo "         macOS will drop the Accessibility grant on every rebuild."
fi
codesign --force --sign "$KMLINK_IDENTITY" --identifier "$BUNDLE_ID" --timestamp=none "$APP"
codesign --verify --strict "$APP"

# Install straight to /Applications and leave nothing runnable behind. Two
# bundles sharing one identifier make macOS evaluate the Accessibility grant
# against a different copy than the one you enabled, and it silently keeps
# asking.
rm -rf "/Applications/$APP"
cp -R "$APP" "/Applications/$APP"
rm -rf "$APP"
codesign --verify --strict "/Applications/$APP"

echo "installed: /Applications/$APP"
