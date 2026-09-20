// kmlink - Mac side. Captures keyboard and mouse, sends them to a Windows PC.
//
// See ../PROTOCOL.md. The short version: input goes over encrypted UDP as
// relative deltas, the clipboard goes over encrypted TCP, and the Mac does all
// the keycode translation so the receiver stays dumb.
//
// Build:  ./build-mac.sh
// Usage:  kmlink --genkey
//         kmlink <windows-ip>

import Foundation
import CoreGraphics
import CryptoKit
import AppKit
import IOKit.hid

// MARK: - Constants

let PORT: UInt16 = 24810
let CONFIG_DIR = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/kmlink")
let KEY_FILE = CONFIG_DIR.appendingPathComponent("key.txt")
let HOST_FILE = CONFIG_DIR.appendingPathComponent("host.txt")

enum PacketType: UInt8 {
    case move = 1, button = 2, wheel = 3, key = 4, enter = 5, leave = 6, ping = 7
}

struct Mods: OptionSet {
    let rawValue: UInt32
    static let shift = Mods(rawValue: 1)
    static let ctrl  = Mods(rawValue: 2)
    static let alt   = Mods(rawValue: 4)
    static let gui   = Mods(rawValue: 8)
}

// MARK: - Keycode translation
//
// macOS virtual keycode -> Windows virtual-key code. Doing this here keeps all
// the platform awkwardness on one side; the receiver just injects what it gets.

let VK: [Int64: UInt16] = [
    // letters
    0x00: 0x41, 0x0B: 0x42, 0x08: 0x43, 0x02: 0x44, 0x0E: 0x45, 0x03: 0x46,
    0x05: 0x47, 0x04: 0x48, 0x22: 0x49, 0x26: 0x4A, 0x28: 0x4B, 0x25: 0x4C,
    0x2E: 0x4D, 0x2D: 0x4E, 0x1F: 0x4F, 0x23: 0x50, 0x0C: 0x51, 0x0F: 0x52,
    0x01: 0x53, 0x11: 0x54, 0x20: 0x55, 0x09: 0x56, 0x0D: 0x57, 0x07: 0x58,
    0x10: 0x59, 0x06: 0x5A,
    // digits
    0x12: 0x31, 0x13: 0x32, 0x14: 0x33, 0x15: 0x34, 0x17: 0x35,
    0x16: 0x36, 0x1A: 0x37, 0x1C: 0x38, 0x19: 0x39, 0x1D: 0x30,
    // control keys
    0x24: 0x0D, 0x30: 0x09, 0x31: 0x20, 0x33: 0x08, 0x35: 0x1B,
    0x75: 0x2E,                                     // forward delete
    // arrows
    0x7B: 0x25, 0x7E: 0x26, 0x7C: 0x27, 0x7D: 0x28,
    // navigation
    0x73: 0x24, 0x77: 0x23, 0x74: 0x21, 0x79: 0x22,
    // punctuation
    0x1B: 0xBD, 0x18: 0xBB, 0x21: 0xDB, 0x1E: 0xDD, 0x2A: 0xDC,
    0x29: 0xBA, 0x27: 0xDE, 0x2B: 0xBC, 0x2F: 0xBE, 0x2C: 0xBF, 0x32: 0xC0,
    // function keys
    0x7A: 0x70, 0x78: 0x71, 0x63: 0x72, 0x76: 0x73, 0x60: 0x74, 0x61: 0x75,
    0x62: 0x76, 0x64: 0x77, 0x65: 0x78, 0x6D: 0x79, 0x67: 0x7A, 0x6F: 0x7B,
]

/// Command becomes Control on Windows, so Cmd+C copies. Control becomes the
/// Windows key. Without this every shortcut lands on the wrong modifier.
func translateMods(_ flags: CGEventFlags) -> Mods {
    var m = Mods()
    if flags.contains(.maskShift)      { m.insert(.shift) }
    if flags.contains(.maskCommand)    { m.insert(.ctrl)  }   // Cmd -> Ctrl
    if flags.contains(.maskControl)    { m.insert(.gui)   }   // Ctrl -> Win
    if flags.contains(.maskAlternate)  { m.insert(.alt)   }
    return m
}

// MARK: - Crypto

final class Cipher {
    private let key: SymmetricKey
    private let prefix: UInt32
    private var counter: UInt64 = 0

    init(key: Data) {
        self.key = SymmetricKey(data: key)
        self.prefix = UInt32.random(in: 0...UInt32.max)
    }

    /// Returns nonce(12) || ciphertext || tag(16), which is exactly what
    /// CryptoKit's `combined` gives us and what the receiver expects.
    func seal(_ plaintext: Data) -> Data? {
        counter &+= 1
        var nonceBytes = Data()
        withUnsafeBytes(of: prefix.bigEndian)  { nonceBytes.append(contentsOf: $0) }
        withUnsafeBytes(of: counter.bigEndian) { nonceBytes.append(contentsOf: $0) }
        guard let nonce = try? AES.GCM.Nonce(data: nonceBytes),
              let box = try? AES.GCM.seal(plaintext, using: key, nonce: nonce)
        else { return nil }
        return box.combined
    }
}

// MARK: - Packet building

var sequence: UInt32 = 0

func payload(_ type: PacketType, _ body: Data = Data()) -> Data {
    sequence &+= 1
    var d = Data([type.rawValue])
    withUnsafeBytes(of: sequence.bigEndian) { d.append(contentsOf: $0) }
    d.append(body)
    return d
}

func be16(_ v: Int16) -> Data {
    var d = Data(); withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) }; return d
}
func be16u(_ v: UInt16) -> Data {
    var d = Data(); withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) }; return d
}
func be32(_ v: UInt32) -> Data {
    var d = Data(); withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) }; return d
}

// MARK: - UDP sender

final class Sender {
    private let fd: Int32
    private var addr: sockaddr_in
    private let cipher: Cipher

    init?(host: String, cipher: Cipher) {
        self.cipher = cipher
        fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }

        // Low delay, and never block the event tap on a send.
        var tos: Int32 = 0x10
        setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, socklen_t(MemoryLayout<Int32>.size))
        var flags = fcntl(fd, F_GETFL, 0)
        flags |= O_NONBLOCK
        _ = fcntl(fd, F_SETFL, flags)

        addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = PORT.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else { return nil }
    }

    /// `copies` > 1 for key and button events: three small datagrams cost
    /// nothing and survive loss without TCP's head-of-line blocking. The
    /// receiver de-duplicates on the sequence number.
    func send(_ plain: Data, copies: Int = 1) {
        guard let sealed = cipher.seal(plain) else { return }
        sealed.withUnsafeBytes { raw in
            for _ in 0..<copies {
                withUnsafePointer(to: &addr) { ap in
                    ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        _ = sendto(fd, raw.baseAddress, raw.count, 0,
                                   sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }
    }
}

// MARK: - Clipboard (Mac -> PC, over TCP)

final class ClipboardWatcher {
    private let host: String
    private let cipher: Cipher
    private var lastChange: Int
    private var timer: Timer?

    init(host: String, cipher: Cipher) {
        self.host = host
        self.cipher = cipher
        self.lastChange = NSPasteboard.general.changeCount
    }

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        let pb = NSPasteboard.general
        guard pb.changeCount != lastChange else { return }
        lastChange = pb.changeCount
        guard let text = pb.string(forType: .string),
              let utf8 = text.data(using: .utf8),
              utf8.count <= 1_000_000 else { return }

        var plain = Data([1])          // format 1 = UTF-8 text
        plain.append(utf8)
        guard let sealed = cipher.seal(plain) else { return }

        // Sent on its own thread: a slow or refused clipboard connection must
        // never stall the event tap.
        DispatchQueue.global(qos: .utility).async { [host] in
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return }
            defer { close(fd) }
            var tv = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            var a = sockaddr_in()
            a.sin_family = sa_family_t(AF_INET)
            a.sin_port = PORT.bigEndian
            guard inet_pton(AF_INET, host, &a.sin_addr) == 1 else { return }
            let ok = withUnsafePointer(to: &a) { ap in
                ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
            guard ok else { return }

            var frame = be32(UInt32(sealed.count))
            frame.append(sealed)
            frame.withUnsafeBytes { _ = write(fd, $0.baseAddress, $0.count) }
        }
    }
}

// MARK: - Menu bar

/// Shows at a glance whether input is going to the Mac or the PC, and gives a
/// way to quit. Without it a forgotten instance sitting in "PC" mode swallows
/// every event and looks like the Mac has frozen.
final class StatusBar {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let stateItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let toggleItem = NSMenuItem(title: "", action: #selector(StatusBar.toggle), keyEquivalent: "")
    var onToggle: (() -> Void)?

    init(host: String) {
        let menu = NSMenu()
        stateItem.isEnabled = false
        menu.addItem(stateItem)
        menu.addItem(NSMenuItem(title: "Peer: \(host)", action: nil, keyEquivalent: ""))
        menu.addItem(.separator())
        toggleItem.target = self
        menu.addItem(toggleItem)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit kmlink", action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
        item.menu = menu
        set(active: false)
    }

    @objc private func toggle() { onToggle?() }

    func set(active: Bool) {
        let name = active ? "display" : "laptopcomputer"
        if let button = item.button {
            button.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
            button.image?.isTemplate = true
            // Fall back to text on anything without the symbol.
            if button.image == nil { button.title = active ? "PC" : "Mac" }
        }
        stateItem.title = active ? "Input going to the PC" : "Input staying on this Mac"
        toggleItem.title = active ? "Take back  (Cmd+Ctrl+Left)" : "Send to PC  (Cmd+Ctrl+Right)"
    }
}

var statusBar: StatusBar?

// MARK: - State

final class Controller {
    let sender: Sender
    var active = false
    private var heldKeys = Set<UInt16>()

    init(sender: Sender) { self.sender = sender }

    func enter() {
        guard !active else { return }
        active = true
        statusBar?.set(active: true)
        sender.send(payload(.enter), copies: 3)
        FileHandle.standardError.write("-> windows\n".data(using: .utf8)!)
    }

    func leave() {
        guard active else { return }
        // Release anything still held before handing control back, so the PC
        // is not left with a modifier down.
        for vk in heldKeys {
            var b = be16u(vk); b.append(0); b.append(be32(0))
            sender.send(payload(.key, b), copies: 3)
        }
        heldKeys.removeAll()
        active = false
        statusBar?.set(active: false)
        sender.send(payload(.leave), copies: 3)
        FileHandle.standardError.write("-> mac\n".data(using: .utf8)!)
    }

    func noteKey(_ vk: UInt16, down: Bool) {
        if down { heldKeys.insert(vk) } else { heldKeys.remove(vk) }
    }
}

// MARK: - Event tap

var controller: Controller!
var eventTap: CFMachPort?

func handle(proxy: CGEventTapProxy, type: CGEventType,
            event: CGEvent, refcon: UnsafeMutableRawPointer?) -> Unmanaged<CGEvent>? {

    // macOS disables a tap that takes too long to return, and after some system
    // events. Re-enable it or input silently stops working until restart.
    if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
        if let tap = eventTap { CGEvent.tapEnable(tap: tap, enable: true) }
        return Unmanaged.passUnretained(event)
    }

    let flags = event.flags
    let keycode = event.getIntegerValueField(.keyboardEventKeycode)

    // Hotkey: Cmd+Ctrl+Right hands over, Cmd+Ctrl+Left takes back. Checked
    // before anything else so it works from either state, and swallowed so the
    // arrow key itself never reaches either machine.
    if type == .keyDown,
       flags.contains(.maskCommand), flags.contains(.maskControl) {
        if keycode == 0x7C { controller.enter(); return nil }
        if keycode == 0x7B { controller.leave(); return nil }
    }

    guard controller.active else { return Unmanaged.passUnretained(event) }

    let mods = translateMods(flags)

    switch type {
    case .mouseMoved, .leftMouseDragged, .rightMouseDragged, .otherMouseDragged:
        let dx = Int16(clamping: event.getIntegerValueField(.mouseEventDeltaX))
        let dy = Int16(clamping: event.getIntegerValueField(.mouseEventDeltaY))
        if dx != 0 || dy != 0 {
            var b = be16(dx); b.append(be16(dy))
            controller.sender.send(payload(.move, b))
        }

    case .leftMouseDown, .leftMouseUp, .rightMouseDown, .rightMouseUp,
         .otherMouseDown, .otherMouseUp:
        let button: UInt8 = (type == .leftMouseDown  || type == .leftMouseUp)  ? 1
                          : (type == .rightMouseDown || type == .rightMouseUp) ? 2 : 3
        let down: UInt8 = (type == .leftMouseDown || type == .rightMouseDown
                           || type == .otherMouseDown) ? 1 : 0
        controller.sender.send(payload(.button, Data([button, down])), copies: 3)

    case .scrollWheel:
        let dy = Int16(clamping: event.getIntegerValueField(.scrollWheelEventDeltaAxis1) * 120)
        let dx = Int16(clamping: event.getIntegerValueField(.scrollWheelEventDeltaAxis2) * 120)
        var b = be16(dx); b.append(be16(dy))
        controller.sender.send(payload(.wheel, b))

    case .keyDown, .keyUp:
        guard let vk = VK[keycode] else { break }
        let down: UInt8 = (type == .keyDown) ? 1 : 0
        controller.noteKey(vk, down: down == 1)
        var b = be16u(vk); b.append(down); b.append(be32(mods.rawValue))
        controller.sender.send(payload(.key, b), copies: 3)

    case .flagsChanged:
        // Modifier state rides along in every key packet, so a bare modifier
        // press only needs to keep the receiver in sync.
        var b = be16u(0); b.append(0); b.append(be32(mods.rawValue))
        controller.sender.send(payload(.key, b), copies: 3)

    default:
        return Unmanaged.passUnretained(event)
    }

    return nil   // swallow it locally: the PC has control
}

// MARK: - Entry

func loadKey() -> Data? {
    guard let hex = try? String(contentsOf: KEY_FILE, encoding: .utf8) else { return nil }
    let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count == 64 else { return nil }
    var out = Data()
    var i = trimmed.startIndex
    while i < trimmed.endIndex {
        let j = trimmed.index(i, offsetBy: 2)
        guard let b = UInt8(trimmed[i..<j], radix: 16) else { return nil }
        out.append(b)
        i = j
    }
    return out
}

let args = CommandLine.arguments

if args.contains("--genkey") {
    var bytes = Data(count: 32)
    _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    try? FileManager.default.createDirectory(at: CONFIG_DIR, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o700])
    try? hex.write(to: KEY_FILE, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: KEY_FILE.path)
    print(hex)
    print("")
    print("Saved to \(KEY_FILE.path)")
    print("Put the same line in %LOCALAPPDATA%\\kmlink\\key.txt on the PC.")
    exit(0)
}

if args.count >= 3, args[1] == "--set-host" {
    try? FileManager.default.createDirectory(at: CONFIG_DIR, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o700])
    try? args[2].write(to: HOST_FILE, atomically: true, encoding: .utf8)
    print("peer set to \(args[2])")
    exit(0)
}

// Launched from an .app there are no arguments, so fall back to the remembered
// peer. The bundle is what macOS attaches the Accessibility grant to.
let savedHost = (try? String(contentsOf: HOST_FILE, encoding: .utf8))?
    .trimmingCharacters(in: .whitespacesAndNewlines)
let host: String
if args.count >= 2, !args[1].hasPrefix("--") {
    host = args[1]
} else if let h = savedHost, !h.isEmpty {
    host = h
} else {
    print("usage: kmlink <windows-ip>")
    print("       kmlink --set-host <windows-ip>   remember it, then run with no arguments")
    print("       kmlink --genkey")
    exit(1)
}

guard let keyData = loadKey() else {
    FileHandle.standardError.write("No key at \(KEY_FILE.path)\nRun: kmlink --genkey\n".data(using: .utf8)!)
    exit(1)
}

// Input Monitoring is a SEPARATE grant from Accessibility, and a keyboard tap
// needs it. Without it macOS quietly downgrades the tap to listen-only: mouse
// events still arrive but cannot be suppressed, and keyboard events are
// withheld entirely. The symptom is "the mouse works, the keyboard does not,
// and the Mac cursor moves too" -- which looks like a bug in the tap rather
// than a missing permission.
let hidAccess = IOHIDCheckAccess(kIOHIDRequestTypeListenEvent)
if hidAccess != kIOHIDAccessTypeGranted {
    _ = IOHIDRequestAccess(kIOHIDRequestTypeListenEvent)
    // Warn but carry on. Without this the mouse still works; only the keyboard
    // is withheld. Exiting here would take away the half that does work.
    FileHandle.standardError.write("""
        WARNING: Input Monitoring is not granted, so the keyboard will not be
        captured and the local cursor will not freeze. The mouse still works.

        Enable kmlink in System Settings -> Privacy & Security -> Input
        Monitoring, then quit and reopen this app.

        """.data(using: .utf8)!)
}

// AXIsProcessTrusted() only asks whether we are trusted; it never prompts, so
// the app never shows up in the Accessibility list for you to enable. Passing
// kAXTrustedCheckOptionPrompt makes macOS show the request and register us,
// which is the only way the entry appears at all.
if !AXIsProcessTrusted() {
    let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
    _ = AXIsProcessTrustedWithOptions(opts)
    FileHandle.standardError.write("""
        Asked macOS for Accessibility permission.

        Approve it in the dialog, or in System Settings -> Privacy & Security
        -> Accessibility, where kmlink is now listed. Then run this again.

        """.data(using: .utf8)!)
    exit(1)
}

let cipher = Cipher(key: keyData)
guard let sender = Sender(host: host, cipher: cipher) else {
    FileHandle.standardError.write("Bad address: \(host)\n".data(using: .utf8)!)
    exit(1)
}
controller = Controller(sender: sender)

let mask: CGEventMask =
    (1 << CGEventType.keyDown.rawValue) | (1 << CGEventType.keyUp.rawValue) |
    (1 << CGEventType.flagsChanged.rawValue) | (1 << CGEventType.mouseMoved.rawValue) |
    (1 << CGEventType.leftMouseDown.rawValue) | (1 << CGEventType.leftMouseUp.rawValue) |
    (1 << CGEventType.rightMouseDown.rawValue) | (1 << CGEventType.rightMouseUp.rawValue) |
    (1 << CGEventType.otherMouseDown.rawValue) | (1 << CGEventType.otherMouseUp.rawValue) |
    (1 << CGEventType.leftMouseDragged.rawValue) | (1 << CGEventType.rightMouseDragged.rawValue) |
    (1 << CGEventType.otherMouseDragged.rawValue) | (1 << CGEventType.scrollWheel.rawValue)

guard let tap = CGEvent.tapCreate(tap: .cghidEventTap, place: .headInsertEventTap,
                                  options: .defaultTap, eventsOfInterest: mask,
                                  callback: handle, userInfo: nil) else {
    FileHandle.standardError.write("Could not create the event tap.\n".data(using: .utf8)!)
    exit(1)
}
eventTap = tap

let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .commonModes)
CGEvent.tapEnable(tap: tap, enable: true)

// Held at top level on purpose: the timer keeps only a weak reference, so
// without this the watcher is deallocated immediately and never syncs.
let clipboard = ClipboardWatcher(host: host, cipher: cipher)
clipboard.start()

// Keepalive doubles as the receiver's liveness signal: if these stop arriving
// it releases everything it thinks is held.
Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
    if controller.active { controller.sender.send(payload(.ping)) }
}

print("kmlink -> \(host)")
print("Cmd+Ctrl+Right  send input to the PC")
print("Cmd+Ctrl+Left   take it back")

// A status item needs a running NSApplication. .accessory keeps it out of the
// Dock and the app switcher; the event tap source is on this run loop, which
// NSApp.run() pumps just as CFRunLoopRun() did.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let bar = StatusBar(host: host)
bar.onToggle = { controller.active ? controller.leave() : controller.enter() }
statusBar = bar
app.run()
