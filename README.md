# kmlink

Use your MacBook's keyboard and trackpad on a Windows PC. Switch with a hotkey.

Two small programs and nothing else: no config files, no service, no daemon, no
screen-edge geometry to get right.

```
Cmd+Ctrl+→    input goes to the PC
Cmd+Ctrl+←    input comes back to the Mac
```

Clipboard follows along. Everything is encrypted.

## Why it exists

Barrier does this, but felt laggy on an ordinary Wi-Fi network. Measuring the
network showed it wasn't the network's fault:

```
500 packets, 24 bytes, 100/sec
replies 500/500   lost 0 (0.0%)
median  8.50 ms   jitter 1.37 ms
```

~4 ms one-way with negligible jitter is plenty for input. Two design choices
explain the difference:

- **UDP with relative deltas, not TCP with absolute positions.** A lost mouse
  delta is self-correcting — the next one makes it up. An absolute position is
  worthless once a newer one exists, yet TCP still delivers every stale one in
  order, so one lost packet makes the cursor slide through where it used to be.
- **Receive and inject on the same thread.** Barrier posts each event to a
  second thread and blocks waiting for it, once per keystroke and once per
  mouse move.

Keyboard traffic is a handful of packets per second, so if typing feels slow
too, the problem was never bandwidth.

## Setup

### 1. Mac

```sh
./build-mac.sh
./kmlink --genkey
```

`--genkey` prints a 64-character key and saves it to
`~/Library/Application Support/kmlink/key.txt` (mode 0600).

Grant Accessibility: **System Settings → Privacy & Security → Accessibility**,
add the `kmlink` binary. Without it macOS won't let anything read the keyboard.

### 2. Windows

Download `kmlink-win.exe` from the Releases page, or build it yourself from
`win/kmlink-win.c`.

Create `%LOCALAPPDATA%\kmlink\key.txt` and paste in the same key from step 1.
Both machines must have identical keys.

Run it. Allow the firewall prompt.

### 3. Go

On the Mac:

```sh
./kmlink 192.168.1.50      # the PC's address
```

Press **Cmd+Ctrl+→**. The PC now has your keyboard and mouse. **Cmd+Ctrl+←**
takes it back.

## What it does

| | |
|---|---|
| Mouse | move, left/right/middle, scroll |
| Keyboard | letters, digits, punctuation, F1–F12, arrows, navigation, modifiers |
| Cmd key | becomes Ctrl on Windows, so Cmd+C and Cmd+V work as you expect |
| Clipboard | text, Mac → PC |
| Encryption | AES-256-GCM on both transports |

## What it doesn't do

Deliberately, because each one is a source of bugs and none were wanted:

- No file drag and drop
- No screen-edge switching — the hotkey is the only way across, so the pointer
  can't wander onto the other machine by accident
- No multi-monitor geometry
- No clipboard from PC back to Mac (one direction for now)
- Nothing at the Windows lock screen. It runs as you, in your session, so log in
  with the PC's own keyboard or Windows Hello first. The alternative is a
  SYSTEM-level service, which is exactly the thing worth avoiding.

## Security

Keystrokes include passwords, so they are not sent in the clear.

- **AES-256-GCM** via CryptoKit on macOS and BCrypt on Windows. Both are
  OS-provided; there is no third-party crypto here to vendor or keep patched.
- **A shared 32-byte key**, generated once. No password-derived key, so there is
  no weak KDF to get wrong.
- **Nonces never repeat**: a per-session random prefix plus a counter.
- **Replay protection**: a sequence number and a 64-entry sliding window, so
  captured traffic can't be replayed at you later.
- **Unauthenticated packets are dropped**, never acted on.
- The receiver **releases every held key** on disconnect or a 3-second silence,
  so a dropped link can't leave Ctrl stuck down on the PC.

The key file is 0600 on macOS. Anyone who can read it can send input to your PC,
so treat it like a password.

## Protocol

[PROTOCOL.md](PROTOCOL.md) — the wire format, in enough detail to reimplement
either half.
