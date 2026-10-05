# kmlink

Use your MacBook's keyboard and trackpad on a SteamOS handheld (here, an ROG
Ally — "the PC" below). Switch with a hotkey.

Two small programs and a shared key. Nothing to configure beyond the PC's
address, and no screen-edge geometry to get right.

```
Cmd+Ctrl+→    input goes to the PC
Cmd+Ctrl+←    input comes back to the Mac
```

Everything is encrypted. The clipboard does not follow along yet on SteamOS —
see [What it doesn't do](#what-it-doesnt-do).

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
cp -R kmlink.app /Applications/
/Applications/kmlink.app/Contents/MacOS/kmlink --genkey
/Applications/kmlink.app/Contents/MacOS/kmlink --set-host 192.168.1.50
```

`--genkey` prints a 64-character key and saves it (mode 0600). You need it in
step 2. `--set-host` is the PC's address, remembered so the app can be launched
with no arguments; step 2 shows how to find it.

Then **open the app once**:

```sh
open /Applications/kmlink.app
```

It asks for Accessibility permission and registers itself in **System Settings
→ Privacy & Security → Accessibility**. Enable it there, then open it again.

> **Why an .app and not just a binary.** macOS attaches an Accessibility grant
> to an *application identity*. A loose executable has none, so the permission
> lands on your terminal instead — or cannot be added at all, because the "+"
> button will not usefully take a bare binary. The app also has to *ask*:
> `AXIsProcessTrusted()` only queries and never prompts, so an app that only
> queries never appears in the list to be enabled.
>
> The bundle is signed with a real certificate rather than ad-hoc, because an
> ad-hoc signature changes on every rebuild and macOS then treats each build as
> a different app and drops the grant.

### 2. SteamOS

**Not yet tried on the device.** The SteamOS receiver builds, but it has never
run on the Ally. [STATUS.md](STATUS.md) lists what to watch the first time.

On the PC, switch to Desktop Mode and open Konsole. Every command below is a
single line on purpose — a multi-line paste once broke an install without any
error — so paste them one at a time.

```sh
mkdir -p ~/.local/bin ~/.config/kmlink
curl -fL -o ~/.local/bin/kmlink.new https://github.com/gabrielbarandiaran/kmlink/releases/download/linux/kmlink-linux
chmod +x ~/.local/bin/kmlink.new
mv ~/.local/bin/kmlink.new ~/.local/bin/kmlink
```

`-f` matters: without it, a missing file is saved as an error page and curl
still reports success. The download lands under a second name and is moved
into place because Linux refuses to overwrite a program while it is running —
which, once installed, it always is — but does allow moving a new file over
it. The same lines are how you update it later; run `--install` again
afterwards to restart on the new copy.

Everything goes in your home folder on purpose: SteamOS replaces its system
partition when it updates, so anything installed outside home would vanish.
CI rebuilds that download on every push. To build it yourself instead, run
`./build-linux.sh` on the Mac and copy `out/kmlink-linux` across, again under
a second name and then moved into place.

Put the key from step 1 in `~/.config/kmlink/key.txt`. Both machines must have
identical keys. The easy way across, rather than typing 64 characters on a
handheld, is to serve it from the Mac for a moment. On the Mac:

```sh
python3 -m http.server 8000 --directory ~/Library/Application\ Support/kmlink
```

On the PC, with the Mac's address in place of this one:

```sh
curl -f -o ~/.config/kmlink/key.txt http://192.168.1.20:8000/key.txt
```

Stop the server on the Mac with Ctrl+C straight away: while it runs, anyone on
the network can fetch the key. Then make it readable only by you:

```sh
chmod 600 ~/.config/kmlink/key.txt
```

Install it so it starts on its own:

```sh
~/.local/bin/kmlink --install
```

That writes a systemd user service to `~/.config/systemd/user/kmlink.service`,
enables it and restarts it. It then prints what `systemctl` actually answered
and checks the service is active, rather than reporting success on its own
say-so — on Windows, the success messages the installer relied on turned out to
be lying, more than once. If the receiver hits a serious error it logs it and
exits, and systemd starts it again, with no limit on retries.
`--uninstall` removes the service.

The PC's address, for the Mac's `--set-host`, is the `inet` line on the Wi-Fi
interface, without the part after the slash:

```sh
ip -4 addr
```

The log:

```sh
journalctl --user -u kmlink -e
```

### 3. Go

On the Mac:

```sh
open /Applications/kmlink.app
```

Press **Cmd+Ctrl+→**. The PC now has your keyboard and mouse. **Cmd+Ctrl+←**
takes it back.

The PC sees them as one virtual keyboard-and-mouse named *kmlink virtual
input*, created through `/dev/uinput`. The kernel treats it like a plugged-in
keyboard and mouse, so Gaming Mode and Desktop Mode should both see it.

## What it does

| | |
|---|---|
| Mouse | move, left/right/middle, scroll |
| Keyboard | letters, digits, punctuation, F1–F12, arrows, navigation, modifiers |
| Cmd key | becomes Ctrl on the PC, so Cmd+C and Cmd+V work as you expect |
| Clipboard | not there yet on SteamOS (see below) |
| Encryption | AES-256-GCM on everything the Mac sends |

## External monitors

kmlink does not touch your display configuration. If one monitor is wired to
both machines, switch its input with its own buttons.

An earlier version turned the external display off while the PC had control,
using `displayplacer`. That is removed: disabling a display takes it offline,
so it leaves the display list and there is no longer an id to address. On this
Mac `displayplacer "id:<it> enabled:true"` answers *"Unable to find screen"*
and exits 1 — displayplacer's own notes warn you may have to unplug and replug
the cable to get the screen back. A feature that can strand a monitor is worse
than no feature.

## What it doesn't do

Deliberately, because each one is a source of bugs and none were wanted:

- No file drag and drop
- No screen-edge switching — the hotkey is the only way across, so the pointer
  can't wander onto the other machine by accident
- No multi-monitor geometry

And one that is only *not yet*:

- **No clipboard.** The Windows receiver took text from the Mac; the SteamOS one
  does not yet. Setting the clipboard on SteamOS depends on whether it is in
  Gaming Mode or Desktop Mode, and on which helper tool is installed, so it
  waits until keys and mouse are proven on the device. Meanwhile the Mac still
  tries to send it: the connection is refused and the Mac gives up quietly in
  the background, so input is unaffected. PC → Mac was never there.

## Security

Keystrokes include passwords, so they are not sent in the clear.

- **AES-256-GCM** via CryptoKit on macOS and Go's standard library on SteamOS.
  Neither is third-party, so there is no crypto here to vendor. Go's is
  compiled into the binary, so a Go security fix reaches the PC only with a
  rebuild.
- **A shared 32-byte key**, generated once. No password-derived key, so there is
  no weak KDF to get wrong.
- **Nonces never repeat**: a per-session random prefix plus a counter.
- **Replay protection**: a sequence number and a 64-entry sliding window, so
  captured traffic can't be replayed at you later.
- **Unauthenticated packets are dropped**, never acted on.
- The receiver **releases every held key** on disconnect or a 3-second silence,
  so a dropped link can't leave Ctrl stuck down on the PC.

The key file is 0600 on both machines (on the PC, setup step 2 does that).
Anyone who can read it can send input to your PC, so treat it like a password.

## Protocol

[PROTOCOL.md](PROTOCOL.md) — the wire format, in enough detail to reimplement
either half.
