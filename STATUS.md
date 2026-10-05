# Status — read this first

Written so work can continue in a fresh session with no prior context.

## Where things stand

**The Mac side works and feels good.** Against the Windows receiver, mouse and
keyboard reached the PC with no perceptible lag. Nothing on the Mac has changed
since apart from wording.

**The PC is now SteamOS, and its receiver is new.** On 2026-10-05 the ROG Ally
moved from Windows to SteamOS. The Windows receiver was removed — commit
`8946e55` is the last one that has it — and a receiver was written in Go
(`linux/`). It speaks the same protocol v1, so the Mac did not need to change.

**The SteamOS receiver has never run on the device.** It builds and passes
`go vet`. Its tests are written but have not been run yet. Everything below
about the Ally is a list of things to check, not things known.

## What is proven

| | |
|---|---|
| Network | 500 packets, **0% loss, 8.5 ms median, 1.37 ms jitter**. Measured with `tools/latency-probe`. Same Ally, same network, but measured under Windows. The network was never the problem. |
| Mac build | Compiles clean, signed with a real identity. |

**Crypto interop is not proven yet, but it is checked automatically.**
`--selftest` decrypts a fixed vector that CryptoKit produced
(`test/aes-gcm-vector.txt`), and CI runs it on the built binary on every build.
That guards the one thing both halves must agree on byte for byte: that Go's
GCM reads exactly what CryptoKit wrote. The first CI run of the `linux` job has
not happened yet. The same check passed on every Windows build against BCrypt,
so the Mac's output is ordinary AES-GCM; whether Go reads it the same way is
what that first run will say.

## Not yet proven on the device

The first run on the Ally is the test. Keep the log open while doing it:

```sh
journalctl --user -u kmlink -e
```

Roughly in the order they would get in the way:

1. **Permission to open `/dev/uinput`.** The receiver runs as the logged-in
   user and creates its virtual device through `/dev/uinput`. Steam's own udev
   rules normally let that user open it, but that is an assumption about this
   install, not something checked. If the log says permission denied, the
   candidate fix — **UNTESTED** — is a file
   `/etc/udev/rules.d/70-kmlink-uinput.rules` containing:

   ```
   KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uinput"
   ```

   As one line, then reboot (`sudo` on SteamOS needs a password set first with
   `passwd`):

   ```sh
   echo 'KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/70-kmlink-uinput.rules
   ```

   That file lives outside the home folder, so whether it survives a SteamOS
   update is a second thing to check. To see whether the device was created at
   all, look for `kmlink virtual input` in `/proc/bus/input/devices`.
2. **Nothing blocking UDP 24810.** Unlike the Windows `--install`, nothing here
   opens a firewall port. `ss -uln | grep 24810` shows whether the receiver is
   listening. If it is and the PC still does not react, read the log first: a
   wrong key says so (`failed authentication`, at most once a minute), so a
   log with nothing after `listening` means no packets are arriving at all.
   Only then look for a firewall; `sudo nft list ruleset` is one place to
   start.
3. **The service starting at boot, and surviving mode switches and sleep.** It
   is a systemd *user* service, so it lives and dies with the user's login.
   Switching between Gaming Mode and Desktop Mode ends one session and starts
   another; whether the service comes through that untouched, or restarts, or
   stops, is not known. Check `systemctl --user status kmlink` after a cold
   boot, after each kind of switch, and after waking from sleep.
4. **Games in Gaming Mode accepting the virtual device.** The kernel presents
   it like a plugged-in keyboard and mouse, which is the best case, but no
   game has seen it yet. If Desktop Mode works and Gaming Mode does not, the
   device itself is fine and the difference is in how Gaming Mode picks up
   input — that is a guess, not a finding.
5. **Scroll direction.** May need a sign flip for macOS natural scrolling.
   Never confirmed on Windows either.
6. **Punctuation keys.** The receiver injects physical key positions; SteamOS's
   keyboard layout turns them into characters. If that layout differs from the
   Mac's, keys like `` ` - = [ ] \ ; ' `` land on different characters. Type
   them into Konsole and compare.
7. **Wi-Fi power saving.** On Windows, `--install` set the radio to Maximum
   Performance, because power saving parks it between beacons and datagrams
   then arrive in bursts or not at all. On SteamOS it has not been looked at.
   `iw dev` lists the interface; `iw dev <name> get power_save` shows the
   setting.
8. **The Ally's address changing.** The Mac sends to a fixed IP. Nothing was
   ever done about this. If it stops, compare `ip -4 addr` on the Ally with the
   *Peer* line in the Mac's menu bar item. The usual fix is a DHCP reservation
   on the router.
9. **A lost key-up now repeats instead of just sticking.** Modifiers are
   repaired by every KEY packet; ordinary keys are not. If all three copies of
   a key-up are lost, the key stays down on the Ally until the same key is
   pressed again or control switches. On Windows that was invisible, because
   injected keys do not auto-repeat. On Linux the compositor repeats any held
   key, so it would type the character — or Backspace — until stopped. It
   needs three losses in a row on a network that measured 0%, and it has not
   been seen. If it ever is, pressing the key again stops it, and the fix
   belongs in the protocol, not in a timeout guess.
10. **How the cursor feels.** The Mac sends deltas it has already accelerated,
    and SteamOS may apply its own pointer acceleration on top. If the cursor
    feels wrong, try the flat acceleration profile in Desktop Mode's mouse
    settings before changing any code.

## Faults found and fixed, in order

Each was found only after the previous one was fixed. Listed because the
pattern matters: **every message that reported success was lying.**

1. `vk=0` rejected before modifier reconciliation → Shift-click lost its modifier.
2. `AXIsProcessTrusted()` only queries, never prompts → app never appeared in
   the Accessibility list, so the permission could not be granted at all.
3. A bare binary has no application identity → macOS attached the grant to the
   terminal. Fixed by shipping a signed `.app`.
4. Two bundles sharing one identifier → macOS evaluated the grant against the
   wrong copy and kept asking for a permission already granted.
5. **Input Monitoring** is a separate grant from Accessibility. Without it macOS
   silently downgrades the tap to listen-only: mouse arrives but cannot be
   suppressed, keyboard is withheld entirely.
6. Suppressing `mouseMoved` does not stop the cursor — the window server moves
   it from the HID layer. Needs `CGAssociateMouseAndMouseCursorPosition(false)`.

Faults 7 to 12 were all in installing the Windows receiver. They are written up
in this file as it stood at `8946e55` (`git show 8946e55:STATUS.md`). Two
lessons from them are built into the new receiver:

- **Every success message was lying**, so `--install` prints what `systemctl`
  really answered and then checks that the service is active, instead of
  reporting success on its own say-so.
- **Install instructions are one-line commands.** A multi-line paste once
  broke an install with no error at all. The SteamOS steps in README.md are one
  line each for that reason.

## The old open problem

**On Windows it kept stopping unpredictably, and that was never diagnosed.** It
is not known whether the cause was in the Windows receiver, in Windows, or in
something that comes with the machine and the network.

If SteamOS shows the same symptom, the two suspects that never depended on
Windows are **the Ally's address changing** and **Wi-Fi radio power saving** —
items 8 and 7 above. When it stops, read the log first and note when it stopped
and what happened just before.

**Suggestion that still holds: stop guessing.** Every fix in the faults list came
from reading actual output. The guesses in between were wrong, twice blaming
the network when measurement later showed it was fine.

## Removed

- **Switching the external display off while the PC had control.** Sound idea,
  unsound mechanism: disabling a display takes it *offline*, so it leaves the
  display list and there is no id left to re-enable. On this Mac
  `displayplacer "id:<it> enabled:true"` answers *"Unable to find screen"* and
  exits 1, and a replug did not bring it back either. `Displays.run()` threw
  the exit code away, so every failed restore reported success — the same
  failure mode as the faults above. The commit that added it said
  "leaving a display switched off with no obvious way back is a bad failure
  mode, worse than the feature is useful", which is exactly what happened.
  Removed rather than patched.
- **The Windows receiver** (`win/kmlink-win.c`), on 2026-10-05, because Windows
  is gone from the Ally. Its CI job was replaced by the `linux` one. It is last
  present at `8946e55`; `git show 8946e55:win/kmlink-win.c` brings it back. The
  `windows` rolling release is still on GitHub with its last build.

## Things deliberately left

- **Clipboard is not there yet on SteamOS.** The Windows receiver took text
  from the Mac; the SteamOS one does not listen on TCP 24810 at all. The Mac
  still sends: the connection is refused and it gives up quietly on a
  background thread (the `guard ok else { return }` in the clipboard sender in
  `mac/kmlink.swift`), so input is unaffected. Planned as the second step, once
  keys and mouse are proven on the device, because setting the clipboard on
  SteamOS depends on the session mode and on which helper tool is installed.
  PC → Mac was never implemented.
- **Scroll direction** may need a sign flip for macOS natural scrolling. Never
  confirmed either way.
- **Replay protection stops at 3 seconds of silence.** The receiver forgets
  the last sequence number when the link goes idle, so that a restarted Mac
  app, which counts from 1 again, is not locked out. The cost is that a
  recording of an earlier session would be accepted while the link is idle.
  The Windows receiver did the same. The README's "can't be replayed at you
  later" is therefore only true within a session. It needs someone on the
  same network who recorded you, and closing it is a protocol change.
- **The encryption key was pasted into a chat transcript** and should be
  rotated: `kmlink --genkey`, then move it across with
  `python3 -m http.server` rather than by pasting. Setting up SteamOS is the
  natural moment, since the key has to be put on it anyway. Reopen the Mac app
  afterwards so it loads the new key.

## Layout

```
mac/kmlink.swift     sender: event tap, UDP, clipboard, menu bar
linux/main.go        receiver: UDP -> /dev/uinput, Go standard library only
linux/main_test.go   its tests; CI runs them with go vet
PROTOCOL.md          wire format; both halves must agree byte for byte
build-mac.sh         builds and installs the signed .app
build-linux.sh       builds out/kmlink-linux, a static linux/amd64 binary
tools/latency-probe  throwaway; delete once the network question stays settled
```

## Why it is built this way

Barrier felt laggy on this network. Measurement showed the network was fine, so
the causes were architectural: TCP with absolute coordinates replays stale
positions after any stall, and its Windows client posted every event to a second
thread and blocked waiting for it. kmlink uses UDP with relative deltas, which
are self-correcting, and injects on the receiving thread. That part worked on
the first try and has never been the problem.
