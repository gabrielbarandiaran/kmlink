# Status — read this first

Written so work can continue in a fresh session with no prior context.

## Where things stand

**The Mac side works and feels good.** Mouse and keyboard reach the PC with no
perceptible lag. The design bet paid off.

**The Windows side is functional but starts unreliably.** Once running it works;
getting it running and keeping it running has been the whole problem. Every
fault so far has been in *starting* it, never in the protocol or the crypto.

## What is proven

| | |
|---|---|
| Network | 500 packets, **0% loss, 8.5 ms median, 1.37 ms jitter**. Measured with `tools/latency-probe`. The network was never the problem. |
| Crypto interop | CryptoKit ⇄ BCrypt AES-256-GCM verified in CI on every build (`--selftest`) against a fixed vector. |
| Windows build | Compiles clean at `/W4` on MSVC. |
| Mac build | Compiles clean, signed with a real identity. |

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
7. `--install` held the single-instance mutex while spawning the real instance,
   which then exited as "already running", leaving nothing listening.
8. Task action quoted twice → registered as `\"C:\path\exe\"`. `schtasks` does
   not validate paths, and `/run` only reports that it *attempted*, so both
   reported success while nothing ran.
9. `schtasks /create` defaults `DisallowStartIfOnBatteries` and
   `StopIfGoingOnBatteries` to true, and caps runtime at 72h. On a handheld
   that means it never starts. Fixed with an XML task definition.

## Open — the current problem

**It still stops working unpredictably.** Not yet diagnosed. The log is now
timestamped, which it was not for any of the above, so the next attempt should
start there:

```powershell
type "$env:LOCALAPPDATA\kmlink\kmlink.log"
```

The question to answer is **when it stopped and what happened just before** —
unplugged, slept, changed network, logged out, game launched.

Candidates not yet ruled out:

- Task stopping on sleep/resume (`StartWhenAvailable` may not cover it)
- The Ally's power management killing the process independently of the task
- The receiver exiting on a `recvfrom` error path
- Wi-Fi address changing (the Mac targets a fixed IP in `host.txt`)

**Suggestion for the next session: stop guessing.** Every fix above came from
reading actual output — `schtasks /query /v`, the empty process list, the
`Power Management` line. The guesses in between were wrong, twice blaming the
network when measurement later showed it was fine.

## Removed

- **Switching the external display off while the PC had control.** Sound idea,
  unsound mechanism: disabling a display takes it *offline*, so it leaves the
  display list and there is no id left to re-enable. On this Mac
  `displayplacer "id:<it> enabled:true"` answers *"Unable to find screen"* and
  exits 1, and a replug did not bring it back either. `Displays.run()` threw
  the exit code away, so every failed restore reported success — the same
  failure mode as the nine faults above. The commit that added it said
  "leaving a display switched off with no obvious way back is a bad failure
  mode, worse than the feature is useful", which is exactly what happened.
  Removed rather than patched.

## Things deliberately left

- **Clipboard is Mac → PC only.** Reverse direction not implemented.
- **Scroll direction** may need a sign flip for macOS natural scrolling. Never
  confirmed either way.
- **Games**: `SendInput` is refused under UIPI when the focused window is
  elevated — the task runs elevated to address this. If input is still ignored
  with no `SendInput refused` in the log, the game filters injected input and
  no user-space program can fix it.
- **The encryption key was pasted into a chat transcript** and should be
  rotated: `kmlink --genkey`, then move it across with
  `python3 -m http.server` rather than by pasting.

## Layout

```
mac/kmlink.swift     sender: event tap, UDP, clipboard, menu bar
win/kmlink-win.c     receiver: single-threaded recvfrom -> SendInput
PROTOCOL.md          wire format; both halves must agree byte for byte
build-mac.sh         builds and installs the signed .app
tools/latency-probe  throwaway; delete once the network question stays settled
```

## Why it is built this way

Barrier felt laggy on this network. Measurement showed the network was fine, so
the causes were architectural: TCP with absolute coordinates replays stale
positions after any stall, and its Windows client posted every event to a second
thread and blocked waiting for it. kmlink uses UDP with relative deltas, which
are self-correcting, and injects on the receiving thread. That part worked on
the first try and has never been the problem.
