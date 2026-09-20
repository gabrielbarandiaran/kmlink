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
10. That XML task definition had never run. `fopen(path, "w, ccs=UTF-16LE")`
    puts the stream into the CRT's Unicode translation mode, where the narrow
    `printf` family is an invalid parameter: nothing is written while `fopen`
    and `fclose` both report success. `schtasks` read the resulting two-byte
    BOM and said *"The task XML is malformed"* — naming the XML, which was
    innocent. Fixed by converting with `MultiByteToWideChar` and writing bytes.
11. The fix for the *reporting* of 10 broke it again. schtasks' output was
    redirected into `kmlink.log`, which this process holds open, so `cmd.exe`
    could not open it for append and the command never ran at all — reported
    identically to the command running and failing. Now via a scratch file.
12. Not a code fault, but the same shape and it cost a round trip: the install
    instructions used a PowerShell backtick line continuation, which does not
    survive a multi-line paste into the console. `Invoke-WebRequest` ran with
    no URL, the download silently did not happen, and the log being read was
    the previous run's. **Hand over one-line commands.**

Installing successfully on 2026-09-20 took 10, 11 and 12 in sequence, each
found only after the last was cleared — the same pattern as 1 through 9, and
the same cause: the component reporting the error was never the one at fault.

## Open — the current problem

**It still stops working unpredictably.** Still not diagnosed. As of
2026-09-20 the receiver installs and runs correctly for the first time, on a
build that has all of the above — so nothing before now tested whether the
unpredictable stopping survives the fixes. It may already be gone. Watch it
over a few days of real use, unplugged, before concluding anything.

When it next stops, the log from that failure is the thing to read:

```powershell
type "$env:LOCALAPPDATA\kmlink\kmlink.log"
```

The question is **when it stopped and what happened just before**. The log can
now answer that without being asked: it records AC↔battery transitions, and it
notices its own absence. A loop pass is capped at the 500 ms recv timeout,
while `GetTickCount64` keeps counting through suspend, so any much larger gap
prints `N s gap -- asleep, or this process was frozen`. An overnight stop
should now say whether the machine slept.

Also worth reading, and available for failures that have *already* happened:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'} -MaxEvents 40 |
    Format-Table TimeCreated, Id, Message -Auto
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 40 |
    Where-Object { $_.Message -match 'kmlink' } | Format-Table TimeCreated, Id, Message -Auto
```

Candidates, and where each now stands:

| Candidate | Status |
|---|---|
| Task gated on mains power | **Ruled out** — XML sets both battery settings false. Verify with `schtasks /query /tn kmlink /xml`. |
| Nothing restarts it once it stops | **Addressed** — `RestartOnFailure`, plus a `SessionUnlock` trigger so a resume starts it if it died. |
| Receiver exiting on a `recvfrom` error | **Addressed** — it rebuilds the listener and logs the error code instead of returning 1. |
| Wi-Fi radio power saving parking the receiver | **Addressed** — `--install` sets the wireless adapter to Maximum Performance on AC and DC. |
| Wi-Fi address changing (the Mac targets a fixed IP) | **Open.** Nothing done. |
| The Ally suspending the process itself | **Open**, but now visible: the gap line fires when it happens. |

None of the four addressed rows is a diagnosis. They remove ways for a stop to
be permanent or invisible; the log from the next failure is what identifies the
cause.

**Suggestion that still holds: stop guessing.** Every fix in the list above came
from reading actual output. The guesses in between were wrong, twice blaming
the network when measurement later showed it was fine.

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
- **The clipboard thread never rebinds.** If its listener socket goes bad
  it spins on `accept` at 10 Hz forever — harmless to input, but it is a
  battery drain on a handheld and it will never recover on its own.
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
