# kmlink wire protocol v1

Two machines, one keyboard and mouse. The Mac captures input and sends it; the
PC replays it. Exactly one machine is active at a time, chosen by a hotkey.

## Transports

| | port | why |
|---|---|---|
| Input | **UDP 24810** | Latency matters more than delivery. A lost mouse delta is self-correcting; the next one makes it up. TCP would stall everything behind a lost packet. |
| Clipboard | **TCP 24810** | Correctness matters more than latency, and it is sent rarely. Reliability for free instead of rebuilding it over UDP. |

## Encryption

AES-256-GCM, on both transports. Keystrokes include passwords; they do not go
over the air in the clear.

- **Key**: 32 bytes, shared secret, hex-encoded in the config on both machines.
  Generated once with `kmlink --genkey`. No password-derived key, so no KDF to
  get wrong.
- **Nonce**: 12 bytes — 4 random bytes chosen per session, then an 8-byte
  big-endian counter. Never reused within a session; a fresh random prefix each
  session makes reuse across sessions vanishingly unlikely.
- **On the wire**: `nonce(12) || ciphertext(N) || tag(16)`

Both platforms use an OS-provided implementation — CryptoKit on macOS, BCrypt
(CNG) on Windows — so there is no third-party crypto to vendor or keep updated.

## Replay protection

Every payload starts with a monotonic sequence number. The receiver keeps the
highest sequence seen plus a 64-entry sliding window bitmap, and drops anything
already seen or older than the window. Without this, someone who captured your
traffic could replay your keystrokes verbatim.

## Payload (plaintext, before encryption)

All integers big-endian.

```
u8   type
u32  seq
...  type-specific
```

| type | name | body | notes |
|---|---|---|---|
| 1 | MOVE | `i16 dx, i16 dy` | Relative. Lost packets self-correct. |
| 2 | BUTTON | `u8 button, u8 down` | 1=left 2=right 3=middle |
| 3 | WHEEL | `i16 dx, i16 dy` | Notches ×120, as Windows expects |
| 4 | KEY | `u16 vk, u8 down, u32 mods` | `vk` is a **Windows** virtual-key code |
| 5 | ENTER | — | Sender took control |
| 6 | LEAVE | — | Sender released control; receiver must release everything held |
| 7 | PING | — | Keepalive, ~1/sec |

### Modifier bitmask (`mods`)

`1` shift · `2` ctrl · `4` alt · `8` gui

**Every KEY packet carries the full modifier state**, not just changes. If a
key-up is lost, the next packet re-synchronises it, so a modifier cannot stick
down. This is what makes UDP safe for a keyboard.

**`vk = 0` means "modifier state only"** — no key is pressed or released. The
sender emits it when a modifier changes on its own. The receiver must still
reconcile modifiers from it; dropping it as an invalid keycode loses
Shift-click and Cmd-scroll.

### Key mapping happens on the Mac

The Mac translates its own keycodes into Windows virtual-key codes before
sending, including the Cmd→Ctrl swap. The receiver stays dumb: it takes a `vk`
and injects it. All the platform awkwardness lives on one side.

### LEAVE is a safety valve

On LEAVE — and on a 3-second gap with no packets — the receiver releases every
key and button it believes is down. A dropped connection mid-chord otherwise
leaves the PC with a stuck Ctrl.

## Clipboard frames (TCP)

```
u32  frame length (of everything that follows)
     nonce(12) || ciphertext || tag(16)
```

Plaintext: `u8 format, bytes data` — format `1` is UTF-8 text. Capped at 1 MB.

## Reliability, deliberately unequal

- **Mouse motion**: fire and forget. Relative deltas are self-correcting.
- **Keys and buttons**: sent **3×** with the same sequence number. The receiver
  de-duplicates by sequence. Loss resistance without TCP's head-of-line
  blocking — three copies of a 25-byte packet cost nothing at these rates.
- **Clipboard**: TCP.
