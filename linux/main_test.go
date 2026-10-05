package main

import (
	"encoding/binary"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// recorder stands in for /dev/uinput and keeps every frame it is handed.
type recorder struct{ frames [][]inputEvent }

func (f *recorder) inject(evs []inputEvent) error {
	f.frames = append(f.frames, append([]inputEvent(nil), evs...))
	return nil
}

func newTestReceiver() (*receiver, *recorder) {
	f := &recorder{}
	return newReceiver(f), f
}

// payload builds plaintext the way the Mac does: u8 type, u32 seq, body.
// dispatch never looks at seq; replayOK has its own test.
func payload(typ byte, body ...byte) []byte {
	return append([]byte{typ, 0, 0, 0, 1}, body...)
}

func keyPayload(vk uint16, down bool, mods uint32) []byte {
	b := binary.BigEndian.AppendUint16(nil, vk)
	if down {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return payload(tKey, binary.BigEndian.AppendUint32(b, mods)...)
}

func wheelPayload(dx, dy int16) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(dx))
	return payload(tWheel, binary.BigEndian.AppendUint16(b, uint16(dy))...)
}

func mustDispatch(t *testing.T, r *receiver, p []byte) bool {
	t.Helper()
	leave, err := r.dispatch(p)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return leave
}

func press(code uint16) inputEvent   { return inputEvent{evKey, code, 1} }
func release(code uint16) inputEvent { return inputEvent{evKey, code, 0} }

func wantFrames(t *testing.T, f *recorder, want ...[]inputEvent) {
	t.Helper()
	if !reflect.DeepEqual(f.frames, want) {
		t.Fatalf("frames\n got %v\nwant %v", f.frames, want)
	}
}

func TestVectorOpens(t *testing.T) {
	if err := checkVector(); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedTagRejected(t *testing.T) {
	aead, err := newAEAD(vectorKey[:])
	if err != nil {
		t.Fatal(err)
	}
	bad := vectorCombined
	bad[len(bad)-1] ^= 0x01
	if _, err := aead.Open(nil, bad[:nonceLen], bad[nonceLen:], nil); err == nil {
		t.Fatal("a packet with a tampered tag was accepted")
	}
}

func TestReplayWindow(t *testing.T) {
	r, _ := newTestReceiver()
	check := func(seq uint32, want bool) {
		t.Helper()
		if got := r.replayOK(seq); got != want {
			t.Fatalf("replayOK(%d) = %v, want %v", seq, got, want)
		}
	}

	check(100, true)  // the first packet is always accepted
	check(100, false) // the second and third copies of a key packet
	check(99, true)   // older, inside the window, not seen yet...
	check(99, false)  // ...but only once
	check(36, true)   // 64 behind: the oldest the window holds
	check(35, false)  // 65 behind: too old

	// A jump of exactly 64 keeps the old newest as the oldest remembered.
	r, _ = newTestReceiver()
	check(10, true)
	check(74, true)
	check(10, false)
	check(11, true)

	// A jump of more than 64 clears the window: nothing old is remembered,
	// so everything still in range is new.
	r, _ = newTestReceiver()
	check(10, true)
	check(9, true)
	check(75, true)
	check(11, true)  // 64 behind, never seen
	check(10, false) // 65 behind, too old

	// A quiet link means a new session, which may start its count again.
	if err := r.idle(); err != nil {
		t.Fatal(err)
	}
	check(1, true)
}

// Reads the table out of the Mac's source, so a key added there without a
// mapping here fails this test instead of being dropped on the handheld.
func TestEveryMacVKHasAKey(t *testing.T) {
	src, err := os.ReadFile("../mac/kmlink.swift")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "let VK:")
	if start < 0 {
		t.Fatal("no `let VK:` table in ../mac/kmlink.swift")
	}
	end := strings.Index(s[start:], "\n]")
	if end < 0 {
		t.Fatal("cannot find the end of the Mac's VK table")
	}
	pairs := regexp.MustCompile(`0x[0-9A-Fa-f]+\s*:\s*0x([0-9A-Fa-f]+)`).
		FindAllStringSubmatch(s[start:start+end], -1)
	if len(pairs) == 0 {
		t.Fatal("found no entries in the Mac's VK table")
	}
	for _, m := range pairs {
		vk, err := strconv.ParseUint(m[1], 16, 16)
		if err != nil {
			t.Fatal(err)
		}
		if vk > 0xFF || vkToKey[vk] == 0 {
			t.Errorf("the Mac sends vk 0x%02X, which has no Linux key", vk)
		}
	}
	t.Logf("checked %d keys from the Mac's table", len(pairs))
}

func TestKeyPressesModifiersFirst(t *testing.T) {
	r, f := newTestReceiver()
	mustDispatch(t, r, keyPayload(0x41, true, 1|2)) // Shift+Ctrl+A
	wantFrames(t, f, []inputEvent{press(keyLeftShift), press(keyLeftCtrl), press(30)})
}

func TestVKZeroOnlyReconcilesModifiers(t *testing.T) {
	r, f := newTestReceiver()
	mustDispatch(t, r, keyPayload(0, true, 8))  // gui goes down on its own
	mustDispatch(t, r, keyPayload(0, false, 8)) // same state again: nothing to send
	mustDispatch(t, r, keyPayload(0, false, 0)) // gui comes up
	wantFrames(t, f,
		[]inputEvent{press(keyLeftMeta)},
		[]inputEvent{release(keyLeftMeta)})
}

func TestModifierReleaseLetsGoOfBothSides(t *testing.T) {
	r, f := newTestReceiver()
	mustDispatch(t, r, keyPayload(0xA1, true, 1)) // right shift, shift in the mask
	mustDispatch(t, r, keyPayload(0, false, 0))
	wantFrames(t, f,
		[]inputEvent{press(keyLeftShift), press(keyRightShift)},
		[]inputEvent{release(keyLeftShift), release(keyRightShift)})
}

func TestLeaveReleasesEverythingHeld(t *testing.T) {
	r, f := newTestReceiver()
	mustDispatch(t, r, keyPayload(0x41, true, 2)) // Ctrl+A held
	mustDispatch(t, r, payload(tButton, 1, 1))    // left button held
	f.frames = nil

	if !mustDispatch(t, r, payload(tLeave)) {
		t.Fatal("LEAVE was not reported as a leave")
	}
	wantFrames(t, f, []inputEvent{release(keyLeftCtrl), release(30), release(btnLeft)})

	// Nothing is believed held any more, so a second LEAVE sends nothing.
	f.frames = nil
	mustDispatch(t, r, payload(tLeave))
	wantFrames(t, f)
}

func TestWheelCarriesRemainder(t *testing.T) {
	r, f := newTestReceiver()
	mustDispatch(t, r, wheelPayload(0, 60))
	mustDispatch(t, r, wheelPayload(0, 60))
	mustDispatch(t, r, wheelPayload(-60, 0))
	mustDispatch(t, r, wheelPayload(-60, 0))
	mustDispatch(t, r, wheelPayload(0, -240))
	wantFrames(t, f,
		[]inputEvent{{evRel, relWheelHiRes, 60}},
		[]inputEvent{{evRel, relWheelHiRes, 60}, {evRel, relWheel, 1}},
		[]inputEvent{{evRel, relHWheelHiRes, -60}},
		[]inputEvent{{evRel, relHWheelHiRes, -60}, {evRel, relHWheel, -1}},
		[]inputEvent{{evRel, relWheelHiRes, -240}, {evRel, relWheel, -2}})
}

func TestSystemdQuote(t *testing.T) {
	got := systemdQuote(`/home/deck/a b/100%/$x/"q"\z`)
	want := `"/home/deck/a b/100%%/$$x/\"q\"\\z"`
	if got != want {
		t.Fatalf("systemdQuote = %s, want %s", got, want)
	}
}
