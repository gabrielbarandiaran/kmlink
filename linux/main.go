// kmlink -- SteamOS receiver.  Wire format is PROTOCOL.md; the Mac side is
// written against the same document and the two must agree byte for byte.
// It replaces the Windows receiver and keeps that receiver's behaviour
// wherever the platform allows.
//
// A datagram goes from the socket straight into /dev/uinput on one goroutine
// with nothing in between.  Barrier's client hands every event to a separate
// thread and waits for it -- a full cross-thread round trip per keystroke and
// per mouse move.  That is the lag being removed here, so do not add a
// goroutine, a channel or a queue to the input path.
//
// Standard library only, no cgo: the binary has to be one static file that
// survives SteamOS replacing its system partition (see build-linux.sh).  The
// uinput calls are raw syscalls with Linux's numbers spelled out and no build
// tags, so the whole program, tests included, also builds and vets on the Mac
// it is written on.  Anywhere but Linux it stops at opening /dev/uinput.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	port         = 24810
	nonceLen     = 12
	tagLen       = 16
	hdrLen       = 5 // u8 type + u32 seq
	pktMin       = nonceLen + hdrLen + tagLen
	pktMax       = 512
	idleTimeout  = 3 * time.Second
	recvTimeout  = 500 * time.Millisecond
	badAuthEvery = time.Minute
)

const (
	tMove   = 1
	tButton = 2
	tWheel  = 3
	tKey    = 4
	tEnter  = 5
	tLeave  = 6
)

// linux/input-event-codes.h, the few this program uses.
const (
	evSyn = 0
	evKey = 1
	evRel = 2

	synReport = 0

	keyLeftCtrl   = 29
	keyLeftShift  = 42
	keyRightShift = 54
	keyLeftAlt    = 56
	keyRightCtrl  = 97
	keyRightAlt   = 100
	keyLeftMeta   = 125
	keyRightMeta  = 126

	btnLeft   = 0x110
	btnRight  = 0x111
	btnMiddle = 0x112

	relX           = 0x00
	relY           = 0x01
	relHWheel      = 0x06
	relWheel       = 0x08
	relWheelHiRes  = 0x0b
	relHWheelHiRes = 0x0c

	busVirtual = 0x06
)

// ------------------------------------------------------------------ keymap

// Windows virtual-key code -> evdev key code.  The Mac sends Windows codes
// because the first receiver handed them straight to SendInput; translating
// them here leaves the wire format and the Mac untouched.  0 means no mapping,
// which is safe because KEY_RESERVED is never a real key.
var vkToKey = [256]uint16{
	// letters A..Z
	0x41: 30, 0x42: 48, 0x43: 46, 0x44: 32, 0x45: 18, 0x46: 33, 0x47: 34,
	0x48: 35, 0x49: 23, 0x4A: 36, 0x4B: 37, 0x4C: 38, 0x4D: 50, 0x4E: 49,
	0x4F: 24, 0x50: 25, 0x51: 16, 0x52: 19, 0x53: 31, 0x54: 20, 0x55: 22,
	0x56: 47, 0x57: 17, 0x58: 45, 0x59: 21, 0x5A: 44,
	// digits 0..9
	0x30: 11, 0x31: 2, 0x32: 3, 0x33: 4, 0x34: 5,
	0x35: 6, 0x36: 7, 0x37: 8, 0x38: 9, 0x39: 10,
	// enter, tab, space, backspace, escape, forward delete
	0x0D: 28, 0x09: 15, 0x20: 57, 0x08: 14, 0x1B: 1, 0x2E: 111,
	// left, up, right, down; home, end, page up, page down
	0x25: 105, 0x26: 103, 0x27: 106, 0x28: 108,
	0x24: 102, 0x23: 107, 0x21: 104, 0x22: 109,
	// - = [ ] \ ; ' , . / `
	0xBD: 12, 0xBB: 13, 0xDB: 26, 0xDD: 27, 0xDC: 43, 0xBA: 39,
	0xDE: 40, 0xBC: 51, 0xBE: 52, 0xBF: 53, 0xC0: 41,
	// F1..F12
	0x70: 59, 0x71: 60, 0x72: 61, 0x73: 62, 0x74: 63, 0x75: 64,
	0x76: 65, 0x77: 66, 0x78: 67, 0x79: 68, 0x7A: 87, 0x7B: 88,
	// Modifiers.  The Mac sends modifier state as a mask, not as keys, but
	// the Windows receiver accepted these and so does this one.
	0x10: keyLeftShift, 0xA0: keyLeftShift, 0xA1: keyRightShift,
	0x11: keyLeftCtrl, 0xA2: keyLeftCtrl, 0xA3: keyRightCtrl,
	0x12: keyLeftAlt, 0xA4: keyLeftAlt, 0xA5: keyRightAlt,
	0x5B: keyLeftMeta, 0x5C: keyRightMeta,
}

var btnCode = [3]uint16{btnLeft, btnRight, btnMiddle} // [button-1]

// What we press when a modifier has to go down, and every key that counts as
// that modifier being down.  Mask bit i is row i: shift, ctrl, alt, gui.
var modPress = [4]uint16{keyLeftShift, keyLeftCtrl, keyLeftAlt, keyLeftMeta}
var modSides = [4][2]uint16{
	{keyLeftShift, keyRightShift},
	{keyLeftCtrl, keyRightCtrl},
	{keyLeftAlt, keyRightAlt},
	{keyLeftMeta, keyRightMeta},
}

// ---------------------------------------------------------------- receiver

type inputEvent struct {
	typ, code uint16
	value     int32
}

// injector delivers one packet's events as a single input frame.  The real
// one is /dev/uinput; the tests put a recorder here instead.
type injector interface {
	inject(evs []inputEvent) error
}

type receiver struct {
	out     injector
	evs     []inputEvent // the frame being built, reused for every packet
	seqMax  uint32
	window  uint64 // bit i set => seqMax-1-i was seen
	haveSeq bool
	keyDown [256]bool // evdev code -> we injected a down with no matching up
	btnDown uint      // bit 0/1/2 = left/right/middle
	wheelX  int32     // scroll not yet sent as whole notches, in 1/120ths
	wheelY  int32
	warned  [256]bool // vk -> already logged as having no Linux key
}

func newReceiver(out injector) *receiver {
	return &receiver{out: out, evs: make([]inputEvent, 0, 32)}
}

// Highest sequence seen plus a 64-bit bitmap of the ones below it.  Key and
// button packets are deliberately sent three times with the same sequence
// number, so rejecting duplicates here is what stops every keystroke being
// injected three times -- it is load-bearing, not a hardening extra.
func (r *receiver) replayOK(seq uint32) bool {
	if !r.haveSeq {
		r.haveSeq = true
		r.seqMax = seq
		r.window = 0
		return true
	}
	if seq > r.seqMax {
		diff := seq - r.seqMax
		switch {
		case diff == 64:
			r.window = 1 << 63 // the old newest is now the oldest we remember
		case diff > 64:
			r.window = 0
		default:
			r.window = r.window<<diff | uint64(1)<<(diff-1)
		}
		r.seqMax = seq
		return true
	}
	diff := r.seqMax - seq
	if diff == 0 || diff > 64 { // the newest, or too old
		return false
	}
	bit := uint64(1) << (diff - 1)
	if r.window&bit != 0 {
		return false
	}
	r.window |= bit
	return true
}

func (r *receiver) emit(typ, code uint16, value int32) {
	r.evs = append(r.evs, inputEvent{typ, code, value})
}

func (r *receiver) key(code uint16, down bool) {
	var v int32
	if down {
		v = 1
	}
	r.emit(evKey, code, v)
	r.keyDown[code] = down
}

func (r *receiver) button(i uint, down bool) { // i 0..2
	var v int32
	if down {
		v = 1
	}
	r.emit(evKey, btnCode[i], v)
	if down {
		r.btnDown |= 1 << i
	} else {
		r.btnDown &^= 1 << i
	}
}

func (r *receiver) modsHeld() uint32 {
	var m uint32
	for i, sides := range modSides {
		for _, code := range sides {
			if r.keyDown[code] {
				m |= 1 << i
			}
		}
	}
	return m
}

// Every KEY packet carries the whole modifier bitmask, so a lost key-up is
// repaired here instead of leaving a modifier stuck down.  "Held" is derived
// from the keys we injected, never from the system's key state: the
// handheld's own controls are on this machine too, and we must neither fight
// them nor release keys we never pressed.
func (r *receiver) reconcileMods(want uint32) {
	have := r.modsHeld()
	for i := range modPress {
		bit := uint32(1) << i
		switch {
		case want&bit != 0 && have&bit == 0:
			r.key(modPress[i], true)
		case want&bit == 0 && have&bit != 0:
			for _, code := range modSides[i] { // let go of every side
				if r.keyDown[code] {
					r.key(code, false)
				}
			}
		}
	}
}

func (r *receiver) releaseAll() {
	for code, down := range r.keyDown {
		if down {
			r.key(uint16(code), false)
		}
	}
	for i := uint(0); i < 3; i++ {
		if r.btnDown&(1<<i) != 0 {
			r.button(i, false)
		}
	}
}

// v is in 1/120ths of a notch, as Windows counts them.  Smooth scrolling reads
// the high-resolution axis as it is.  Readers that only know REL_WHEEL need
// whole notches, so what does not make one yet is carried to the next packet
// rather than rounded away -- otherwise a slow scroll never moves them at all.
func (r *receiver) wheel(rem *int32, hiRes, notch uint16, v int32) {
	if v == 0 {
		return
	}
	r.emit(evRel, hiRes, v)
	*rem += v
	if n := *rem / 120; n != 0 {
		r.emit(evRel, notch, n)
		*rem -= n * 120
	}
}

// flush sends the frame built so far.  The frame is dropped whether or not
// that worked: a failed write is fatal, and the caller is on its way out.
func (r *receiver) flush() error {
	if len(r.evs) == 0 {
		return nil
	}
	err := r.out.inject(r.evs)
	r.evs = r.evs[:0]
	return err
}

func be16s(p []byte) int32 { return int32(int16(binary.BigEndian.Uint16(p))) }

// p is decrypted plaintext with len(p) >= hdrLen.  Reports whether it was a
// LEAVE, and any failure to inject, which the caller treats as fatal.
func (r *receiver) dispatch(p []byte) (leave bool, err error) {
	switch p[0] {
	case tMove:
		if len(p) < hdrLen+4 {
			return false, nil
		}
		if dx := be16s(p[5:]); dx != 0 {
			r.emit(evRel, relX, dx)
		}
		if dy := be16s(p[7:]); dy != 0 {
			r.emit(evRel, relY, dy)
		}

	case tButton:
		if len(p) < hdrLen+2 || p[5] < 1 || p[5] > 3 {
			return false, nil
		}
		r.button(uint(p[5]-1), p[6] != 0)

	case tWheel:
		if len(p) < hdrLen+4 {
			return false, nil
		}
		// Signs pass through unchanged, as they did into SendInput: on both
		// systems positive means away from the user, and to the right.
		r.wheel(&r.wheelY, relWheelHiRes, relWheel, be16s(p[7:]))
		r.wheel(&r.wheelX, relHWheelHiRes, relHWheel, be16s(p[5:]))

	case tKey:
		if len(p) < hdrLen+7 {
			return false, nil
		}
		vk := binary.BigEndian.Uint16(p[5:])
		if vk > 0xFF { // not a Windows vk
			return false, nil
		}
		r.reconcileMods(binary.BigEndian.Uint32(p[8:]))
		// vk 0 carries modifier state only: the sender emits it when a
		// modifier changes on its own.  Rejecting it before reconciling
		// means holding Shift or Cmd alone never reaches us, and Shift-click
		// loses its modifier.
		if vk != 0 {
			if code := vkToKey[vk]; code != 0 {
				r.key(code, p[7] != 0)
			} else if !r.warned[vk] {
				// Once per vk: this sits on the input path, and a key the
				// table lacks would otherwise log on every press.
				r.warned[vk] = true
				log.Printf("kmlink: no Linux key for vk 0x%02x, ignoring it", vk)
			}
		}

	case tEnter:
		// Nothing should be held when the sender takes control.  If a LEAVE
		// went missing this is the only thing that clears it, because a
		// steady stream of pings keeps the idle timer from ever firing.
		r.releaseAll()

	case tLeave:
		r.releaseAll()
		leave = true

	default: // PING, and unknown
	}
	return leave, r.flush()
}

// A gap means a new session: let go of everything, and let its sequence
// numbers restart.
func (r *receiver) idle() error {
	r.releaseAll()
	r.haveSeq = false
	return r.flush()
}

// After a fatal error.  Best effort: if injecting is what failed, this fails
// too, and exiting closes the device, at which point the kernel lets go of
// every key it still held.
func (r *receiver) giveUp() {
	r.evs = r.evs[:0]
	r.releaseAll()
	_ = r.flush()
}

// ------------------------------------------------------------------ uinput

// The _IOW/_IO request numbers from linux/uinput.h as they come out on
// x86_64.  Spelled out because the standard library has no uinput.
const (
	uiSetEvBit  = 0x40045564
	uiSetKeyBit = 0x40045565
	uiSetRelBit = 0x40045566
	uiDevSetup  = 0x405c5503 // carries sizeof(struct uinput_setup), 92
	uiDevCreate = 0x5501
)

const eventSize = 24 // struct input_event on 64-bit: timeval(16) u16 u16 s32

type uinput struct {
	fd  int
	buf []byte // one frame of struct input_event, reused for every packet
}

func ioctl(fd int, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, arg); e != 0 {
		return e
	}
	return nil
}

func openUinput() (*uinput, error) {
	fd, err := syscall.Open("/dev/uinput", syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("cannot open /dev/uinput: %v\n"+
				"        This user is not allowed to create input devices; see STATUS.md in the repo.", err)
		}
		return nil, fmt.Errorf("cannot open /dev/uinput: %v", err)
	}
	fail := func(what string, e error) (*uinput, error) {
		syscall.Close(fd)
		return nil, fmt.Errorf("%s on /dev/uinput failed: %v", what, e)
	}

	// No EV_REP.  The compositor repeats held keys itself, and the Mac's own
	// repeated key-downs change no key state, so the kernel drops them.
	// Kernel repeat on top would be a third source of repeats.
	if err := ioctl(fd, uiSetEvBit, evKey); err != nil {
		return fail("UI_SET_EVBIT EV_KEY", err)
	}
	if err := ioctl(fd, uiSetEvBit, evRel); err != nil {
		return fail("UI_SET_EVBIT EV_REL", err)
	}
	// The kernel silently discards events for codes not enabled here, so a
	// key missing from this list fails with no symptom but silence.
	for _, code := range vkToKey {
		if code == 0 {
			continue
		}
		if err := ioctl(fd, uiSetKeyBit, uintptr(code)); err != nil {
			return fail(fmt.Sprintf("UI_SET_KEYBIT %d", code), err)
		}
	}
	for _, code := range btnCode {
		if err := ioctl(fd, uiSetKeyBit, uintptr(code)); err != nil {
			return fail(fmt.Sprintf("UI_SET_KEYBIT 0x%x", code), err)
		}
	}
	for _, code := range []uint16{relX, relY, relHWheel, relWheel, relWheelHiRes, relHWheelHiRes} {
		if err := ioctl(fd, uiSetRelBit, uintptr(code)); err != nil {
			return fail(fmt.Sprintf("UI_SET_RELBIT 0x%x", code), err)
		}
	}

	// struct uinput_setup: input_id{bustype, vendor, product, version},
	// char name[80], u32 ff_effects_max.
	var setup [92]byte
	binary.LittleEndian.PutUint16(setup[0:], busVirtual)
	copy(setup[8:88], "kmlink virtual input")
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uiDevSetup,
		uintptr(unsafe.Pointer(&setup))); e != 0 {
		return fail("UI_DEV_SETUP", e)
	}
	if err := ioctl(fd, uiDevCreate, 0); err != nil {
		return fail("UI_DEV_CREATE", err)
	}
	return &uinput{fd: fd, buf: make([]byte, 0, 32*eventSize)}, nil
}

func appendEvent(b []byte, e inputEvent) []byte {
	var stamp [16]byte // the kernel stamps its own time and ignores ours
	b = append(b, stamp[:]...)
	b = binary.LittleEndian.AppendUint16(b, e.typ)
	b = binary.LittleEndian.AppendUint16(b, e.code)
	return binary.LittleEndian.AppendUint32(b, uint32(e.value))
}

// The whole packet goes down in one write, SYN_REPORT included: one kernel
// crossing per packet instead of one per event, on the path this program
// exists to keep short.
func (u *uinput) inject(evs []inputEvent) error {
	b := u.buf[:0]
	for _, e := range evs {
		b = appendEvent(b, e)
	}
	b = appendEvent(b, inputEvent{evSyn, synReport, 0})
	u.buf = b

	// A raw write is not retried on EINTR the way os.File's is, and the Go
	// runtime signals its own threads, so retry here rather than die on it.
	for {
		n, err := syscall.Write(u.fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n != len(b) {
			return fmt.Errorf("short write (%d of %d bytes)", n, len(b))
		}
		return nil
	}
}

// ------------------------------------------------------------------- crypto

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block) // 12-byte nonce, 16-byte tag: what CryptoKit uses
}

// ----------------------------------------------------------------- key file

func keyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "kmlink", "key.txt"), nil
}

func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if len(s) != 64 {
		return nil, fmt.Errorf("expected 64 hex characters, found %d", len(s))
	}
	k, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("expected 64 hex characters, found something else")
	}
	return k, nil
}

// loadKey reports its own failure, because --install refuses for exactly the
// same reasons the receiver does and should say so in the same words.
func loadKey() (string, []byte, bool) {
	path, err := keyPath()
	if err != nil {
		log.Printf("kmlink: cannot find the config folder: %v", err)
		return "", nil, false
	}
	k, err := readKey(path)
	if err != nil {
		log.Printf("kmlink: no usable key at %s\n"+
			"        (%v)\n"+
			"        Run `kmlink --genkey` on the Mac, then save the 64-character\n"+
			"        hex key it prints into that file:  mkdir -p %s",
			path, err, filepath.Dir(path))
		return path, nil, false
	}
	return path, k, true
}

// --------------------------------------------------------------------- run

// No signal handling.  When systemd stops us the process exits, the uinput
// fd closes, the device is destroyed, and the kernel releases every key and
// button it still held -- nothing is left stuck down.
func run() int {
	path, raw, ok := loadKey()
	if !ok {
		return 1
	}
	aead, err := newAEAD(raw)
	if err != nil {
		log.Printf("kmlink: AES-GCM setup failed: %v", err)
		return 1
	}

	// Binding the port is the single-instance lock: a second copy fails
	// here, before it has created a second virtual device.  The receive
	// timeout is how the loop notices a dead link without a second
	// goroutine holding a timer.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		log.Printf("kmlink: cannot listen on udp %d: %v\n"+
			"        Is another kmlink already running?  systemctl --user status kmlink", port, err)
		return 1
	}
	dev, err := openUinput()
	if err != nil {
		log.Printf("kmlink: %v", err)
		return 1
	}
	r := newReceiver(dev)
	log.Printf("kmlink: listening on udp %d, key loaded from %s", port, path)

	var (
		dgram, plain [pktMax]byte
		lastRx       time.Time
		linked       bool
		peer         netip.AddrPort
		havePeer     bool
		badAuth      int
		badAuthAt    time.Time
	)
	for {
		conn.SetReadDeadline(time.Now().Add(recvTimeout))
		n, from, rerr := conn.ReadFromUDPAddrPort(dgram[:])

		// Checked every pass and not only on a timeout: a flood of packets
		// we go on to reject must not disguise a dead link.
		now := time.Now()
		if linked && now.Sub(lastRx) >= idleTimeout {
			linked = false
			if err := r.idle(); err != nil {
				log.Printf("kmlink: injecting input failed: %v", err)
				r.giveUp()
				return 1
			}
			log.Print("kmlink: link idle, released everything held")
		}

		if rerr != nil {
			if errors.Is(rerr, os.ErrDeadlineExceeded) {
				continue
			}
			// The Windows receiver rebuilt its socket here, because nothing
			// restarted it.  systemd does (Restart=always, no start limit),
			// so exit and let the journal show the restart instead of
			// growing a recovery loop.
			log.Printf("kmlink: receive failed: %v", rerr)
			r.giveUp()
			return 1
		}
		if n < pktMin {
			continue
		}
		// A bad tag is dropped, and said at most once a minute.  Anyone on
		// the network can send us garbage, so it must not be able to fill
		// the journal; but saying nothing at all makes a wrong key look
		// exactly like no packets arriving, and that sends the reader off
		// to look for a firewall that is not there.
		p, err := aead.Open(plain[:0], dgram[:nonceLen], dgram[nonceLen:n], nil)
		if err != nil {
			badAuth++
			if now.Sub(badAuthAt) >= badAuthEvery {
				log.Printf("kmlink: %d packet(s) failed authentication, last from %s -- is the key the same on both machines?",
					badAuth, from.Addr())
				badAuth = 0
				badAuthAt = now
			}
			continue
		}
		if len(p) < hdrLen {
			continue
		}
		if !r.replayOK(binary.BigEndian.Uint32(p[1:])) {
			continue
		}

		lastRx = now
		linked = true

		if !havePeer || from != peer {
			peer = from
			havePeer = true
			log.Printf("kmlink: input from %s", from.Addr())
		}

		leave, err := r.dispatch(p)
		if err != nil {
			log.Printf("kmlink: injecting input failed: %v", err)
			r.giveUp()
			return 1
		}
		if leave {
			log.Print("kmlink: leave, released everything held")
		}
	}
}

// --------------------------------------------------------------- self test

// The one thing that cannot be checked from the Mac: that Go's AES-GCM reads
// exactly what CryptoKit wrote.  If they disagree on nonce or tag placement
// then every packet fails authentication at runtime, with no symptom but
// silence.  This vector came from CryptoKit; see test/aes-gcm-vector.txt.
var vectorKey = [32]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// nonce(12) || ciphertext(9) || tag(16)
var vectorCombined = [37]byte{
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
	0xe7, 0x18, 0x7c, 0x2d, 0x44, 0xcb, 0x07, 0x40, 0x9f,
	0x70, 0x2b, 0x01, 0x7b, 0xe0, 0x4f, 0x28, 0x21, 0x8f, 0x82, 0x63, 0x55, 0x56, 0x4c, 0xf8, 0x0a,
}

// MOVE, seq=1, dx=+5, dy=-3
var vectorPlain = [9]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0xff, 0xfd}

func checkVector() error {
	aead, err := newAEAD(vectorKey[:])
	if err != nil {
		return fmt.Errorf("AES-GCM setup failed: %v", err)
	}
	got, err := aead.Open(nil, vectorCombined[:nonceLen], vectorCombined[nonceLen:], nil)
	if err != nil {
		return errors.New("authentication FAILED -- CryptoKit and Go disagree")
	}
	if string(got) != string(vectorPlain[:]) {
		return fmt.Errorf("plaintext mismatch: got %x, want %x", got, vectorPlain)
	}
	return nil
}

func selftest() int {
	if err := checkVector(); err != nil {
		log.Printf("selftest: %v", err)
		return 1
	}
	log.Print("selftest: AES-256-GCM interop ok")
	return 0
}

// --------------------------------------------------------------- autostart

const unitName = "kmlink.service"

// StartLimitIntervalSec=0 is the line that matters.  Without it, five failed
// starts within ten seconds make systemd give up on the unit for good: it sits
// "failed" until someone notices, which is exactly the "stopped and never came
// back" this project keeps hitting.  With it, Restart=always means always.
const unitText = `[Unit]
Description=kmlink receiver (keyboard and mouse from the Mac)
# Keep restarting forever; never give up after a burst of failures.
StartLimitIntervalSec=0

[Service]
ExecStart=%s
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`

// systemd reads ExecStart with its own rules, not a shell's: inside double
// quotes it takes C escapes, and everywhere it expands %-specifiers and
// $VARIABLES.  A home folder may contain any of those characters.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(s) + `"`
}

// Every command's real output and exit status, every time.  Install steps
// that said nothing and reported success while nothing ran are the history of
// this project; the output is the only evidence anyone gets.
func systemctl(args ...string) (string, bool) {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	status := "exit status 0"
	if err != nil {
		status = err.Error()
	}
	log.Printf("kmlink: systemctl --user %s -> %s", strings.Join(args, " "), status)
	text := strings.TrimSpace(string(out))
	if text != "" {
		log.Printf("  %s", strings.ReplaceAll(text, "\n", "\n  "))
	}
	return text, err == nil
}

func unitPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "systemd", "user", unitName), nil
}

func install() int {
	if _, _, ok := loadKey(); !ok {
		log.Print("kmlink: not installing without a key; the service would only fail and restart.")
		return 1
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		log.Printf("kmlink: cannot determine my own path: %v", err)
		return 1
	}
	unit, err := unitPath()
	if err != nil {
		log.Printf("kmlink: cannot find the config folder: %v", err)
		return 1
	}

	// Written fresh every time, so reinstalling after moving the binary
	// points the unit at where it is now.
	text := fmt.Sprintf(unitText, systemdQuote(exe))
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		log.Printf("kmlink: cannot create %s: %v", filepath.Dir(unit), err)
		return 1
	}
	if err := os.WriteFile(unit, []byte(text), 0o644); err != nil {
		log.Printf("kmlink: cannot write %s: %v", unit, err)
		return 1
	}
	log.Printf("kmlink: wrote %s:\n%s", unit, text)

	// restart rather than start, so running this again after the binary
	// has been replaced moves the service onto the new copy.
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", unitName},
		{"restart", unitName},
	} {
		if _, ok := systemctl(args...); !ok {
			log.Print("kmlink: install stopped at that step.")
			return 1
		}
	}

	// Prove it.  A service that dies at startup is still "active" for the
	// moment after restart returns; a second later systemd has seen it exit
	// and is waiting to restart it.
	time.Sleep(time.Second)
	state, ok := systemctl("is-active", unitName)
	if !ok {
		log.Printf("kmlink: installed, but the service is %q, not running.  Why:\n"+
			"  journalctl --user -u kmlink -e", state)
		return 1
	}
	log.Print("kmlink: running, and starts at login.")
	return 0
}

func uninstall() int {
	ok := true
	if _, done := systemctl("disable", "--now", unitName); !done {
		ok = false
	}
	unit, err := unitPath()
	if err != nil {
		log.Printf("kmlink: cannot find the config folder: %v", err)
		return 1
	}
	switch err := os.Remove(unit); {
	case err == nil:
		log.Printf("kmlink: removed %s", unit)
	case errors.Is(err, fs.ErrNotExist):
		log.Printf("kmlink: %s was not there", unit)
	default:
		log.Printf("kmlink: cannot remove %s: %v", unit, err)
		ok = false
	}
	if _, done := systemctl("daemon-reload"); !done {
		ok = false
	}
	if !ok {
		return 1
	}
	log.Print("kmlink: uninstalled.")
	return 0
}

// -------------------------------------------------------------------- main

func main() {
	log.SetFlags(0) // journald adds its own timestamps

	switch {
	case len(os.Args) == 1:
		os.Exit(run())
	case len(os.Args) == 2 && os.Args[1] == "--selftest":
		os.Exit(selftest())
	case len(os.Args) == 2 && os.Args[1] == "--install":
		os.Exit(install())
	case len(os.Args) == 2 && os.Args[1] == "--uninstall":
		os.Exit(uninstall())
	}
	name := filepath.Base(os.Args[0])
	log.Printf("usage: %s              receive keyboard and mouse from the Mac\n"+
		"       %s --selftest   check AES-GCM agrees with the Mac's\n"+
		"       %s --install    run at login as a systemd user service\n"+
		"       %s --uninstall  remove that service", name, name, name, name)
	os.Exit(2)
}
