/* kmlink -- Windows receiver.  Wire format is PROTOCOL.md; the Mac side is
 * written against the same document and the two must agree byte for byte.
 *
 * A datagram goes from recvfrom() straight into SendInput() on one thread with
 * nothing in between.  Barrier's Windows client PostThreadMessage()s every
 * event to a separate "desk" thread and blocks on a condition variable waiting
 * for it -- a full cross-thread round trip per keystroke and per mouse move.
 * That is the lag being removed here, so do not add a thread, a message loop
 * or a queue to the input path.  The clipboard gets its own thread precisely
 * so that a slow clipboard write can never stall mouse motion.
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

#define PORT            24810
#define NONCE_LEN       12
#define TAG_LEN         16
#define HDR_LEN         5                             /* u8 type + u32 seq */
#define PKT_MIN         (NONCE_LEN + HDR_LEN + TAG_LEN)
#define PKT_MAX         512
#define CLIP_MAX        (1024 * 1024)
#define IDLE_MS         3000
#define RECV_TIMEOUT_MS 500
#define MOD_COUNT       4                        /* shift, ctrl, alt, gui */

#define T_MOVE 1
#define T_BUTTON 2
#define T_WHEEL 3
#define T_KEY 4
#define T_ENTER 5
#define T_LEAVE 6
#define T_PING 7

#define BOK(s) ((s) >= 0)                   /* NTSTATUS success, sans ntdef.h */

/* The only global: written during startup, before a second thread exists. */
static BCRYPT_ALG_HANDLE g_alg;

typedef struct {
    BCRYPT_KEY_HANDLE handle;
    unsigned char    *obj;           /* CNG key object, must outlive handle */
} aeskey;

typedef struct {
    uint32_t      seq_max;
    uint64_t      window;            /* bit i set => seq_max-1-i was seen */
    int           have_seq;
    unsigned char key_down[256];     /* vk -> 1 if we injected an unmatched down */
    unsigned      btn_down;          /* bit 0/1/2 = left/right/middle */
} rxstate;

typedef struct { aeskey key; SOCKET listener; } clipctx;

/* ------------------------------------------------------------------ helpers */

static uint16_t be16(const unsigned char *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static int16_t  bei16(const unsigned char *p) { return (int16_t)be16(p); }

static uint32_t be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int is_space(int c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* ---------------------------------------------------------------- key file */

static int key_path(char *path, size_t cap)
{
    char  base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, (DWORD)sizeof base);
    int   len;

    if (n == 0 || n >= sizeof base) return 0;
    len = snprintf(path, cap, "%s\\kmlink\\key.txt", base);
    return len > 0 && (size_t)len < cap;
}

static int read_hex_key(const char *path, unsigned char out[32])
{
    HANDLE f;
    char   buf[160];
    DWORD  got = 0;
    size_t a, b, i;

    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(f, buf, (DWORD)sizeof buf, &got, NULL)) { CloseHandle(f); return 0; }
    CloseHandle(f);

    a = 0; b = got;
    while (a < b && is_space((unsigned char)buf[a])) a++;
    while (b > a && is_space((unsigned char)buf[b - 1])) b--;
    if (b - a != 64) return 0;
    for (i = 0; i < 32; i++) {
        int hi = hexval((unsigned char)buf[a + 2 * i]);
        int lo = hexval((unsigned char)buf[a + 2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* ------------------------------------------------------------------ crypto */

static int crypto_init(void)
{
    NTSTATUS s = BCryptOpenAlgorithmProvider(&g_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BOK(s)) return 0;
    s = BCryptSetProperty(g_alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    return BOK(s);
}

/* One key handle per thread.  Sharing one would mean a lock, and a lock shared
 * with the clipboard thread is the cross-thread coupling this program exists
 * to avoid; a second handle costs a couple of kilobytes. */
static int key_make(aeskey *k, const unsigned char raw[32])
{
    DWORD    objlen = 0, got = 0;
    NTSTATUS s = BCryptGetProperty(g_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen,
                                   sizeof objlen, &got, 0);
    if (!BOK(s)) return 0;
    k->obj = (unsigned char *)malloc(objlen);
    if (!k->obj) return 0;
    s = BCryptGenerateSymmetricKey(g_alg, &k->handle, k->obj, objlen, (PUCHAR)raw, 32, 0);
    return BOK(s);
}

/* in = nonce(12) || ciphertext || tag(16).  Returns 0 on any failure, a bad
 * tag included; the caller drops the packet and says nothing about it. */
static int aes_open(aeskey *k, const unsigned char *in, ULONG inlen,
                    unsigned char *out, ULONG outcap, ULONG *outlen)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS s;

    if (inlen < NONCE_LEN + TAG_LEN + 1) return 0;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)in;
    info.cbNonce = NONCE_LEN;
    info.pbTag   = (PUCHAR)(in + inlen - TAG_LEN);
    info.cbTag   = TAG_LEN;
    s = BCryptDecrypt(k->handle, (PUCHAR)(in + NONCE_LEN), inlen - NONCE_LEN - TAG_LEN,
                      &info, NULL, 0, out, outcap, outlen, 0);
    return BOK(s);
}

/* ----------------------------------------------------------- replay window */

/* Highest sequence seen plus a 64-bit bitmap of the ones below it.  Key and
 * button packets are deliberately sent three times with the same sequence
 * number, so rejecting duplicates here is what stops every keystroke being
 * injected three times -- it is load-bearing, not a hardening extra. */
static int replay_ok(rxstate *st, uint32_t seq)
{
    uint32_t diff;

    if (!st->have_seq) {
        st->have_seq = 1;
        st->seq_max  = seq;
        st->window   = 0;
        return 1;
    }
    if (seq > st->seq_max) {
        diff = seq - st->seq_max;
        if (diff >= 64) st->window = (diff == 64) ? (1ull << 63) : 0;
        else            st->window = (st->window << diff) | (1ull << (diff - 1));
        st->seq_max = seq;
        return 1;
    }
    diff = st->seq_max - seq;
    if (diff == 0 || diff > 64) return 0;          /* the newest, or too old */
    if (st->window & (1ull << (diff - 1))) return 0;
    st->window |= (1ull << (diff - 1));
    return 1;
}

/* -------------------------------------------------------------- injection */

/* E0-prefixed keys.  LWIN/RWIN/APPS are here too: they genuinely are extended,
 * and reconcile_mods() presses VK_LWIN. */
static int key_is_extended(BYTE vk)
{
    switch (vk) {
    case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
    case VK_INSERT: case VK_DELETE: case VK_HOME: case VK_END:
    case VK_PRIOR: case VK_NEXT: case VK_RCONTROL: case VK_RMENU:
    case VK_NUMLOCK: case VK_SNAPSHOT: case VK_DIVIDE:
    case VK_LWIN: case VK_RWIN: case VK_APPS:
        return 1;
    default:
        return 0;
    }
}

static void send_key(rxstate *st, BYTE vk, int down)
{
    INPUT in;

    memset(&in, 0, sizeof in);
    in.type       = INPUT_KEYBOARD;
    in.ki.wVk     = vk;
    in.ki.wScan   = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    in.ki.dwFlags = (DWORD)((down ? 0 : KEYEVENTF_KEYUP) |
                            (key_is_extended(vk) ? KEYEVENTF_EXTENDEDKEY : 0));
    SendInput(1, &in, sizeof in);
    st->key_down[vk] = (unsigned char)(down ? 1 : 0);
}

static void send_mouse(DWORD flags, LONG dx, LONG dy, DWORD data)
{
    INPUT in;

    memset(&in, 0, sizeof in);
    in.type         = INPUT_MOUSE;
    in.mi.dx        = dx;
    in.mi.dy        = dy;
    in.mi.mouseData = data;
    in.mi.dwFlags   = flags;
    SendInput(1, &in, sizeof in);
}

static const DWORD btn_flags[3][2] = {              /* [button-1][down] */
    { MOUSEEVENTF_LEFTUP,   MOUSEEVENTF_LEFTDOWN   },
    { MOUSEEVENTF_RIGHTUP,  MOUSEEVENTF_RIGHTDOWN  },
    { MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MIDDLEDOWN }
};

static void send_button(rxstate *st, unsigned button, int down)   /* button 1..3 */
{
    unsigned i = button - 1;

    send_mouse(btn_flags[i][down ? 1 : 0], 0, 0, 0);
    if (down) st->btn_down |= 1u << i;
    else      st->btn_down &= ~(1u << i);
}

/* ------------------------------------------------------ modifier tracking */

/* What we press when a modifier has to go down, and every vk that counts as
 * that modifier being down -- the Mac may send the sided ones.  0 pads a row. */
static const BYTE mod_generic[MOD_COUNT] = { VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN };
static const BYTE mod_variants[MOD_COUNT][3] = {
    { VK_SHIFT,   VK_LSHIFT,   VK_RSHIFT   },
    { VK_CONTROL, VK_LCONTROL, VK_RCONTROL },
    { VK_MENU,    VK_LMENU,    VK_RMENU    },
    { VK_LWIN,    VK_RWIN,     0           }
};

static unsigned mods_held(const rxstate *st)
{
    unsigned m = 0, i, j;

    for (i = 0; i < MOD_COUNT; i++)
        for (j = 0; j < 3; j++)
            if (mod_variants[i][j] && st->key_down[mod_variants[i][j]])
                m |= 1u << i;
    return m;
}

/* Every KEY packet carries the whole modifier bitmask, so a lost key-up is
 * repaired here instead of leaving a modifier stuck down.  "Held" is derived
 * from the keys we injected, never from GetAsyncKeyState: the user's own
 * keyboard is on this machine too, and we must neither fight it nor release
 * keys we never pressed. */
static void reconcile_mods(rxstate *st, unsigned want)
{
    unsigned have = mods_held(st), i, j;

    for (i = 0; i < MOD_COUNT; i++) {
        unsigned bit = 1u << i;
        if ((want & bit) && !(have & bit)) {
            send_key(st, mod_generic[i], 1);
        } else if (!(want & bit) && (have & bit)) {
            for (j = 0; j < 3; j++) {                 /* let go of every side */
                BYTE v = mod_variants[i][j];
                if (v && st->key_down[v]) send_key(st, v, 0);
            }
        }
    }
}

static void release_all(rxstate *st)
{
    unsigned i;

    for (i = 0; i < 256; i++)
        if (st->key_down[i]) send_key(st, (BYTE)i, 0);
    for (i = 0; i < 3; i++)
        if (st->btn_down & (1u << i)) send_button(st, i + 1, 0);
}

/* ---------------------------------------------------------------- dispatch */

/* p/n is decrypted plaintext with n >= HDR_LEN.  Returns 1 if it was a LEAVE. */
static int dispatch(rxstate *st, const unsigned char *p, ULONG n)
{
    LONG     dx, dy;
    uint16_t vk;

    switch (p[0]) {
    case T_MOVE:
        if (n < HDR_LEN + 4) return 0;
        dx = bei16(p + 5); dy = bei16(p + 7);
        if (dx || dy) send_mouse(MOUSEEVENTF_MOVE, dx, dy, 0);
        return 0;

    case T_BUTTON:
        if (n < HDR_LEN + 2 || p[5] < 1 || p[5] > 3) return 0;
        send_button(st, p[5], p[6] != 0);
        return 0;

    case T_WHEEL:
        if (n < HDR_LEN + 4) return 0;
        dx = bei16(p + 5); dy = bei16(p + 7);
        if (dy) send_mouse(MOUSEEVENTF_WHEEL,  0, 0, (DWORD)dy);
        if (dx) send_mouse(MOUSEEVENTF_HWHEEL, 0, 0, (DWORD)dx);
        return 0;

    case T_KEY:
        if (n < HDR_LEN + 7) return 0;
        vk = be16(p + 5);
        if (vk == 0 || vk > 0xFF) return 0;              /* not a Windows vk */
        reconcile_mods(st, be32(p + 8));
        send_key(st, (BYTE)vk, p[7] != 0);
        return 0;

    case T_ENTER:
        /* Nothing should be held when the sender takes control.  If a LEAVE
         * went missing this is the only thing that clears it, because a steady
         * stream of pings keeps the idle timer from ever firing. */
        release_all(st);
        return 0;

    case T_LEAVE:
        release_all(st);
        return 1;

    default:                                            /* PING, and unknown */
        return 0;
    }
}

/* --------------------------------------------------------------- clipboard */

/* OpenClipboard(NULL) would let EmptyClipboard null the clipboard owner, which
 * documentedly makes SetClipboardData fail.  A message-only window gives us a
 * real owner, and it never receives broadcasts, so it needs no message pump. */
static HWND clip_window(void)
{
    WNDCLASSEXA wc;

    memset(&wc, 0, sizeof wc);
    wc.cbSize        = sizeof wc;
    wc.lpfnWndProc   = DefWindowProcA;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = "kmlink_clip";
    RegisterClassExA(&wc);
    return CreateWindowExA(0, "kmlink_clip", "", 0, 0, 0, 0, 0, HWND_MESSAGE,
                           NULL, wc.hInstance, NULL);
}

static void clipboard_set_utf8(HWND owner, const char *text, int len)
{
    int      wlen;
    HGLOBAL  h;
    wchar_t *w;

    if (len <= 0) return;
    wlen = MultiByteToWideChar(CP_UTF8, 0, text, len, NULL, 0);
    if (wlen <= 0) return;
    h = GlobalAlloc(GMEM_MOVEABLE, ((SIZE_T)wlen + 1) * sizeof(wchar_t));
    if (!h) return;
    w = (wchar_t *)GlobalLock(h);
    if (!w) { GlobalFree(h); return; }
    MultiByteToWideChar(CP_UTF8, 0, text, len, w, wlen);
    w[wlen] = L'\0';                        /* the count form does not add one */
    GlobalUnlock(h);

    /* Another app may hold the clipboard; drop this frame rather than spin. */
    if (!OpenClipboard(owner)) { GlobalFree(h); return; }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, h)) GlobalFree(h);   /* still ours */
    CloseClipboard();
}

static int recv_all(SOCKET s, unsigned char *buf, int n)
{
    int off = 0, got;

    while (off < n) {
        got = recv(s, (char *)buf + off, n - off, 0);
        if (got <= 0) return 0;
        off += got;
    }
    return 1;
}

static DWORD WINAPI clipboard_thread(LPVOID arg)
{
    clipctx       *ctx   = (clipctx *)arg;
    HWND           owner = clip_window();
    unsigned char *frame = (unsigned char *)malloc(CLIP_MAX);
    unsigned char *plain = (unsigned char *)malloc(CLIP_MAX);
    BOOL           on    = TRUE;

    if (!frame || !plain) return 1;

    for (;;) {
        SOCKET c = accept(ctx->listener, NULL, NULL);
        if (c == INVALID_SOCKET) { Sleep(100); continue; }
        /* Long idle gaps are normal here, so no recv timeout; keepalive is
         * what eventually reaps a peer that vanished without a FIN. */
        setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof on);

        for (;;) {
            unsigned char lenbuf[4];
            uint32_t      len;
            ULONG         plen = 0;

            if (!recv_all(c, lenbuf, 4)) break;
            len = be32(lenbuf);
            if (len < NONCE_LEN + TAG_LEN + 1 || len > CLIP_MAX) break;
            if (!recv_all(c, frame, (int)len)) break;
            /* A bad tag on a stream means the peer is not who we think, or the
             * stream has desynced; drop the connection rather than resync. */
            if (!aes_open(&ctx->key, frame, len, plain, CLIP_MAX, &plen)) break;
            if (plen >= 1 && plain[0] == 1)
                clipboard_set_utf8(owner, (const char *)plain + 1, (int)(plen - 1));
        }
        closesocket(c);
    }
}

/* -------------------------------------------------------------------- main */

static SOCKET bind_listener(int stream)
{
    struct sockaddr_in a;
    DWORD  ms = RECV_TIMEOUT_MS;
    SOCKET s  = socket(AF_INET, stream ? SOCK_STREAM : SOCK_DGRAM,
                       stream ? IPPROTO_TCP : IPPROTO_UDP);

    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    memset(&a, 0, sizeof a);
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port        = htons(PORT);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { closesocket(s); return INVALID_SOCKET; }
    if (stream) {
        if (listen(s, 1) != 0) { closesocket(s); return INVALID_SOCKET; }
    } else {
        /* The receive timeout is how the input loop notices a dead link
         * without a second thread holding a timer. */
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    }
    return s;
}

int main(void)
{
    unsigned char raw[32], dgram[PKT_MAX], plain[PKT_MAX];
    char          path[MAX_PATH];
    aeskey        ukey;
    clipctx       clip;
    WSADATA       wsa;
    SOCKET        usock;
    rxstate       st;
    ULONGLONG     last_rx = 0;
    int           linked = 0, have_peer = 0;
    uint32_t      peer_ip = 0;
    uint16_t      peer_port = 0;

    setvbuf(stdout, NULL, _IONBF, 0);     /* nothing is logged per event */

    if (!key_path(path, sizeof path)) {
        printf("kmlink: cannot resolve %%LOCALAPPDATA%%\n");
        return 1;
    }
    if (!read_hex_key(path, raw)) {
        printf("kmlink: no usable key at %s\n"
               "        Run `kmlink --genkey` on the Mac, then save the 64-character\n"
               "        hex key it prints into that file (create the folder first).\n", path);
        return 1;
    }

    memset(&st, 0, sizeof st);
    memset(&clip, 0, sizeof clip);
    if (!crypto_init() || !key_make(&ukey, raw) || !key_make(&clip.key, raw)) {
        printf("kmlink: BCrypt AES-GCM setup failed\n");
        return 1;
    }
    SecureZeroMemory(raw, sizeof raw);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("kmlink: WSAStartup failed\n");
        return 1;
    }
    usock         = bind_listener(0);
    clip.listener = bind_listener(1);
    if (usock == INVALID_SOCKET || clip.listener == INVALID_SOCKET) {
        printf("kmlink: cannot bind port %d (already in use?)\n", PORT);
        return 1;
    }
    if (!CreateThread(NULL, 0, clipboard_thread, &clip, 0, NULL)) {
        printf("kmlink: cannot start the clipboard thread\n");
        return 1;
    }
    printf("kmlink: listening on udp/tcp %d, key loaded from %s\n", PORT, path);

    for (;;) {
        struct sockaddr_in from;
        int                fromlen = sizeof from;
        int                n;
        ULONG              plen = 0;
        ULONGLONG          now;

        n = recvfrom(usock, (char *)dgram, (int)sizeof dgram, 0,
                     (struct sockaddr *)&from, &fromlen);

        /* Checked every pass and not only on a timeout: a flood of packets we
         * go on to reject must not disguise a dead link. */
        now = GetTickCount64();
        if (linked && now - last_rx >= IDLE_MS) {
            release_all(&st);
            st.have_seq = 0;    /* a gap means a new session; let its seq restart */
            linked = 0;
            printf("kmlink: link idle, released everything held\n");
        }

        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEMSGSIZE || e == WSAECONNRESET || e == WSAEINTR)
                continue;
            printf("kmlink: recvfrom failed (%d)\n", e);
            return 1;
        }
        if (n < PKT_MIN) continue;
        if (!aes_open(&ukey, dgram, (ULONG)n, plain, (ULONG)sizeof plain, &plen)) continue;
        if (plen < HDR_LEN) continue;
        if (!replay_ok(&st, be32(plain + 1))) continue;

        last_rx = now;
        linked  = 1;

        if (!have_peer || from.sin_addr.s_addr != peer_ip || from.sin_port != peer_port) {
            char ip[INET_ADDRSTRLEN];
            peer_ip   = from.sin_addr.s_addr;
            peer_port = from.sin_port;
            have_peer = 1;
            if (InetNtopA(AF_INET, &from.sin_addr, ip, sizeof ip))
                printf("kmlink: input from %s\n", ip);
        }

        if (dispatch(&st, plain, plen))
            printf("kmlink: leave, released everything held\n");
    }
}
