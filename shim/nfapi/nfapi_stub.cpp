// ABI-compatible Linux backend shim for the customized nfapi.dll imported by ExitLag.
// The built-in production policy exposes only the exports proven by the TCP and UDP
// data planes. EXITLAG_NFAPI_TRACE=1 enables the full research trace; without it the
// log contains only lifecycle/compatibility events and explicit unsupported calls.
// EXITLAG_NFAPI_SUCCEED, EXITLAG_NFAPI_EXTVER, and EXITLAG_NFAPI_INJECT are isolated
// research overrides and are not needed by the normal runtime.

#include "ipc_validation.h"
#include "socket_attribution.h"
#include "tcp_callback_policy.h"
#include "pid_domain.h"
#include "udp_validation.h"

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

#define WINAPI __stdcall
#define INVALID_HANDLE_VALUE ((HANDLE)(__int64)-1)
#define FILE_APPEND_DATA 0x00000004UL
#define FILE_SHARE_READ 0x00000001UL
#define FILE_SHARE_WRITE 0x00000002UL
#define OPEN_ALWAYS 4UL
#define FILE_ATTRIBUTE_NORMAL 0x00000080UL

extern "C" {
__declspec(dllimport) HANDLE WINAPI CreateFileW(const wchar_t *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) BOOL WINAPI FlushFileBuffers(HANDLE);
__declspec(dllimport) BOOL WINAPI CloseHandle(HANDLE);
__declspec(dllimport) DWORD WINAPI GetCurrentProcessId();
__declspec(dllimport) DWORD WINAPI GetCurrentThreadId();
__declspec(dllimport) DWORD WINAPI TlsAlloc();
__declspec(dllimport) void *WINAPI TlsGetValue(DWORD);
__declspec(dllimport) BOOL WINAPI TlsSetValue(DWORD, void *);
__declspec(dllimport) HANDLE WINAPI GetProcessHeap();
__declspec(dllimport) void *WINAPI HeapAlloc(HANDLE, DWORD, unsigned __int64);
__declspec(dllimport) BOOL WINAPI HeapFree(HANDLE, DWORD, void *);
__declspec(dllimport) DWORD WINAPI GetEnvironmentVariableW(const wchar_t *, wchar_t *, DWORD);
__declspec(dllimport) void WINAPI GetSystemTimeAsFileTime(void *);
__declspec(dllimport) unsigned __int64 WINAPI GetTickCount64();
__declspec(dllimport) void WINAPI OutputDebugStringA(const char *);
__declspec(dllimport) unsigned __int64 WINAPI VirtualQuery(const void *, void *, unsigned __int64);
__declspec(dllimport) HANDLE WINAPI GetModuleHandleW(const wchar_t *);
__declspec(dllimport) BOOL WINAPI VirtualProtect(void *, unsigned __int64, DWORD, DWORD *);
__declspec(dllimport) HANDLE WINAPI OpenProcess(DWORD, BOOL, DWORD);
__declspec(dllimport) BOOL WINAPI QueryFullProcessImageNameW(HANDLE, DWORD, wchar_t *, DWORD *);
/* ws2_32: loopback TCP transport to the native Linux helper. */
typedef unsigned __int64 SOCKET;
#define INVALID_SOCKET ((SOCKET)~0)
#define SOCKET_ERROR (-1)
#define SOL_SOCKET_ 0xffff
#define SO_SNDTIMEO_ 0x1005
#define SO_RCVTIMEO_ 0x1006
__declspec(dllimport) int WINAPI WSAStartup(unsigned short, void *);
__declspec(dllimport) SOCKET WINAPI socket(int, int, int);
__declspec(dllimport) int WINAPI connect(SOCKET, const void *, int);
__declspec(dllimport) int WINAPI send(SOCKET, const char *, int, int);
__declspec(dllimport) int WINAPI recv(SOCKET, char *, int, int);
__declspec(dllimport) int WINAPI closesocket(SOCKET);
__declspec(dllimport) int WINAPI setsockopt(SOCKET, int, int, const char *, int);
/* iphlpapi: map a flow to its owning *Windows* process, the way the real
   NetFilter driver does. Wine implements this over /proc and returns genuine
   Wine PIDs, so no Linux-PID translation is needed for Wine applications. */
__declspec(dllimport) unsigned long WINAPI GetExtendedTcpTable(void *, unsigned long *, int, unsigned long, int, unsigned long);
__declspec(dllimport) unsigned long WINAPI GetExtendedUdpTable(void *, unsigned long *, int, unsigned long, int, unsigned long);
__declspec(dllimport) BOOL WINAPI ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport) BOOL WINAPI DeleteFileW(const wchar_t *);
__declspec(dllimport) BOOL WINAPI GetFileSizeEx(HANDLE, unsigned __int64 *);
__declspec(dllimport) BOOL WINAPI MoveFileExW(const wchar_t *, const wchar_t *, DWORD);
__declspec(dllimport) HANDLE WINAPI CreateThread(void *, unsigned __int64, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
__declspec(dllimport) void WINAPI Sleep(DWORD);
}
#define GENERIC_READ 0x80000000UL
#define OPEN_EXISTING 3UL

// MEMORY_BASIC_INFORMATION (x64) and the protection bits needed to bound a dump.
struct MEMORY_BASIC_INFORMATION64 {
    void *BaseAddress; void *AllocationBase; DWORD AllocationProtect; DWORD pad0;
    unsigned __int64 RegionSize; DWORD State; DWORD Protect; DWORD Type; DWORD pad1;
};
#define MEM_COMMIT 0x1000UL
#define PAGE_NOACCESS 0x01UL
#define PAGE_GUARD 0x100UL

typedef enum _NF_STATUS {
    NF_STATUS_SUCCESS = 0,
    NF_STATUS_FAIL = -1,
    NF_STATUS_INVALID_ENDPOINT_ID = -2,
    NF_STATUS_NOT_INITIALIZED = -3,
    NF_STATUS_IO_ERROR = -4,
    NF_STATUS_REBOOT_REQUIRED = -5,
} NF_STATUS;

namespace nfapi {

using ENDPOINT_ID = unsigned __int64;

class NF_EventHandler;
class NF_IPEventHandler;

#pragma pack(push, 1)
typedef struct _NF_PORT_RANGE {
    unsigned short valueLow;
    unsigned short valueHigh;
} NF_PORT_RANGE;

typedef struct _NF_RULE_EX {
    int protocol;
    unsigned long processId;
    unsigned char direction;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned short ip_family;
    unsigned char localIpAddress[16];
    unsigned char localIpAddressMask[16];
    unsigned char remoteIpAddress[16];
    unsigned char remoteIpAddressMask[16];
    unsigned long filteringFlag;
    wchar_t processName[260];
    NF_PORT_RANGE localPortRange;
    NF_PORT_RANGE remotePortRange;
    unsigned char redirectTo[28];
    unsigned long localProxyProcessId;
} NF_RULE_EX;

typedef struct _NF_FLOWCTL_DATA {
    unsigned __int64 inLimit;
    unsigned __int64 outLimit;
} NF_FLOWCTL_DATA;

typedef struct _NF_FLOWCTL_STAT {
    unsigned __int64 inBytes;
    unsigned __int64 outBytes;
} NF_FLOWCTL_STAT;

typedef struct _NF_UDP_OPTIONS {
    unsigned long flags;
    long optionsLength;
    unsigned char options[1];
} NF_UDP_OPTIONS;
#pragma pack(pop)

// ExitLag extensions absent from the public SDK headers. Preserve their ABI names,
// but do not guess or dereference their layouts.
typedef struct _NF_FCQUEUE_PARAMS { unsigned char opaque; } NF_FCQUEUE_PARAMS;
typedef struct _NF_UDP_REMOTE_ADDR_RULE { unsigned char opaque; } NF_UDP_REMOTE_ADDR_RULE;

namespace trace {

struct line {
    char bytes[8192];
    unsigned int length;
    bool enabled;

    line() : length(0), enabled(true) {}

    void character(char value)
    {
        if (length + 1 < sizeof(bytes)) bytes[length++] = value;
    }

    void text(const char *value)
    {
        if (!value) value = "<null>";
        while (*value && length + 1 < sizeof(bytes)) bytes[length++] = *value++;
    }

    void decimal(unsigned __int64 value)
    {
        char reversed[32];
        unsigned int count = 0;
        do {
            reversed[count++] = (char)('0' + value % 10);
            value /= 10;
        } while (value && count < sizeof(reversed));
        while (count) character(reversed[--count]);
    }

    void signed_decimal(__int64 value)
    {
        if (value < 0) {
            character('-');
            decimal((unsigned __int64)(-(value + 1)) + 1);
        } else decimal((unsigned __int64)value);
    }

    void hex(unsigned __int64 value)
    {
        static const char digits[] = "0123456789abcdef";
        char reversed[16];
        unsigned int count = 0;
        text("0x");
        do {
            reversed[count++] = digits[value & 15];
            value >>= 4;
        } while (value && count < sizeof(reversed));
        while (count) character(reversed[--count]);
    }

    void pointer(const void *value) { hex((unsigned __int64)value); }

    void quoted_ascii(const char *value, unsigned int limit)
    {
        character('"');
        if (!value) text("<null>");
        else {
            unsigned int i;
            for (i = 0; i < limit && value[i]; ++i) {
                unsigned char c = (unsigned char)value[i];
                if (c == '\\' || c == '"') character('\\');
                character(c >= 32 && c < 127 ? (char)c : '.');
            }
            if (i == limit) text("...");
        }
        character('"');
    }

    void wide_ascii(const wchar_t __unaligned *value, unsigned int limit)
    {
        character('"');
        if (!value) text("<null>");
        else {
            unsigned int i;
            for (i = 0; i < limit && value[i]; ++i) {
                wchar_t c = value[i];
                if (c == L'\\' || c == L'"') character('\\');
                character(c >= 32 && c < 127 ? (char)c : '?');
            }
            if (i == limit) text("...");
        }
        character('"');
    }

    void byte_array(const unsigned char __unaligned *value, unsigned int count)
    {
        static const char digits[] = "0123456789abcdef";
        if (!value) { text("<null>"); return; }
        for (unsigned int i = 0; i < count; ++i) {
            character(digits[value[i] >> 4]);
            character(digits[value[i] & 15]);
        }
    }
};

static volatile long sequence;

static bool research_trace_enabled()
{
    static volatile long initialized;
    static bool enabled;
    if (!__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) {
        wchar_t value[16];
        DWORD length = GetEnvironmentVariableW(L"EXITLAG_NFAPI_TRACE", value,
                                                sizeof(value) / sizeof(value[0]));
        enabled = length && length < sizeof(value) / sizeof(value[0]) &&
                  !(length == 1 && value[0] == L'0');
        __atomic_store_n(&initialized, 1, __ATOMIC_RELEASE);
    }
    return enabled;
}

static bool same_name(const char *left, const char *right)
{
    while (*left && *left == *right) { ++left; ++right; }
    return !*left && !*right;
}

static bool operational_event(const char *name)
{
    static const char *const names[] = {
        "compat.install", "policy.mode", "nf_init", "nf_free",
        "ipc.config", "ipc.connect", "ipc.hello_ack", "ipc.disconnect"
    };
    for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (same_name(name, names[i])) return true;
    return false;
}

// Number of bytes readable at [p, p+wanted) according to the committed, non-guard,
// non-noaccess regions that contain it. Used to dump opaque structures without
// touching unmapped memory.
static unsigned __int64 readable_bytes(const void *p, unsigned __int64 wanted)
{
    unsigned __int64 have = 0;
    const unsigned char *cur = (const unsigned char *)p;
    while (have < wanted) {
        MEMORY_BASIC_INFORMATION64 info;
        if (!VirtualQuery(cur, &info, sizeof(info))) break;
        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) || !info.Protect) break;
        unsigned __int64 region_end = (unsigned __int64)info.BaseAddress + info.RegionSize;
        unsigned __int64 chunk = region_end - (unsigned __int64)cur;
        have += chunk; cur += chunk;
    }
    return have < wanted ? have : wanted;
}

static void safe_hex(line &out, const void *p, unsigned __int64 wanted)
{
    if (!p) { out.text("<null>"); return; }
    unsigned __int64 n = readable_bytes(p, wanted);
    out.text("readable="); out.decimal(n); out.text(" hex=");
    out.byte_array((const unsigned char __unaligned *)p, (unsigned int)n);
}

// sockaddr_in / sockaddr_in6 (NF_MAX_ADDRESS_LENGTH = 28 bytes) as text.
static void sockaddr_text(line &out, const unsigned char __unaligned *sa)
{
    if (!sa) { out.text("<null>"); return; }
    unsigned short family = (unsigned short)(sa[0] | (sa[1] << 8));
    unsigned short port = (unsigned short)((sa[2] << 8) | sa[3]);
    if (family == 2) {
        out.text("AF_INET "); out.decimal(sa[4]); out.character('.'); out.decimal(sa[5]); out.character('.');
        out.decimal(sa[6]); out.character('.'); out.decimal(sa[7]); out.character(':'); out.decimal(port);
    } else if (family == 23) {
        out.text("AF_INET6 [");
        for (int i = 0; i < 16; i += 2) { if (i) out.character(':'); out.hex((unsigned)((sa[8 + i] << 8) | sa[9 + i])); }
        out.text("]:"); out.decimal(port);
        out.text(" scope="); out.decimal((unsigned)(sa[24] | (sa[25] << 8) | (sa[26] << 16) | (sa[27] << 24)));
    } else { out.text("family="); out.decimal(family); }
}

static void ip_text(line &out, unsigned short family, const unsigned char __unaligned *ip)
{
    if (family == 23) {
        out.character('[');
        for (int i = 0; i < 16; i += 2) { if (i) out.character(':'); out.hex((unsigned)((ip[i] << 8) | ip[i + 1])); }
        out.character(']');
    } else {
        out.decimal(ip[0]); out.character('.'); out.decimal(ip[1]); out.character('.'); out.decimal(ip[2]); out.character('.'); out.decimal(ip[3]);
    }
}

// The exports the Linux backend genuinely implements. In the production path
// these succeed without any environment configuration; anything absent from
// this table still fails explicitly, so an unimplemented capability degrades
// rather than silently pretending to work.
//
// This list is the contract, not a convenience default: it is exactly the set
// proven end to end by the TCP redirect and UDP take-and-reinject runs.
static const char *const k_supported_exports[] = {
    "nf_init",
    "nf_getExtensionsVersion",
    "nf_getProcessNameFromKernel",
    "nf_addFlowCtl",
    "nf_setFlowCtlQueueParams",
    "nf_setRulesEx",
    "nf_setUDPFlowCtl",
    "nf_udpPostSend",
    "nf_udpPostReceive",
    "nf_udpDisableFiltering",
    "nf_udpEnableFiltering",
    "nf_udpAddRemoteAddrRule",
};

static unsigned supported_export_count()
{
    return (unsigned)(sizeof(k_supported_exports) / sizeof(k_supported_exports[0]));
}

static bool name_in_supported_table(const char *name)
{
    for (unsigned i = 0; i < sizeof(k_supported_exports) / sizeof(k_supported_exports[0]); ++i) {
        const char *a = name, *b = k_supported_exports[i];
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (!*a && !*b) return true;
    }
    return false;
}

// Research override: EXITLAG_NFAPI_SUCCEED replaces the built-in table with an
// explicit list, so a run can narrow or widen the surface to isolate behaviour.
// It is deliberately not consulted unless it is set -- the production path must
// not depend on it. Returns 1 match, 0 no match, -1 when the variable is unset.
static int policy_override_succeeds(const char *name)
{
    static const wchar_t env_name[] = L"EXITLAG_NFAPI_SUCCEED";
    wchar_t list[1024];
    DWORD size = GetEnvironmentVariableW(env_name, list, sizeof(list) / sizeof(list[0]));
    if (!size || size >= sizeof(list) / sizeof(list[0])) return -1;
    const wchar_t *p = list;
    while (*p) {
        const char *n = name; const wchar_t *q = p;
        while (*q && *q != L',' && *n && (wchar_t)*n == *q) { ++q; ++n; }
        if (!*n && (*q == 0 || *q == L',')) return 1;
        while (*p && *p != L',') ++p;
        if (*p == L',') ++p;
    }
    return 0;
}

// Success policy, evaluated per call so runs stay self-describing.
static bool policy_succeeds(const char *name)
{
    int override_result = policy_override_succeeds(name);
    if (override_result >= 0) return override_result != 0;
    return name_in_supported_table(name);
}

// True when the run is using the built-in production table rather than an
// override. Logged once at init so every capture says which policy was active.
static bool policy_is_production()
{
    static const wchar_t env_name[] = L"EXITLAG_NFAPI_SUCCEED";
    wchar_t list[1024];
    return GetEnvironmentVariableW(env_name, list, sizeof(list) / sizeof(list[0])) == 0;
}

// The NetFilter SDK extensions version the backend implements. ExitLag gates
// UDP filtering on this being recent enough, so the production path reports it
// without configuration; EXITLAG_NFAPI_EXTVER remains a research override for
// probing how the client reacts to other values.
#define EXITLAG_SUPPORTED_EXTENSIONS_VERSION 8UL

static unsigned long policy_extensions_version()
{
    static const wchar_t env_name[] = L"EXITLAG_NFAPI_EXTVER";
    wchar_t text[32];
    DWORD size = GetEnvironmentVariableW(env_name, text, sizeof(text) / sizeof(text[0]));
    unsigned long value = 0;
    if (!size || size >= sizeof(text) / sizeof(text[0])) return EXITLAG_SUPPORTED_EXTENSIONS_VERSION;
    for (const wchar_t *p = text; *p >= L'0' && *p <= L'9'; ++p) value = value * 10 + (unsigned long)(*p - L'0');
    return value;
}

static long next_sequence()
{
    return __atomic_add_fetch(&sequence, 1, __ATOMIC_SEQ_CST);
}

static void prefix(line &out, const char *name)
{
    out.enabled = research_trace_enabled() || operational_event(name);
    // utc_ft is a FILETIME (100 ns units since 1601-01-01 UTC); tick_ms is the
    // monotonic system tick, so intervals between calls survive clock changes.
    unsigned __int64 filetime = 0;
    GetSystemTimeAsFileTime(&filetime);
    out.text("seq="); out.decimal((unsigned long)next_sequence());
    out.text(" utc_ft="); out.decimal(filetime);
    out.text(" tick_ms="); out.decimal(GetTickCount64());
    out.text(" pid="); out.decimal(GetCurrentProcessId());
    out.text(" tid="); out.decimal(GetCurrentThreadId());
    out.text(" call="); out.text(name);
}

static void finish(line &out)
{
    if (!out.enabled) return;
    static const wchar_t env_name[] = L"EXITLAG_NFAPI_LOG";
    static const wchar_t default_name[] = L"nfapi-shim-calls.log";
    wchar_t path[1024];
    DWORD size = GetEnvironmentVariableW(env_name, path, sizeof(path) / sizeof(path[0]));
    const wchar_t *selected = default_name;
    if (size && size < sizeof(path) / sizeof(path[0])) selected = path;

    out.character('\n');
    out.bytes[out.length] = 0;
    HANDLE file = CreateFileW(selected, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(file, out.bytes, out.length, &written, 0);
        FlushFileBuffers(file);
        /* Bound the log. With the research trace on, a single session produced
           11 MB during development. One previous generation is kept so a crash
           stays investigable. Checked periodically, not per line. */
        static volatile long since_size_check;
        if (__atomic_add_fetch(&since_size_check, 1, __ATOMIC_RELAXED) >= 512) {
            __atomic_store_n(&since_size_check, 0, __ATOMIC_RELAXED);
            unsigned __int64 size = 0;
            if (GetFileSizeEx(file, &size) && size >= 8ULL * 1024 * 1024) {
                wchar_t rotated[1040];
                unsigned int i = 0;
                for (; selected[i] && i < 1024; ++i) rotated[i] = selected[i];
                rotated[i++] = L'.'; rotated[i++] = L'1'; rotated[i] = 0;
                CloseHandle(file);
                file = INVALID_HANDLE_VALUE;
                MoveFileExW(selected, rotated, 0x1 /* MOVEFILE_REPLACE_EXISTING */);
            }
        }
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    OutputDebugStringA(out.bytes);
}

static void callbacks(line &out, const void *handler, unsigned int count)
{
    out.text(" handler="); out.pointer(handler);
    if (!handler) return;
    void *const *vtable = *(void *const *const *)handler;
    out.text(" vtable="); out.pointer(vtable);
    out.text(" callbacks=[");
    for (unsigned int i = 0; i < count; ++i) {
        if (i) out.character(',');
        out.pointer(vtable[i]);
    }
    out.character(']');
}

static void result(line &out, __int64 value)
{
    out.text(" return="); out.signed_decimal(value);
}

// Chooses the return for a status export: documented success (0) when the policy
// names it, otherwise the explicit failure the observation shim always used.
static NF_STATUS status_for(line &out, const char *name)
{
    bool ok = policy_succeeds(name);
    if (!ok) out.enabled = true; /* unsupported capability is an operational warning */
    out.text(ok ? " policy=succeed" : " policy=fail");
    return ok ? NF_STATUS_SUCCESS : NF_STATUS_FAIL;
}

} // namespace trace


// ---------------------------------------------------------------------------
// Wine compatibility guards.
//
// ExitLag imports functions that Wine does not export. Wine's loader resolves a
// missing import to a synthesised stub that raises EXCEPTION_WINE_STUB
// (0x80000100) when called, which is non-continuable: the whole client exits.
// Opening the affected pages therefore kills ExitLag rather than degrading.
//
// Confirmed from the Crashpad minidump of a PC Boost crash: exception code
// 0x80000100 with arguments ("IPHLPAPI.DLL", "GetInterfaceDnsSettings") -- the
// two strings Wine's loader takes from ExitLag's own import table.
//
// The complete set was derived by diffing every ExitLag import against the
// exports of the Wine DLLs actually loaded (/usr/lib/wine/x86_64-windows):
// eight IPHLPAPI entries (DNS settings, interface rows, UDP owner modules) and
// three POWRPROF entries (power-scheme editing, i.e. PC Boost). No bundled
// ExitLag DLL is affected, so only the main image's IAT is touched.
//
// Each guarded slot is replaced with a function that returns
// ERROR_NOT_SUPPORTED, the ordinary Win32 contract for an unavailable
// capability. Output buffers are deliberately left untouched: their contents
// are undefined on failure, and writing a guessed number of bytes into a caller
// structure would risk corrupting memory to paper over a feature that cannot
// work anyway. The aim is that these features fail cleanly, not that they work.
// ---------------------------------------------------------------------------

namespace compat {

#define PAGE_READWRITE 0x04UL
#define ERROR_NOT_SUPPORTED 50UL
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define GUARD_COUNT 11

struct guard_entry {
    const char *dll;
    const char *function;
    void **slot;
    void *original;
    volatile long calls;
};

static guard_entry g_guards[GUARD_COUNT] = {
    { "IPHLPAPI.DLL", "GetInterfaceDnsSettings", 0, 0, 0 },
    { "IPHLPAPI.DLL", "SetInterfaceDnsSettings", 0, 0, 0 },
    { "IPHLPAPI.DLL", "FreeInterfaceDnsSettings", 0, 0, 0 },
    { "IPHLPAPI.DLL", "GetOwnerModuleFromUdpEntry", 0, 0, 0 },
    { "IPHLPAPI.DLL", "GetOwnerModuleFromUdp6Entry", 0, 0, 0 },
    { "IPHLPAPI.DLL", "InitializeIpInterfaceEntry", 0, 0, 0 },
    { "IPHLPAPI.DLL", "ResolveIpNetEntry2", 0, 0, 0 },
    { "IPHLPAPI.DLL", "SetIpInterfaceEntry", 0, 0, 0 },
    { "POWRPROF.dll", "PowerDuplicateScheme", 0, 0, 0 },
    { "POWRPROF.dll", "PowerWriteDCValueIndex", 0, 0, 0 },
    { "POWRPROF.dll", "PowerWriteFriendlyName", 0, 0, 0 },
};

static bool ascii_equal_ci(const char *left, const char *right)
{
    if (!left || !right) return false;
    while (*left && *right) {
        char a = *left++, b = *right++;
        if (a >= 'a' && a <= 'z') a = (char)(a - ('a' - 'A'));
        if (b >= 'a' && b <= 'z') b = (char)(b - ('a' - 'A'));
        if (a != b) return false;
    }
    return *left == 0 && *right == 0;
}

// The x64 calling convention is caller-cleanup with arguments in registers and
// caller-allocated shadow space, so a zero-argument replacement is safe for any
// arity. Functions declared void in Windows simply ignore the returned value.
template <unsigned Index>
static unsigned long WINAPI guard_thunk()
{
    guard_entry &entry = g_guards[Index];
    long count = __atomic_add_fetch(&entry.calls, 1, __ATOMIC_SEQ_CST);
    if (count <= 3) {                       // enough to prove it, never a flood
        trace::line line;
        trace::prefix(line, "compat.call");
        line.text(" guard="); line.text(entry.dll);
        line.character('!'); line.text(entry.function);
        line.text(" call="); line.decimal((unsigned __int64)count);
        line.text(" policy=unsupported return="); line.decimal(ERROR_NOT_SUPPORTED);
        trace::finish(line);
    }
    return ERROR_NOT_SUPPORTED;
}

static void *const k_guard_thunks[GUARD_COUNT] = { (void *)&guard_thunk<0>, (void *)&guard_thunk<1>, (void *)&guard_thunk<2>, (void *)&guard_thunk<3>, (void *)&guard_thunk<4>, (void *)&guard_thunk<5>, (void *)&guard_thunk<6>, (void *)&guard_thunk<7>, (void *)&guard_thunk<8>, (void *)&guard_thunk<9>, (void *)&guard_thunk<10> };

static bool valid_rva(unsigned int rva, unsigned __int64 bytes, unsigned int image_size)
{
    return rva && rva < image_size && bytes <= (unsigned __int64)image_size - rva;
}

enum install_state {
    INSTALL_NOT_ATTEMPTED = 0,
    INSTALL_DONE = 1,
    INSTALL_BAD_DOS = -1,
    INSTALL_BAD_PE = -2,
    INSTALL_BAD_MAGIC = -3,
    INSTALL_NO_IMPORTS = -4,
};

static volatile long g_install_state;
static unsigned short g_install_magic;
static unsigned int g_installed_count;

static void install_main_iat_guards()
{
    if (g_install_state != INSTALL_NOT_ATTEMPTED) return;

    unsigned char *base = (unsigned char *)GetModuleHandleW(0);
    if (!base || trace::readable_bytes(base, 64) < 64 ||
        base[0] != 'M' || base[1] != 'Z') {
        g_install_state = INSTALL_BAD_DOS; return;
    }

    unsigned int pe_offset = *(const unsigned int __unaligned *)(base + 0x3c);
    if (trace::readable_bytes(base + pe_offset, 24 + 128) < 24 + 128 ||
        base[pe_offset] != 'P' || base[pe_offset + 1] != 'E' ||
        base[pe_offset + 2] != 0 || base[pe_offset + 3] != 0) {
        g_install_state = INSTALL_BAD_PE; return;
    }

    const unsigned char *optional = base + pe_offset + 24;
    unsigned short magic = *(const unsigned short __unaligned *)optional;
    if (magic != 0x20b) {
        g_install_magic = magic; g_install_state = INSTALL_BAD_MAGIC; return;
    }
    unsigned int image_size = *(const unsigned int __unaligned *)(optional + 56);
    unsigned int directory_count = *(const unsigned int __unaligned *)(optional + 108);
    unsigned int imports_rva = directory_count > 1
        ? *(const unsigned int __unaligned *)(optional + 120) : 0;
    unsigned int imports_size = directory_count > 1
        ? *(const unsigned int __unaligned *)(optional + 124) : 0;
    if (!valid_rva(imports_rva, 20, image_size)) {
        g_install_state = INSTALL_NO_IMPORTS; return;
    }

    // IMAGE_IMPORT_DESCRIPTOR is five DWORDs. The walk is capped by both the
    // image and the declared directory size so malformed metadata cannot escape.
    unsigned int descriptor_limit = imports_size / 20;
    if (!descriptor_limit || descriptor_limit > 4096) descriptor_limit = 4096;
    for (unsigned int descriptor_index = 0; descriptor_index < descriptor_limit; ++descriptor_index) {
        unsigned int descriptor_rva = imports_rva + descriptor_index * 20;
        if (!valid_rva(descriptor_rva, 20, image_size)) break;
        const unsigned int __unaligned *descriptor =
            (const unsigned int __unaligned *)(base + descriptor_rva);
        unsigned int original_thunk = descriptor[0];
        unsigned int name_rva = descriptor[3];
        unsigned int first_thunk = descriptor[4];
        if (!original_thunk && !name_rva && !first_thunk) break;
        if (!valid_rva(name_rva, 1, image_size)) continue;
        const char *dll_name = (const char *)(base + name_rva);
        if (!valid_rva(original_thunk, 8, image_size) ||
            !valid_rva(first_thunk, 8, image_size)) continue;

        unsigned int thunk_limit = (image_size - original_thunk) / 8;
        unsigned int iat_limit = (image_size - first_thunk) / 8;
        if (thunk_limit > iat_limit) thunk_limit = iat_limit;
        if (thunk_limit > 65536) thunk_limit = 65536;
        for (unsigned int thunk_index = 0; thunk_index < thunk_limit; ++thunk_index) {
            unsigned __int64 lookup = *(const unsigned __int64 __unaligned *)
                (base + original_thunk + thunk_index * 8);
            if (!lookup) break;
            if (lookup & IMAGE_ORDINAL_FLAG64) continue;
            unsigned int import_name_rva = (unsigned int)lookup;
            if (!valid_rva(import_name_rva, 3, image_size)) continue;
            const char *import_name = (const char *)(base + import_name_rva + 2);

            for (unsigned int guard_index = 0; guard_index < GUARD_COUNT; ++guard_index) {
                guard_entry &entry = g_guards[guard_index];
                if (entry.slot) continue;                       // already patched
                if (!ascii_equal_ci(dll_name, entry.dll)) continue;
                if (!ascii_equal_ci(import_name, entry.function)) continue;

                void **slot = (void **)(base + first_thunk + thunk_index * 8);
                DWORD old_protect = 0;
                if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) break;
                entry.original = *slot;
                *slot = k_guard_thunks[guard_index];
                DWORD ignored = 0;
                VirtualProtect(slot, sizeof(*slot), old_protect, &ignored);
                entry.slot = slot;
                ++g_installed_count;
                break;
            }
        }
    }

    g_install_state = INSTALL_DONE;
}

static void log_main_iat_guards()
{
    trace::line summary;
    trace::prefix(summary, "compat.install");
    summary.text(" state=");
    switch (g_install_state) {
    case INSTALL_DONE: summary.text("done"); break;
    case INSTALL_BAD_DOS: summary.text("bad-dos-header"); break;
    case INSTALL_BAD_PE: summary.text("bad-pe-header"); break;
    case INSTALL_BAD_MAGIC:
        summary.text("unsupported-pe-magic magic="); summary.hex(g_install_magic); break;
    case INSTALL_NO_IMPORTS: summary.text("no-import-directory"); break;
    default: summary.text("not-attempted"); break;
    }
    summary.text(" guards="); summary.decimal(g_installed_count);
    summary.text("/"); summary.decimal(GUARD_COUNT);
    trace::finish(summary);

    for (unsigned int index = 0; index < GUARD_COUNT; ++index) {
        const guard_entry &entry = g_guards[index];
        trace::line line;
        trace::prefix(line, "compat.guard");
        line.text(" "); line.text(entry.dll);
        line.character('!'); line.text(entry.function);
        if (entry.slot) {
            line.text(" state=installed slot="); line.pointer(entry.slot);
            line.text(" before="); line.pointer(entry.original);
            line.text(" after="); line.pointer(*entry.slot);
        } else {
            line.text(" state=import-not-found");
        }
        trace::finish(line);
    }
}

} // namespace compat

extern "C" BOOL WINAPI DllMain(HANDLE, DWORD reason, void *)
{
    if (reason == 1 /* DLL_PROCESS_ATTACH */) compat::install_main_iat_guards();
    return 1;
}


// ---------------------------------------------------------------------------
// Synthetic event injection (controlled experiments only).
//
// After nf_init succeeds, a stand-in for the SDK filtering thread is started when
// EXITLAG_NFAPI_INJECT names a command file. The thread calls threadStart() once
// (as the real SDK does on its filtering thread), then polls for the file. Each
// line is one event; the file is deleted after it is read. Structures are logged
// as raw hex before and after the callback together with a field diff.
//
//   tcp_connect  ID PID LOCALIP LPORT REMOTEIP RPORT [FLAGS]    -> slot 2 tcpConnectRequest
//   tcp_connected ID PID LOCALIP LPORT REMOTEIP RPORT [FLAGS]   -> slot 3 tcpConnected
//   tcp_closed   ID PID LOCALIP LPORT REMOTEIP RPORT [FLAGS]    -> slot 4 tcpClosed
//   udp_created  ID PID LOCALIP LPORT                            -> slot 9 udpCreated
//   udp_connect  ID PID LOCALIP LPORT REMOTEIP RPORT [FLAGS]    -> slot 10 udpConnectRequest
//   udp_closed   ID PID LOCALIP LPORT                            -> slot 11 udpClosed
//   udp_receive  ID REMOTEIP RPORT HEXPAYLOAD                    -> slot 12 udpReceive
//   udp_send     ID REMOTEIP RPORT HEXPAYLOAD                    -> slot 13 udpSend
//   sleep MS
// IPv4 dotted or IPv6 (hex groups, no :: compression) addresses; FLAGS decimal.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _NF_TCP_CONN_INFO {
    unsigned long filteringFlag; unsigned long processId; unsigned char direction;
    unsigned short ip_family; unsigned char localAddress[28]; unsigned char remoteAddress[28];
} NF_TCP_CONN_INFO;                 // 67 bytes
typedef struct _NF_UDP_CONN_INFO {
    unsigned long processId; unsigned short ip_family; unsigned char localAddress[28];
} NF_UDP_CONN_INFO;                 // 34 bytes
typedef struct _NF_UDP_CONN_REQUEST {
    unsigned long filteringFlag; unsigned long processId; unsigned short ip_family;
    unsigned char localAddress[28]; unsigned char remoteAddress[28];
} NF_UDP_CONN_REQUEST;              // 66 bytes
#pragma pack(pop)

typedef void (*cb_id_ptr)(void *self, ENDPOINT_ID id, void *info);
typedef void (*cb_udp_data)(void *self, ENDPOINT_ID id, const unsigned char *remote, const char *buf, int len, NF_UDP_OPTIONS *opt);
typedef void (*cb_void)(void *self);

namespace inject {

static NF_EventHandler *g_handler;
static volatile long g_running;
static HANDLE g_thread;

static bool read_env(const wchar_t *name, wchar_t *buf, DWORD cap)
{
    DWORD size = GetEnvironmentVariableW(name, buf, cap);
    return size && size < cap;
}

static void *slot(unsigned int i)
{
    void *const *vtable = *(void *const *const *)g_handler;
    return vtable[i];
}

static bool parse_u64(const char *&p, unsigned __int64 &v)
{
    while (*p == ' ') ++p;
    if (*p < '0' || *p > '9') return false;
    v = 0;
    while (*p >= '0' && *p <= '9') v = v * 10 + (unsigned)(*p++ - '0');
    return true;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Fills a 28-byte sockaddr (sockaddr_in or sockaddr_in6) from "ip port".
static bool parse_sockaddr(const char *&p, unsigned char *sa, unsigned short &family)
{
    for (int i = 0; i < 28; ++i) sa[i] = 0;
    while (*p == ' ') ++p;
    const char *q = p; bool v6 = false;
    while (*q && *q != ' ') { if (*q == ':') v6 = true; ++q; }
    if (!v6) {
        unsigned __int64 part; unsigned char ip[4];
        for (int i = 0; i < 4; ++i) {
            if (!parse_u64(p, part) || part > 255) return false;
            ip[i] = (unsigned char)part;
            if (i < 3) { if (*p != '.') return false; ++p; }
        }
        unsigned __int64 port; if (!parse_u64(p, port) || port > 65535) return false;
        family = 2; sa[0] = 2; sa[1] = 0; sa[2] = (unsigned char)(port >> 8); sa[3] = (unsigned char)port;
        sa[4] = ip[0]; sa[5] = ip[1]; sa[6] = ip[2]; sa[7] = ip[3];
        return true;
    }
    // IPv6: eight hex groups separated by ':'
    for (int g = 0; g < 8; ++g) {
        unsigned v = 0; int digits = 0, d;
        while ((d = hexval(*p)) >= 0) { v = v * 16 + (unsigned)d; ++p; ++digits; }
        if (!digits) return false;
        sa[8 + g * 2] = (unsigned char)(v >> 8); sa[9 + g * 2] = (unsigned char)v;
        if (g < 7) { if (*p != ':') return false; ++p; }
    }
    unsigned __int64 port; if (!parse_u64(p, port) || port > 65535) return false;
    family = 23; sa[0] = 23; sa[1] = 0; sa[2] = (unsigned char)(port >> 8); sa[3] = (unsigned char)port;
    return true;
}

static void diff_bytes(trace::line &out, const unsigned char *before, const unsigned char *after, unsigned n)
{
    bool any = false;
    for (unsigned i = 0; i < n; ++i) if (before[i] != after[i]) {
        if (!any) out.text(" mutated=["); else out.character(',');
        any = true;
        out.text("@"); out.decimal(i); out.character(':'); out.hex(before[i]); out.text("->"); out.hex(after[i]);
    }
    if (!any) out.text(" mutated=none"); else out.character(']');
}

static void log_tcp_info(trace::line &out, const NF_TCP_CONN_INFO *c)
{
    out.text(" filteringFlag="); out.hex(c->filteringFlag);
    out.text(" processId="); out.decimal(c->processId);
    out.text(" direction="); out.decimal(c->direction);
    out.text(" family="); out.decimal(c->ip_family);
    out.text(" local="); trace::sockaddr_text(out, c->localAddress);
    out.text(" remote="); trace::sockaddr_text(out, c->remoteAddress);
}

// Enumerates ExitLag's per-application server-IP sets so a synthetic connect
// request can use an address the client will actually match.
//
// Layout recovered from the redirect decision at 0x14127d3e0 and the matcher at
// 0x141409db0 (MSVC std::unordered_set<unsigned int>):
//   backend   = handler - 0x48            (tcpConnectRequest does lea rbx,[rcx-0x48])
//   apps      = [backend+0xa0] .. [backend+0xa8], stride 0x10, app = *entry
//   set       = [app+0x100]; sentinel = [set+0x10]; node->next = [node+0];
//               key (host-order IPv4) = [node+0x10]
// Every dereference is bounded with readable_bytes(), so a wrong guess prints
// nothing useful instead of faulting. A key is "confirmed" only when injecting it
// makes ExitLag rewrite the address.
static bool read_ptr(const void *at, unsigned __int64 &value)
{
    if (trace::readable_bytes(at, 8) < 8) return false;
    value = *(const unsigned __int64 __unaligned *)at;
    return true;
}

static void dump_apps(unsigned __int64 vector_offset)
{
    trace::line out; trace::prefix(out, "inject.dump_apps");
    out.text(" vectorOffset="); out.hex(vector_offset);
    unsigned char *backend = (unsigned char *)g_handler - 0x48;
    out.text(" handler="); out.pointer(g_handler); out.text(" backend="); out.pointer(backend);
    unsigned __int64 begin = 0, end = 0;
    if (!read_ptr(backend + vector_offset, begin) || !read_ptr(backend + vector_offset + 8, end)) {
        out.text(" error=apps-vector-unreadable"); trace::finish(out); return;
    }
    out.text(" appsBegin="); out.hex(begin); out.text(" appsEnd="); out.hex(end);
    unsigned count = (begin && end && end > begin) ? (unsigned)((end - begin) / 0x10) : 0;
    out.text(" appCount="); out.decimal(count);
    trace::finish(out);
    for (unsigned i = 0; i < count && i < 64; ++i) {
        unsigned __int64 app = 0;
        if (!read_ptr((const void *)(begin + (unsigned __int64)i * 0x10), app) || !app) continue;
        unsigned __int64 set = 0, sentinel = 0;
        trace::line a; trace::prefix(a, "inject.dump_apps.app");
        a.text(" index="); a.decimal(i); a.text(" app="); a.hex(app);
        if (!read_ptr((const void *)(app + 0x100), set) || !set) { a.text(" serverSet=none"); trace::finish(a); continue; }
        a.text(" serverSet="); a.hex(set);
        if (!read_ptr((const void *)(set + 0x10), sentinel) || !sentinel) { a.text(" sentinel=unreadable"); trace::finish(a); continue; }
        a.text(" sentinel="); a.hex(sentinel);
        unsigned __int64 node = 0;
        if (!read_ptr((const void *)sentinel, node)) { a.text(" head=unreadable"); trace::finish(a); continue; }
        a.text(" ips=[");
        unsigned printed = 0;
        while (node && node != sentinel && printed < 512) {
            if (trace::readable_bytes((const void *)(node + 0x10), 4) < 4) break;
            unsigned key = *(const unsigned __int32 __unaligned *)(node + 0x10);
            if (printed) a.character(',');
            a.decimal((key >> 24) & 0xff); a.character('.'); a.decimal((key >> 16) & 0xff);
            a.character('.'); a.decimal((key >> 8) & 0xff); a.character('.'); a.decimal(key & 0xff);
            ++printed;
            unsigned __int64 next = 0;
            if (!read_ptr((const void *)node, next)) break;
            node = next;
        }
        a.character(']'); a.text(" printed="); a.decimal(printed);
        trace::finish(a);
    }
}

// Read-only search of this process's own committed memory. Used to recover the
// application configuration (process-name lists) that ExitLag downloads at runtime
// and never writes to disk. Regions are enumerated with VirtualQuery and only
// committed, readable, non-guard pages are touched.
static void scan_memory(const char *needle, bool utf16, unsigned max_hits, unsigned context)
{
    unsigned char pattern[128];
    unsigned plen = 0;
    for (const char *q = needle; *q && plen + 2 < sizeof(pattern); ++q) {
        pattern[plen++] = (unsigned char)*q;
        if (utf16) pattern[plen++] = 0;
    }
    trace::line head; trace::prefix(head, "inject.scan");
    head.text(" needle="); head.quoted_ascii(needle, 64);
    head.text(utf16 ? " encoding=utf16le" : " encoding=ascii");
    head.text(" patternLength="); head.decimal(plen);
    trace::finish(head);
    if (!plen) return;

    unsigned hits = 0;
    unsigned __int64 address = 0x10000;
    while (address < 0x00007fffffff0000ULL && hits < max_hits) {
        MEMORY_BASIC_INFORMATION64 info;
        if (!VirtualQuery((const void *)address, &info, sizeof(info))) break;
        unsigned __int64 base = (unsigned __int64)info.BaseAddress;
        unsigned __int64 size = info.RegionSize;
        if (!size) break;
        bool usable = info.State == MEM_COMMIT && info.Protect &&
                      !(info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                      size <= 128ULL * 1024 * 1024;
        if (usable) {
            const unsigned char *p = (const unsigned char *)base;
            unsigned __int64 limit = size - plen;
            for (unsigned __int64 i = 0; i <= limit && hits < max_hits; ++i) {
                if (p[i] != pattern[0]) continue;
                unsigned j = 1;
                while (j < plen && p[i + j] == pattern[j]) ++j;
                if (j != plen) continue;
                ++hits;
                trace::line out; trace::prefix(out, "inject.scan.hit");
                out.text(" index="); out.decimal(hits);
                out.text(" at="); out.hex(base + i);
                out.text(" regionBase="); out.hex(base);
                unsigned __int64 start = i > context ? i - context : 0;
                unsigned __int64 stop = i + context; if (stop > size) stop = size;
                out.text(" context=\"");
                for (unsigned __int64 k = start; k < stop; ++k) {
                    unsigned char c = p[k];
                    if (c == '"' || c == '\\') out.character('.');
                    else out.character(c >= 32 && c < 127 ? (char)c : '.');
                }
                out.character('"');
                trace::finish(out);
                i += plen;
            }
        }
        address = base + size;
    }
    trace::line tail; trace::prefix(tail, "inject.scan.done"); tail.text(" hits="); tail.decimal(hits);
    trace::finish(tail);
}

// Raw hex window of this process's memory, used to verify recovered object
// layouts instead of trusting a guessed offset. Bounded by readable_bytes().
static void dump_mem(unsigned __int64 at, unsigned length, const char *label)
{
    trace::line out; trace::prefix(out, "inject.dump_mem");
    out.text(" label="); out.text(label); out.text(" at="); out.hex(at);
    out.text(" requested="); out.decimal(length);
    if (length > 1024) length = 1024;
    unsigned __int64 n = trace::readable_bytes((const void *)at, length);
    out.text(" readable="); out.decimal(n);
    out.text(" qwords=[");
    for (unsigned __int64 i = 0; i + 8 <= n; i += 8) {
        if (i) out.character(',');
        out.text("+"); out.hex(i); out.character('=');
        out.hex(*(const unsigned __int64 __unaligned *)(at + i));
    }
    out.character(']');
    trace::finish(out);
}

static void run_event(const char *line)
{
    const char *p = line;
    char cmd[32]; unsigned n = 0;
    while (*p && *p != ' ' && n + 1 < sizeof(cmd)) cmd[n++] = *p++;
    cmd[n] = 0;
    trace::line out; trace::prefix(out, "inject");
    out.text(" event="); out.text(cmd);

    auto same = [](const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; };

    if (same(cmd, "dump_apps")) { unsigned __int64 off = 0xa0; parse_u64(p, off); trace::finish(out); dump_apps(off); return; }
    if (same(cmd, "dump_backend")) {
        unsigned __int64 off = 0, len = 512;
        parse_u64(p, off); parse_u64(p, len);
        trace::finish(out);
        dump_mem((unsigned __int64)((unsigned char *)g_handler - 0x48) + off, (unsigned)len, "backend");
        return;
    }
    if (same(cmd, "scan_utf16") || same(cmd, "scan_ascii")) {
        bool utf16 = same(cmd, "scan_utf16");
        while (*p == ' ') ++p;
        static char needle[128]; unsigned k = 0;
        while (*p && *p != '|' && k + 1 < sizeof(needle)) needle[k++] = *p++;
        needle[k] = 0;
        unsigned __int64 max_hits = 6, context = 240;
        if (*p == '|') { ++p; parse_u64(p, max_hits); parse_u64(p, context); }
        trace::finish(out);
        scan_memory(needle, utf16, (unsigned)max_hits, (unsigned)context);
        return;
    }
    if (same(cmd, "sleep")) {
        unsigned __int64 ms; if (parse_u64(p, ms)) { out.text(" ms="); out.decimal(ms); trace::finish(out); Sleep((DWORD)ms); }
        return;
    }
    unsigned __int64 id;
    if (!parse_u64(p, id)) { out.text(" error=bad-id"); trace::finish(out); return; }
    out.text(" id="); out.hex(id);

    if (same(cmd, "tcp_connect") || same(cmd, "tcp_connected") || same(cmd, "tcp_closed")) {
        unsigned slot_index = same(cmd, "tcp_connect") ? 2 : same(cmd, "tcp_connected") ? 3 : 4;
        NF_TCP_CONN_INFO info; unsigned char *raw = (unsigned char *)&info;
        for (unsigned i = 0; i < sizeof(info); ++i) raw[i] = 0;
        unsigned __int64 pid; unsigned short fl, fr;
        if (!parse_u64(p, pid) || !parse_sockaddr(p, info.localAddress, fl) || !parse_sockaddr(p, info.remoteAddress, fr)) {
            out.text(" error=bad-args"); trace::finish(out); return;
        }
        unsigned __int64 flags = 0x10; parse_u64(p, flags);
        info.filteringFlag = (unsigned long)flags; info.processId = (unsigned long)pid; info.direction = 2; info.ip_family = fr;
        NF_TCP_CONN_INFO before = info;
        out.text(" slot="); out.decimal(slot_index); out.text(" target="); out.pointer(slot(slot_index));
        out.text(" sizeof="); out.decimal(sizeof(info)); out.text(" before:"); log_tcp_info(out, &before);
        out.text(" beforeRaw="); out.byte_array(raw, sizeof(info));
        trace::finish(out);
        ((cb_id_ptr)slot(slot_index))(g_handler, id, &info);
        trace::line post; trace::prefix(post, "inject.return"); post.text(" event="); post.text(cmd); post.text(" id="); post.hex(id);
        post.text(" after:"); log_tcp_info(post, &info); post.text(" afterRaw="); post.byte_array(raw, sizeof(info));
        diff_bytes(post, (unsigned char *)&before, raw, sizeof(info));
        trace::finish(post);
        return;
    }
    if (same(cmd, "udp_created") || same(cmd, "udp_closed")) {
        unsigned slot_index = same(cmd, "udp_created") ? 9 : 11;
        NF_UDP_CONN_INFO info; unsigned char *raw = (unsigned char *)&info;
        for (unsigned i = 0; i < sizeof(info); ++i) raw[i] = 0;
        unsigned __int64 pid; unsigned short fl;
        if (!parse_u64(p, pid) || !parse_sockaddr(p, info.localAddress, fl)) { out.text(" error=bad-args"); trace::finish(out); return; }
        info.processId = (unsigned long)pid; info.ip_family = fl;
        NF_UDP_CONN_INFO before = info;
        out.text(" slot="); out.decimal(slot_index); out.text(" target="); out.pointer(slot(slot_index));
        out.text(" sizeof="); out.decimal(sizeof(info)); out.text(" processId="); out.decimal(pid);
        out.text(" local="); trace::sockaddr_text(out, info.localAddress); out.text(" beforeRaw="); out.byte_array(raw, sizeof(info));
        trace::finish(out);
        ((cb_id_ptr)slot(slot_index))(g_handler, id, &info);
        trace::line post; trace::prefix(post, "inject.return"); post.text(" event="); post.text(cmd); post.text(" id="); post.hex(id);
        post.text(" afterRaw="); post.byte_array(raw, sizeof(info)); diff_bytes(post, (unsigned char *)&before, raw, sizeof(info));
        trace::finish(post);
        return;
    }
    if (same(cmd, "udp_connect")) {
        NF_UDP_CONN_REQUEST info; unsigned char *raw = (unsigned char *)&info;
        for (unsigned i = 0; i < sizeof(info); ++i) raw[i] = 0;
        unsigned __int64 pid; unsigned short fl, fr;
        if (!parse_u64(p, pid) || !parse_sockaddr(p, info.localAddress, fl) || !parse_sockaddr(p, info.remoteAddress, fr)) {
            out.text(" error=bad-args"); trace::finish(out); return;
        }
        unsigned __int64 flags = 0x12; parse_u64(p, flags);
        info.filteringFlag = (unsigned long)flags; info.processId = (unsigned long)pid; info.ip_family = fr;
        NF_UDP_CONN_REQUEST before = info;
        out.text(" slot=10 target="); out.pointer(slot(10)); out.text(" sizeof="); out.decimal(sizeof(info));
        out.text(" filteringFlag="); out.hex(info.filteringFlag); out.text(" processId="); out.decimal(pid);
        out.text(" local="); trace::sockaddr_text(out, info.localAddress); out.text(" remote="); trace::sockaddr_text(out, info.remoteAddress);
        out.text(" beforeRaw="); out.byte_array(raw, sizeof(info));
        trace::finish(out);
        ((cb_id_ptr)slot(10))(g_handler, id, &info);
        trace::line post; trace::prefix(post, "inject.return"); post.text(" event=udp_connect id="); post.hex(id);
        post.text(" after: filteringFlag="); post.hex(info.filteringFlag); post.text(" remote="); trace::sockaddr_text(post, info.remoteAddress);
        post.text(" afterRaw="); post.byte_array(raw, sizeof(info)); diff_bytes(post, (unsigned char *)&before, raw, sizeof(info));
        trace::finish(post);
        return;
    }
    if (same(cmd, "udp_send") || same(cmd, "udp_receive")) {
        unsigned slot_index = same(cmd, "udp_send") ? 13 : 12;
        unsigned char remote[28]; unsigned short fr;
        if (!parse_sockaddr(p, remote, fr)) { out.text(" error=bad-remote"); trace::finish(out); return; }
        while (*p == ' ') ++p;
        static char payload[2048]; int len = 0; int hi, lo;
        while ((hi = hexval(p[0])) >= 0 && (lo = hexval(p[1])) >= 0 && len < (int)sizeof(payload)) { payload[len++] = (char)(hi * 16 + lo); p += 2; }
        unsigned char remote_before[28]; for (int i = 0; i < 28; ++i) remote_before[i] = remote[i];
        struct { unsigned long flags; long optionsLength; unsigned char options[8]; } opt = {0, 0, {0}};
        out.text(" slot="); out.decimal(slot_index); out.text(" target="); out.pointer(slot(slot_index));
        out.text(" remote="); trace::sockaddr_text(out, remote); out.text(" remoteRaw="); out.byte_array(remote, 28);
        out.text(" len="); out.decimal(len); out.text(" payload="); out.byte_array((unsigned char *)payload, len < 64 ? len : 64);
        out.text(" options={flags=0,optionsLength=0}");
        trace::finish(out);
        ((cb_udp_data)slot(slot_index))(g_handler, id, remote, payload, len, (NF_UDP_OPTIONS *)&opt);
        trace::line post; trace::prefix(post, "inject.return"); post.text(" event="); post.text(cmd); post.text(" id="); post.hex(id);
        post.text(" remoteAfter="); trace::sockaddr_text(post, remote); diff_bytes(post, remote_before, remote, 28);
        post.text(" optionsAfter={flags="); post.hex(opt.flags); post.text(",optionsLength="); post.signed_decimal(opt.optionsLength); post.character('}');
        trace::finish(post);
        return;
    }
    out.text(" error=unknown-event"); trace::finish(out);
}

static DWORD WINAPI thread_main(void *)
{
    wchar_t path[1024];
    if (!read_env(L"EXITLAG_NFAPI_INJECT", path, sizeof(path) / sizeof(path[0]))) return 0;
    {
        trace::line out; trace::prefix(out, "inject.thread"); out.text(" state=start calling=threadStart slot=0 target="); out.pointer(slot(0)); trace::finish(out);
        ((cb_void)slot(0))(g_handler);
    }
    static char buffer[65536];
    while (g_running) {
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (file == INVALID_HANDLE_VALUE) { Sleep(200); continue; }
        DWORD got = 0;
        ReadFile(file, buffer, sizeof(buffer) - 1, &got, 0);
        CloseHandle(file);
        DeleteFileW(path);
        buffer[got] = 0;
        char *line = buffer;
        while (*line) {
            char *end = line;
            while (*end && *end != '\n' && *end != '\r') ++end;
            char saved = *end; *end = 0;
            if (*line && *line != '#') run_event(line);
            if (!saved) break;
            line = end + 1;
        }
    }
    {
        trace::line out; trace::prefix(out, "inject.thread"); out.text(" state=stop calling=threadEnd slot=1 target="); out.pointer(slot(1)); trace::finish(out);
        ((cb_void)slot(1))(g_handler);
    }
    return 0;
}

static void start(NF_EventHandler *handler)
{
    wchar_t path[1024];
    if (!handler || !read_env(L"EXITLAG_NFAPI_INJECT", path, sizeof(path) / sizeof(path[0]))) return;
    g_handler = handler; g_running = 1;
    g_thread = CreateThread(0, 0, thread_main, 0, 0, 0);
}

static void stop()
{
    g_running = 0;
    g_thread = 0;
}

} // namespace inject


// ---------------------------------------------------------------------------
// Native-helper transport (Stage 1).
//
// The shim owns the Windows nfapi ABI and ExitLag's callback object; the helper
// owns packet observation and Linux attribution. They speak the framed protocol
// in backend/protocol.h over loopback TCP (Wine's ws2_32 has no AF_UNIX).
//
// Failure is always open: if the helper is absent, unreachable, or speaks a
// version we do not know, the shim keeps working exactly as before and ExitLag
// is never blocked. The transport lives on its own thread and never calls into
// ExitLag from a path that could be re-entered by the helper.
// ---------------------------------------------------------------------------


namespace ipc {

static volatile long g_running;
static SOCKET g_socket = INVALID_SOCKET;
static unsigned __int64 g_tag;
static volatile long g_send_lock;
static unsigned __int64 g_udp_session;

struct udp_event_context {
    unsigned __int64 tag, id, session;
    SOCKET socket;
    unsigned int post_count, rule_count, control_count;
    unsigned int direction;
    unsigned char *scratch;
    char *resolve_buffer;
    unsigned char *owner_table;
    udp_event_context *previous;
};

// The TLS slot lives as long as the DLL. nf_free does not yet join every
// worker, so freeing/reusing this slot there would expose stale callbacks.
static DWORD g_udp_tls = 0xffffffffUL;
static volatile long g_udp_tls_state;

static bool ensure_udp_tls()
{
    long expected = 0;
    if (__atomic_compare_exchange_n(&g_udp_tls_state, &expected, 1, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        g_udp_tls = TlsAlloc();
        __atomic_store_n(&g_udp_tls_state, g_udp_tls == 0xffffffffUL ? -1 : 2,
                         __ATOMIC_RELEASE);
    }
    while (__atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) == 1) Sleep(0);
    return __atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) == 2;
}

static udp_event_context *current_udp_event(ENDPOINT_ID id)
{
    if (__atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) != 2) return 0;
    udp_event_context *context = (udp_event_context *)TlsGetValue(g_udp_tls);
    if (!context || !__atomic_load_n(&g_running, __ATOMIC_ACQUIRE) ||
        context->socket != __atomic_load_n(&g_socket, __ATOMIC_ACQUIRE) ||
        !exl_udp_validation::context_matches(context->tag, context->id, context->session,
            __atomic_load_n(&g_udp_session, __ATOMIC_ACQUIRE), id)) return 0;
    return context;
}

class udp_event_scope {
    bool bound;
public:
    udp_event_context context;
    udp_event_scope(unsigned __int64 tag, ENDPOINT_ID id, unsigned int direction = 0) : bound(false), context{}
    {
        if (!ensure_udp_tls()) return;
        context.previous = (udp_event_context *)TlsGetValue(g_udp_tls);
        if (!context.previous ||
            context.previous->session != __atomic_load_n(&g_udp_session, __ATOMIC_ACQUIRE) ||
            context.previous->socket != __atomic_load_n(&g_socket, __ATOMIC_ACQUIRE)) return;
        context.tag = tag; context.id = id;
        context.direction = direction;
        context.session = context.previous->session;
        context.socket = context.previous->socket;
        context.scratch = context.previous->scratch;
        context.resolve_buffer = context.previous->resolve_buffer;
        context.owner_table = context.previous->owner_table;
        bound = TlsSetValue(g_udp_tls, &context) != 0;
    }
    bool valid() const { return bound && current_udp_event(context.id) == &context; }
    ~udp_event_scope() { if (bound) TlsSetValue(g_udp_tls, context.previous); }
};

using exl_pid_domain::pid_origin;
using exl_pid_domain::pid_unknown;
using exl_pid_domain::pid_linux;
using exl_pid_domain::pid_windows;
using exl_pid_domain::pid_ambiguous;

// Numeric Windows and Linux PIDs can collide. Record both observed domains
// without eviction; collisions and saturation disable attributed callbacks.
// This POD is never reset while worker/SDK calls can still refer to old PIDs.
static exl_pid_domain::registry g_process_pids;

static bool remember_process_pid(unsigned int pid, pid_origin domain)
{
    return exl_pid_domain::remember_pid(g_process_pids, pid, domain);
}

static pid_origin process_pid_origin(unsigned int pid)
{
    return exl_pid_domain::lookup_pid(g_process_pids, pid);
}

static bool send_all(SOCKET s, const char *data, int length)
{
    while (length > 0) {
        int n = send(s, data, length, 0);
        if (n <= 0) return false;
        data += n; length -= n;
    }
    return true;
}

static bool recv_all(SOCKET s, char *data, int length)
{
    while (length > 0) {
        int n = recv(s, data, length, 0);
        if (n <= 0) return false;
        data += n; length -= n;
    }
    return true;
}

static bool send_message(SOCKET s, unsigned short type, const void *payload, unsigned int length);

// Synchronous PID -> path request, issued from inside an ExitLag callback while
// the helper is already waiting for that callback's reply. The helper serves it
// nested, so this is safe on the same connection.
static int resolve_linux_pid(unsigned int pid, wchar_t *buffer, unsigned long length)
{
    udp_event_context *transport = __atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) == 2 ?
        (udp_event_context *)TlsGetValue(g_udp_tls) : 0;
    if (!transport || !transport->resolve_buffer || !buffer || !length ||
        transport->session != __atomic_load_n(&g_udp_session, __ATOMIC_ACQUIRE) ||
        transport->socket != __atomic_load_n(&g_socket, __ATOMIC_ACQUIRE)) return 0;
    SOCKET s = transport->socket;
    exl_resolve_pid_req req;
    req.tag = __atomic_add_fetch(&g_tag, 1, __ATOMIC_RELAXED); req.process_id = pid; req.reserved = 0;
    if (!send_message(s, EXL_MSG_RESOLVE_PID_REQ, &req, sizeof(req))) return 0;

    for (;;) {
        exl_header head;
        if (!recv_all(s, (char *)&head, (int)sizeof(head))) return 0;
        if (!exl_ipc_validation::valid_frame_header(head)) return 0;
        char *payload = transport->resolve_buffer;
        if (head.length && !recv_all(s, payload, (int)head.length)) return 0;
        if (head.type != EXL_MSG_RESOLVE_PID_REPLY) continue;
        if (head.length < sizeof(exl_resolve_pid_reply)) return 0;
        const exl_resolve_pid_reply *reply = (const exl_resolve_pid_reply *)payload;
        if (reply->tag != req.tag) continue;
        return exl_ipc_validation::copy_pid_reply_path(*reply, payload, head.length,
                                                      buffer, length) ? 1 : 0;
    }
}

static bool send_message(SOCKET s, unsigned short type, const void *payload, unsigned int length)
{
    while (__atomic_exchange_n(&g_send_lock, 1, __ATOMIC_ACQUIRE)) Sleep(0);
    exl_header head; head.magic = EXL_MAGIC; head.type = type; head.flags = 0; head.length = length;
    bool ok = send_all(s, (const char *)&head, (int)sizeof(head)) &&
              (!length || send_all(s, (const char *)payload, (int)length));
    __atomic_store_n(&g_send_lock, 0, __ATOMIC_RELEASE);
    return ok;
}

static bool send_udp_message_parts(udp_event_context *context, unsigned short type,
                                   const void *fixed, unsigned int fixed_length,
                                   const void *first, unsigned int first_length,
                                   const void *second, unsigned int second_length)
{
    if (!context || first_length > EXL_MAX_PAYLOAD - fixed_length ||
        second_length > EXL_MAX_PAYLOAD - fixed_length - first_length) return false;
    while (__atomic_exchange_n(&g_send_lock, 1, __ATOMIC_ACQUIRE)) Sleep(0);
    bool ok = current_udp_event(context->id) == context;
    unsigned int length = fixed_length + first_length + second_length;
    exl_header head; head.magic = EXL_MAGIC; head.type = type; head.flags = 0; head.length = length;
    if (ok) ok = send_all(context->socket, (const char *)&head, (int)sizeof(head)) &&
              (!fixed_length || send_all(context->socket, (const char *)fixed, (int)fixed_length)) &&
              (!first_length || send_all(context->socket, (const char *)first, (int)first_length)) &&
              (!second_length || send_all(context->socket, (const char *)second, (int)second_length));
    __atomic_store_n(&g_send_lock, 0, __ATOMIC_RELEASE);
    return ok && current_udp_event(context->id) == context;
}

static bool prepare_udp_post(const unsigned char *remote, const char *buffer, int length,
                              NF_UDP_OPTIONS __unaligned *options, unsigned char wire[28],
                              unsigned int &options_length)
{
    options_length = 0;
    if (options) {
        if (trace::readable_bytes(options, 8) != 8 ||
            options->optionsLength < 0 || options->optionsLength > 4096) return false;
        options_length = (unsigned int)options->optionsLength;
        if (trace::readable_bytes(options, 8u + options_length) != 8u + options_length) return false;
    }
    if (!remote || trace::readable_bytes(remote, 4) != 4) return false;
    unsigned int family = exl_socket_attribution::endpoint_family(remote, 4);
    // sockaddr_in's sin_zero is padding, not a routing field. Do not copy
    // potentially uninitialized caller padding into IPC or reject it as policy.
    unsigned int remote_length = family == 2 ? 8u : family == 23 ? 28u : 0u;
    if (!remote_length || trace::readable_bytes(remote, remote_length) != remote_length ||
        !exl_udp_validation::valid_post_arguments(remote, buffer, length, (int)options_length) ||
        (length && trace::readable_bytes(buffer, (unsigned int)length) != (unsigned int)length)) return false;
    return exl_udp_validation::canonical_post_remote(remote, remote_length, wire, 28);
}

// SDK posts are valid only on the current synchronous callback thread. They
// carry that callback's tag and session; async or endpoint-mismatched calls
// explicitly fail instead of borrowing another thread's active event.
static bool report_udp_post(unsigned int api, ENDPOINT_ID id, int status,
                            const unsigned char *remote, const char *buffer, int length,
                            NF_UDP_OPTIONS __unaligned *options)
{
    udp_event_context *context = current_udp_event(id);
    unsigned char wire[28]; unsigned int options_length;
    if (!context || (api == EXL_UDP_API_POST_SEND ? context->direction != EXL_DIR_OUT :
                     api == EXL_UDP_API_POST_RECEIVE ? context->direction != EXL_DIR_IN : true) ||
        !prepare_udp_post(remote, buffer, length, options, wire, options_length)) return false;
    exl_udp_post event;
    event.event_tag = context->tag;
    event.endpoint_id = id; event.api = api; event.status = status;
    for (int i = 0; i < 28; ++i) event.remote_address[i] = wire[i];
    event.option_flags = options ? options->flags : 0; event.options_length = options_length;
    event.payload_length = (unsigned int)length;
    if (!send_udp_message_parts(context, EXL_MSG_UDP_POST, &event, sizeof(event),
             options_length ? options->options : 0, options_length, buffer, (unsigned int)length)) return false;
    ++context->post_count;
    return true;
}

static bool report_udp_state(unsigned int api, ENDPOINT_ID id, int status,
                             unsigned int value, const void *data, unsigned int data_length)
{
    udp_event_context *context = current_udp_event(id);
    if (!context || data_length > 128 || (data_length &&
        (!data || trace::readable_bytes(data, data_length) != data_length))) return false;
    exl_udp_state event;
    event.event_tag = context->tag;
    event.endpoint_id = id; event.api = api;
    event.status = status; event.value = value; event.data_length = data_length;
    if (!send_udp_message_parts(context, EXL_MSG_UDP_STATE, &event, sizeof(event),
                                 data, data_length, 0, 0)) return false;
    if (api == EXL_UDP_API_ADD_REMOTE_RULE) ++context->rule_count;
    else ++context->control_count;
    return true;
}


// Both owner-table APIs write before decoding. Keep their storage private to
// this worker even while an older, unjoined nf_free worker is unwinding.
static const unsigned long OWNER_TABLE_CAPACITY = 512u * 1024u;
static const unsigned long OWNER_TABLE_OFFSET = (EXL_MAX_PAYLOAD * 2u + 65535u + 15u) & ~15u;
static unsigned char *worker_owner_table()
{
    if (__atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) != 2) return 0;
    udp_event_context *transport = (udp_event_context *)TlsGetValue(g_udp_tls);
    if (!transport || !transport->owner_table ||
        !__atomic_load_n(&g_running, __ATOMIC_ACQUIRE) ||
        transport->session != __atomic_load_n(&g_udp_session, __ATOMIC_ACQUIRE) ||
        transport->socket != __atomic_load_n(&g_socket, __ATOMIC_ACQUIRE)) return 0;
    return transport->owner_table;
}

// ---- flow -> owning Windows PID -------------------------------------------
#define TCP_TABLE_OWNER_PID_ALL 5
#define UDP_TABLE_OWNER_PID 1
#define AF_INET_  2
#define AF_INET6_ 23

static_assert(sizeof(unsigned long) == sizeof(exl_socket_attribution::u32),
              "iphlpapi DWORD argument must retain the Windows ABI");

static exl_socket_attribution::owner_result query_windows_tcp_owner(
    unsigned char *buffer, unsigned long capacity, unsigned int family,
    const unsigned char *local, const unsigned char *remote, bool mapped)
{
    unsigned long size = capacity;
    if (GetExtendedTcpTable(buffer, &size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0))
        return exl_socket_attribution::result(exl_socket_attribution::owner_unavailable);
    if (mapped)
        return exl_socket_attribution::lookup_tcp_mapped_owner(buffer, capacity, size,
                                                              local, 28, remote, 28);
    return exl_socket_attribution::lookup_tcp_owner(buffer, capacity, size,
                                                   family, local, 28, remote, 28);
}

// Endpoints use Windows sockaddr layouts; the portable decoder checks the
// complete tuple and returned table span before choosing a Windows PID.
static exl_socket_attribution::owner_result owning_windows_pid(
    const unsigned char *local, const unsigned char *remote)
{
    unsigned char *buffer = worker_owner_table();
    if (!buffer) return exl_socket_attribution::result(exl_socket_attribution::owner_invalid);
    unsigned int family = exl_socket_attribution::endpoint_family(local, 28);
    if (!exl_socket_attribution::valid_endpoint(local, 28, family) ||
        !exl_socket_attribution::valid_endpoint(remote, 28, family))
        return exl_socket_attribution::result(exl_socket_attribution::owner_invalid);
    exl_socket_attribution::owner_result exact = query_windows_tcp_owner(
        buffer, OWNER_TABLE_CAPACITY, family, local, remote, false);
    if (family != AF_INET_ ||
        (exact.status != exl_socket_attribution::owner_none &&
         exact.status != exl_socket_attribution::owner_unavailable)) return exact;
    // A dual-stack socket can be listed under IPv6 while its packets are IPv4.
    // Query that table only after no exact IPv4 owner was obtained, constructing
    // both explicit mapped endpoints with zero scopes. Runtime Wine behavior is
    // not assumed by the native fixtures; errors retain their unavailable state.
    exl_socket_attribution::owner_result mapped = query_windows_tcp_owner(
        buffer, OWNER_TABLE_CAPACITY, AF_INET6_, local, remote, true);
    return exl_socket_attribution::combine_tcp_owners(exact, mapped);
}

static exl_socket_attribution::owner_result query_windows_udp_owner(
    unsigned char *buffer, unsigned long capacity, unsigned int family,
    const unsigned char *local, bool mapped)
{
    unsigned long size = capacity;
    if (GetExtendedUdpTable(buffer, &size, 0, family, UDP_TABLE_OWNER_PID, 0))
        return exl_socket_attribution::result(exl_socket_attribution::owner_unavailable);
    return mapped ? exl_socket_attribution::lookup_udp_mapped_owner(buffer, capacity, size, local, 28) :
        exl_socket_attribution::lookup_udp_owner(buffer, capacity, size, family, local, 28);
}

static exl_socket_attribution::owner_result owning_windows_udp_pid(const unsigned char *local)
{
    unsigned char *buffer = worker_owner_table();
    if (!buffer) return exl_socket_attribution::result(exl_socket_attribution::owner_invalid);
    unsigned int family = exl_socket_attribution::endpoint_family(local, 28);
    if (!exl_socket_attribution::valid_endpoint(local, 28, family))
        return exl_socket_attribution::result(exl_socket_attribution::owner_invalid);
    exl_socket_attribution::owner_result exact = query_windows_udp_owner(
        buffer, OWNER_TABLE_CAPACITY, family, local, false);
    if (family != AF_INET_) return exact;
    // Check both compatible address families. Distinct owners or an ambiguous
    // IPv6 ANY bind must not be hidden by an exact IPv4 row.
    exl_socket_attribution::owner_result mapped = query_windows_udp_owner(
        buffer, OWNER_TABLE_CAPACITY, AF_INET6_, local, true);
    return exl_socket_attribution::combine_tcp_owners(exact, mapped);
}

// Invokes ExitLag's real tcpConnectRequest (vtable slot 2) with a structure
// built from the helper's observation, then reports exactly what changed.
static void handle_tcp_connect(const exl_tcp_connect_req &req, exl_tcp_connect_reply &reply)
{
    // Prefer the real Windows owner: that is what ExitLag expects, and it lets
    // nf_getProcessNameFromKernel answer from OpenProcess directly. Only fall
    // back to the helper's Linux PID when the flow belongs to a non-Wine process.
    exl_tcp_callback_policy::passthrough_reply(req, reply);
    exl_socket_attribution::owner_result windows_owner =
        owning_windows_pid(req.local_address, req.remote_address);
    exl_tcp_callback_policy::process_selection selected =
        exl_tcp_callback_policy::select_process(windows_owner, req.process_id);
    unsigned int process_id = selected.pid;
    if (!process_id || !remember_process_pid(process_id, selected.origin) ||
        process_pid_origin(process_id) != selected.origin) {
        trace::line rejected; trace::prefix(rejected, "ipc.tcpConnectRequest.skipped");
        rejected.text(" reason=unverified-or-ambiguous-owner windows_status=");
        rejected.decimal((unsigned int)windows_owner.status);
        trace::finish(rejected);
        return;
    }
    bool windows_pid = selected.origin == pid_windows;

    reply.tag = req.tag; reply.mutated_flag = 0; reply.mutated_remote = 0;
    reply.reserved[0] = reply.reserved[1] = 0;

    NF_TCP_CONN_INFO info;
    unsigned char *raw = (unsigned char *)&info;
    for (unsigned i = 0; i < sizeof(info); ++i) raw[i] = 0;
    info.filteringFlag = req.filtering_flag;
    info.processId = process_id;
    info.direction = req.direction;
    info.ip_family = req.ip_family;
    for (int i = 0; i < 28; ++i) { info.localAddress[i] = req.local_address[i]; info.remoteAddress[i] = req.remote_address[i]; }
    NF_TCP_CONN_INFO before = info;

    trace::line out; trace::prefix(out, "ipc.tcpConnectRequest");
    out.text(" tag="); out.hex(req.tag); out.text(" id="); out.hex(req.endpoint_id);
    out.text(" processId="); out.decimal(process_id);
    out.text(windows_pid ? "(windows)" : "(linux)");
    out.text(" before: filteringFlag="); out.hex(info.filteringFlag);
    out.text(" local="); trace::sockaddr_text(out, info.localAddress);
    out.text(" remote="); trace::sockaddr_text(out, info.remoteAddress);
    out.text(" beforeRaw="); out.byte_array(raw, sizeof(info));

    if (!inject::g_handler) {
        out.text(" verdict=no-handler"); trace::finish(out);
        reply.verdict = EXL_VERDICT_NO_HANDLER;
        reply.filtering_flag = req.filtering_flag;
        for (int i = 0; i < 28; ++i) reply.remote_address[i] = req.remote_address[i];
        return;
    }
    trace::finish(out);

    ((cb_id_ptr)inject::slot(2))(inject::g_handler, req.endpoint_id, &info);

    if (process_pid_origin(process_id) != selected.origin) {
        // A concurrent SDK/event observation exposed a cross-domain collision.
        // Discard this callback mutation rather than apply an ambiguous name.
        exl_tcp_callback_policy::passthrough_reply(req, reply);
        trace::line rejected; trace::prefix(rejected, "ipc.tcpConnectRequest.skipped");
        rejected.text(" reason=pid-domain-changed-during-callback");
        trace::finish(rejected);
        return;
    }

    trace::line post; trace::prefix(post, "ipc.tcpConnectRequest.return");
    post.text(" tag="); post.hex(req.tag);
    post.text(" after: filteringFlag="); post.hex(info.filteringFlag);
    post.text(" remote="); trace::sockaddr_text(post, info.remoteAddress);
    post.text(" afterRaw="); post.byte_array(raw, sizeof(info));
    inject::diff_bytes(post, (const unsigned char *)&before, raw, sizeof(info));

    reply.filtering_flag = info.filteringFlag;
    for (int i = 0; i < 28; ++i) reply.remote_address[i] = info.remoteAddress[i];
    if (info.filteringFlag != before.filteringFlag) reply.mutated_flag = 1;
    for (int i = 0; i < 28; ++i) if (info.remoteAddress[i] != before.remoteAddress[i]) { reply.mutated_remote = 1; break; }
    reply.verdict = (reply.mutated_flag || reply.mutated_remote) ? EXL_VERDICT_MUTATED : EXL_VERDICT_UNCHANGED;
    post.text(" verdict="); post.decimal(reply.verdict);
    trace::finish(post);
}

static unsigned int effective_udp_pid(unsigned int linux_pid, const unsigned char *local)
{
    exl_socket_attribution::owner_result windows_owner = owning_windows_udp_pid(local);
    exl_tcp_callback_policy::process_selection selected =
        exl_tcp_callback_policy::select_process(windows_owner, linux_pid);
    if (!selected.pid || !remember_process_pid(selected.pid, selected.origin) ||
        process_pid_origin(selected.pid) != selected.origin) return 0;
    return selected.pid;
}

static void handle_udp_lifecycle(const exl_udp_lifecycle_req &req,
                                 exl_udp_lifecycle_reply &reply, unsigned int slot_index,
                                 const char *name)
{
    unsigned int process_id = effective_udp_pid(req.process_id, req.local_address);
    pid_origin domain = process_pid_origin(process_id);
    NF_UDP_CONN_INFO info;
    info.processId = process_id; info.ip_family = req.ip_family;
    for (int i = 0; i < 28; ++i) info.localAddress[i] = req.local_address[i];
    NF_UDP_CONN_INFO before = info;

    trace::line out; trace::prefix(out, name);
    out.text(" tag="); out.hex(req.tag); out.text(" id="); out.hex(req.endpoint_id);
    out.text(" processId="); out.decimal(process_id);
    out.text(process_pid_origin(process_id) == pid_windows ? "(windows)" : "(linux)");
    out.text(" local="); trace::sockaddr_text(out, info.localAddress);
    out.text(" beforeRaw="); out.byte_array((const unsigned char *)&info, sizeof(info));

    reply.tag = req.tag; reply.process_id = process_id; reply.mutated_info = 0;
    reply.ip_family = req.ip_family;
    for (int i = 0; i < 28; ++i) reply.local_address[i] = req.local_address[i];
    reply.reserved[0] = reply.reserved[1] = reply.reserved[2] = 0;
    if (!process_id) {
        out.text(" verdict=unresolved-pid"); trace::finish(out);
        reply.verdict = EXL_VERDICT_NO_HANDLER;
    } else if (!inject::g_handler) {
        out.text(" verdict=no-handler"); trace::finish(out);
        reply.verdict = EXL_VERDICT_NO_HANDLER;
    } else {
        trace::finish(out);
        if (domain != pid_linux && domain != pid_windows) {
            reply.verdict = EXL_VERDICT_NO_HANDLER; return;
        }
        udp_event_scope event(req.tag, req.endpoint_id);
        if (!event.valid()) { reply.verdict = EXL_VERDICT_NO_HANDLER; return; }
        ((cb_id_ptr)inject::slot(slot_index))(inject::g_handler, req.endpoint_id, &info);
        if (process_pid_origin(process_id) != domain) {
            reply.verdict = EXL_VERDICT_NO_HANDLER; return;
        }
        reply.verdict = EXL_VERDICT_UNCHANGED;
        const unsigned char *a = (const unsigned char *)&before;
        const unsigned char *b = (const unsigned char *)&info;
        for (unsigned int i = 0; i < sizeof(info); ++i)
            if (a[i] != b[i]) { reply.mutated_info = 1; reply.verdict = EXL_VERDICT_MUTATED; break; }
        trace::line post; trace::prefix(post, "ipc.udpLifecycle.return");
        post.text(" event="); post.text(name); post.text(" tag="); post.hex(req.tag);
        post.text(" id="); post.hex(req.endpoint_id); inject::diff_bytes(post, a, b, sizeof(info));
        trace::finish(post);
    }
    reply.ip_family = info.ip_family;
    for (int i = 0; i < 28; ++i) reply.local_address[i] = info.localAddress[i];
}

static void handle_udp_connect(const exl_udp_connect_req &req, exl_udp_connect_reply &reply)
{
    unsigned int process_id = effective_udp_pid(req.process_id, req.local_address);
    pid_origin domain = process_pid_origin(process_id);
    NF_UDP_CONN_REQUEST info;
    info.filteringFlag = req.filtering_flag; info.processId = process_id; info.ip_family = req.ip_family;
    for (int i = 0; i < 28; ++i) {
        info.localAddress[i] = req.local_address[i]; info.remoteAddress[i] = req.remote_address[i];
    }
    NF_UDP_CONN_REQUEST before = info;

    trace::line out; trace::prefix(out, "ipc.udpConnectRequest");
    out.text(" tag="); out.hex(req.tag); out.text(" id="); out.hex(req.endpoint_id);
    out.text(" processId="); out.decimal(process_id);
    out.text(process_pid_origin(process_id) == pid_windows ? "(windows)" : "(linux)");
    out.text(" filteringFlag="); out.hex(info.filteringFlag);
    out.text(" local="); trace::sockaddr_text(out, info.localAddress);
    out.text(" remote="); trace::sockaddr_text(out, info.remoteAddress);
    out.text(" beforeRaw="); out.byte_array((const unsigned char *)&info, sizeof(info));

    reply.tag = req.tag; reply.process_id = process_id;
    reply.filtering_flag = req.filtering_flag;
    for (int i = 0; i < 28; ++i) reply.remote_address[i] = req.remote_address[i];
    reply.mutated_flag = 0; reply.mutated_remote = 0;
    reply.reserved[0] = reply.reserved[1] = 0;
    if (!process_id) {
        out.text(" verdict=unresolved-pid"); trace::finish(out);
        reply.verdict = EXL_VERDICT_NO_HANDLER;
    } else if (!inject::g_handler) {
        out.text(" verdict=no-handler"); trace::finish(out);
        reply.verdict = EXL_VERDICT_NO_HANDLER;
    } else {
        trace::finish(out);
        if (domain != pid_linux && domain != pid_windows) {
            reply.verdict = EXL_VERDICT_NO_HANDLER; return;
        }
        udp_event_scope event(req.tag, req.endpoint_id);
        if (!event.valid()) { reply.verdict = EXL_VERDICT_NO_HANDLER; return; }
        ((cb_id_ptr)inject::slot(10))(inject::g_handler, req.endpoint_id, &info);
        if (process_pid_origin(process_id) != domain) {
            reply.verdict = EXL_VERDICT_NO_HANDLER; return;
        }
        if (info.filteringFlag != before.filteringFlag) reply.mutated_flag = 1;
        for (int i = 0; i < 28; ++i)
            if (info.remoteAddress[i] != before.remoteAddress[i]) { reply.mutated_remote = 1; break; }
        reply.verdict = (reply.mutated_flag || reply.mutated_remote) ? EXL_VERDICT_MUTATED : EXL_VERDICT_UNCHANGED;
        trace::line post; trace::prefix(post, "ipc.udpConnectRequest.return");
        post.text(" tag="); post.hex(req.tag); post.text(" id="); post.hex(req.endpoint_id);
        post.text(" filteringFlag="); post.hex(info.filteringFlag);
        post.text(" remote="); trace::sockaddr_text(post, info.remoteAddress);
        inject::diff_bytes(post, (const unsigned char *)&before, (const unsigned char *)&info, sizeof(info));
        trace::finish(post);
    }
    reply.filtering_flag = info.filteringFlag;
    for (int i = 0; i < 28; ++i) reply.remote_address[i] = info.remoteAddress[i];
}

static void handle_udp_datagram(exl_udp_datagram_req &req, unsigned int frame_length,
                                exl_udp_datagram_reply &reply)
{
    reply.tag = req.tag; reply.verdict = EXL_VERDICT_NO_HANDLER;
    reply.post_count = reply.remote_rule_count = reply.control_count = 0;
    reply.mutated_remote = reply.mutated_payload = reply.mutated_options = reply.reserved = 0;
    if (!exl_udp_validation::valid_datagram(req, frame_length)) return;
    unsigned int process_id = effective_udp_pid(req.process_id, req.local_address);
    pid_origin domain = process_pid_origin(process_id);
    if (!process_id) {
        trace::line out; trace::prefix(out, "ipc.udpDatagram");
        out.text(" id="); out.hex(req.endpoint_id); out.text(" verdict=unresolved-pid");
        trace::finish(out); return;
    }

    unsigned char *base = (unsigned char *)&req;
    unsigned char *option_bytes = base + sizeof(req);
    char *payload = (char *)(option_bytes + req.options_length);
    udp_event_context *transport = __atomic_load_n(&g_udp_tls_state, __ATOMIC_ACQUIRE) == 2 ?
        (udp_event_context *)TlsGetValue(g_udp_tls) : 0;
    if (!transport || !transport->scratch ||
        transport->session != __atomic_load_n(&g_udp_session, __ATOMIC_ACQUIRE) ||
        transport->socket != __atomic_load_n(&g_socket, __ATOMIC_ACQUIRE)) return;
    unsigned char *payload_before = transport->scratch;
    volatile unsigned char *saved_payload = payload_before;
    const volatile unsigned char *source_payload = (const volatile unsigned char *)payload;
    for (unsigned int i = 0; i < req.payload_length; ++i) saved_payload[i] = source_payload[i];
    unsigned char remote_before[28];
    for (int i = 0; i < 28; ++i) remote_before[i] = req.remote_address[i];

    struct udp_options_storage {
        unsigned long flags; long optionsLength; unsigned char options[4096];
    } options;
    options.flags = req.option_flags; options.optionsLength = (long)req.options_length;
    volatile unsigned char *saved_options = options.options;
    const volatile unsigned char *source_options = option_bytes;
    for (unsigned int i = 0; i < req.options_length; ++i) saved_options[i] = source_options[i];

    trace::line out; trace::prefix(out, req.direction == 2 ? "ipc.udpSend" : "ipc.udpReceive");
    out.text(" tag="); out.hex(req.tag); out.text(" id="); out.hex(req.endpoint_id);
    out.text(" processId="); out.decimal(process_id);
    out.text(" local="); trace::sockaddr_text(out, req.local_address);
    out.text(" remote="); trace::sockaddr_text(out, req.remote_address);
    out.text(" len="); out.decimal(req.payload_length); out.text(" payloadHead:");
    out.byte_array((const unsigned char *)payload, req.payload_length < 64 ? req.payload_length : 64);
    out.text(" optionFlags="); out.hex(options.flags); out.text(" optionsLength="); out.signed_decimal(options.optionsLength);
    if (!inject::g_handler) { out.text(" verdict=no-handler"); trace::finish(out); return; }
    trace::finish(out);

    if (domain != pid_linux && domain != pid_windows) return;
    udp_event_scope event(req.tag, req.endpoint_id, req.direction);
    if (!event.valid()) return;
    unsigned int slot_index = req.direction == 2 ? 13 : 12;
    ((cb_udp_data)inject::slot(slot_index))(inject::g_handler, req.endpoint_id,
        req.remote_address, payload, (int)req.payload_length, (NF_UDP_OPTIONS *)&options);
    if (process_pid_origin(process_id) != domain) return;
    reply.post_count = event.context.post_count; reply.remote_rule_count = event.context.rule_count;
    reply.control_count = event.context.control_count;
    reply.verdict = EXL_VERDICT_UNCHANGED;
    for (int i = 0; i < 28; ++i)
        if (remote_before[i] != req.remote_address[i]) { reply.mutated_remote = 1; break; }
    for (unsigned int i = 0; i < req.payload_length; ++i)
        if (payload_before[i] != (unsigned char)payload[i]) { reply.mutated_payload = 1; break; }
    if (options.flags != req.option_flags || options.optionsLength != (long)req.options_length)
        reply.mutated_options = 1;
    else for (unsigned int i = 0; i < req.options_length; ++i)
        if (options.options[i] != option_bytes[i]) { reply.mutated_options = 1; break; }
    if (reply.mutated_remote || reply.mutated_payload || reply.mutated_options)
        reply.verdict = EXL_VERDICT_MUTATED;

    trace::line post; trace::prefix(post, "ipc.udpDatagram.return");
    post.text(" tag="); post.hex(req.tag); post.text(" id="); post.hex(req.endpoint_id);
    post.text(" posts="); post.decimal(reply.post_count);
    post.text(" remoteRules="); post.decimal(reply.remote_rule_count);
    post.text(" controls="); post.decimal(reply.control_count);
    post.text(" directMutation=");
    post.text(reply.verdict == EXL_VERDICT_MUTATED ? "yes" : "none");
    trace::finish(post);
}


/*
 * Read this session's IPC token. The helper writes 64 hex characters to a file
 * only the owning user can read, so being able to read it is the proof. The
 * value is never logged and never kept beyond the handshake buffer.
 */
static bool read_session_token(unsigned char *out)
{
    wchar_t path[1024];
    DWORD size = GetEnvironmentVariableW(L"EXITLAG_NETD_TOKEN", path, sizeof(path) / sizeof(path[0]));
    if (!size || size >= sizeof(path) / sizeof(path[0])) {
        static volatile long warned;
        if (!__atomic_exchange_n(&warned, 1, __ATOMIC_SEQ_CST)) {
            trace::line warn; trace::prefix(warn, "ipc.token");
            warn.text(" state=missing detail=EXITLAG_NETD_TOKEN-not-set;"
                      "-the-backend-will-refuse-this-connection");
            trace::finish(warn);
        }
        return false;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        static volatile long warned_open;
        if (!__atomic_exchange_n(&warned_open, 1, __ATOMIC_SEQ_CST)) {
            trace::line warn; trace::prefix(warn, "ipc.token");
            warn.text(" state=unreadable path="); warn.wide_ascii(path, 256);
            trace::finish(warn);
        }
        return false;
    }
    char hex[EXL_TOKEN_BYTES * 2 + 4];
    DWORD read_bytes = 0;
    BOOL read_ok = ReadFile(file, hex, (DWORD)(EXL_TOKEN_BYTES * 2), &read_bytes, 0);
    CloseHandle(file);
    if (!read_ok || read_bytes != EXL_TOKEN_BYTES * 2) return false;
    for (unsigned int i = 0; i < EXL_TOKEN_BYTES; ++i) {
        unsigned int value = 0;
        for (unsigned int n = 0; n < 2; ++n) {
            char c = hex[i * 2 + n];
            unsigned int digit;
            if (c >= '0' && c <= '9') digit = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f') digit = (unsigned int)(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') digit = (unsigned int)(c - 'A') + 10;
            else return false;
            value = (value << 4) | digit;
        }
        out[i] = (unsigned char)value;
    }
    return true;
}

static DWORD WINAPI thread_main(void *)
{
    wchar_t endpoint[128];
    DWORD size = GetEnvironmentVariableW(L"EXITLAG_NETD", endpoint, sizeof(endpoint) / sizeof(endpoint[0]));
    if (!size || size >= sizeof(endpoint) / sizeof(endpoint[0])) return 0;

    unsigned char address[16];
    if (!exl_ipc_validation::parse_loopback_endpoint(endpoint, address)) {
        trace::line bad; trace::prefix(bad, "ipc.config");
        bad.text(" error=bad-endpoint value="); bad.wide_ascii(endpoint, 128); trace::finish(bad);
        return 0;
    }

    char winsock_data[512];
    WSAStartup(0x0202, winsock_data);

    // A previous nf_free worker can still be unwinding. Keep receive bytes and
    // UDP before-images and socket owner tables private to each worker.
    HANDLE heap = GetProcessHeap();
    char *payload = (char *)HeapAlloc(heap, 0, OWNER_TABLE_OFFSET + OWNER_TABLE_CAPACITY);
    if (!payload) return 0;

    while (g_running) {
        SOCKET s = socket(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 6 /*IPPROTO_TCP*/);
        if (s == INVALID_SOCKET) { Sleep(2000); continue; }
        if (connect(s, address, 16) == SOCKET_ERROR) {
            closesocket(s);
            Sleep(2000);           // helper absent: keep retrying, never block ExitLag
            continue;
        }
        int one = 1;
        setsockopt(s, 6 /*IPPROTO_TCP*/, 1 /*TCP_NODELAY*/, (const char *)&one, sizeof(one));
        /* Never let a silent/stale listener pin this thread forever. Wine can
           transiently leave a loopback connect established after the helper
           disappears. All real helper replies are bounded to 300 ms, so five
           seconds is deliberately generous and converts that state into the
           ordinary fail-open reconnect loop. */
        int io_timeout_ms = 5000;
        setsockopt(s, SOL_SOCKET_, SO_SNDTIMEO_, (const char *)&io_timeout_ms, sizeof(io_timeout_ms));
        setsockopt(s, SOL_SOCKET_, SO_RCVTIMEO_, (const char *)&io_timeout_ms, sizeof(io_timeout_ms));
        unsigned __int64 session = __atomic_add_fetch(&g_udp_session, 1, __ATOMIC_ACQ_REL);
        __atomic_store_n(&g_socket, s, __ATOMIC_RELEASE);
        // Bind the request stream to THIS worker. A legacy unjoined worker
        // cannot borrow a replacement worker's socket or epoch via globals.
        udp_event_context transport = {};
        transport.session = session; transport.socket = s;
        transport.scratch = (unsigned char *)payload + EXL_MAX_PAYLOAD;
        transport.resolve_buffer = payload + EXL_MAX_PAYLOAD + 65535u;
        transport.owner_table = (unsigned char *)payload + OWNER_TABLE_OFFSET;
        if (!ensure_udp_tls() || !TlsSetValue(g_udp_tls, &transport)) {
            __atomic_add_fetch(&g_udp_session, 1, __ATOMIC_ACQ_REL);
            __atomic_store_n(&g_socket, INVALID_SOCKET, __ATOMIC_RELEASE);
            closesocket(s); Sleep(2000); continue;
        }

        exl_hello hello; hello.version = EXL_PROTOCOL_VERSION;
        hello.shim_process_id = GetCurrentProcessId(); hello.capabilities = 0;
        for (unsigned int i = 0; i < EXL_TOKEN_BYTES; ++i) hello.token[i] = 0;
        // Re-read on every attempt: the helper generates a fresh token each time
        // it starts, so a cached one would be stale after a helper restart.
        bool have_token = read_session_token(hello.token);
        bool ok = have_token && send_message(s, EXL_MSG_HELLO, &hello, sizeof(hello));
        if (!have_token) {
            TlsSetValue(g_udp_tls, 0);
            __atomic_add_fetch(&g_udp_session, 1, __ATOMIC_ACQ_REL);
            __atomic_store_n(&g_socket, INVALID_SOCKET, __ATOMIC_RELEASE);
            closesocket(s); Sleep(2000); continue;
        }

        {
            trace::line out; trace::prefix(out, "ipc.connect");
            out.text(" endpoint="); out.wide_ascii(endpoint, 128);
            out.text(" sent_hello="); out.decimal(ok ? 1 : 0);
            out.text(" token=present");   // never the value
            trace::finish(out);
        }

        while (ok && g_running) {
            exl_header head;
            if (!recv_all(s, (char *)&head, (int)sizeof(head))) break;
            if (!exl_ipc_validation::valid_frame_header(head)) break;
            if (head.length && !recv_all(s, payload, (int)head.length)) break;

            if (head.type == EXL_MSG_HELLO_ACK && head.length >= sizeof(exl_hello_ack)) {
                const exl_hello_ack *ack = (const exl_hello_ack *)payload;
                trace::line out; trace::prefix(out, "ipc.hello_ack");
                out.text(" version="); out.decimal(ack->version);
                out.text(" helperPid="); out.decimal(ack->helper_pid);
                if (ack->version != EXL_PROTOCOL_VERSION) out.text(" error=version-mismatch");
                trace::finish(out);
                if (ack->version != EXL_PROTOCOL_VERSION) break;
            } else if (head.type == EXL_MSG_PING && head.length == 0) {
                if (!send_message(s, EXL_MSG_PONG, 0, 0)) break;
            } else if (head.type == EXL_MSG_TCP_CONNECT_REQ && head.length >= sizeof(exl_tcp_connect_req)) {
                exl_tcp_connect_req req = *(const exl_tcp_connect_req *)payload;
                exl_tcp_connect_reply reply;
                handle_tcp_connect(req, reply);
                if (!send_message(s, EXL_MSG_TCP_CONNECT_REPLY, &reply, sizeof(reply))) break;
            } else if (head.type == EXL_MSG_UDP_CREATED_REQ || head.type == EXL_MSG_UDP_CLOSED_REQ) {
                if (head.length != sizeof(exl_udp_lifecycle_req)) break;
                const exl_udp_lifecycle_req &req = *(const exl_udp_lifecycle_req *)payload;
                if (!exl_udp_validation::valid_lifecycle(req)) break;
                exl_udp_lifecycle_reply reply;
                bool created = head.type == EXL_MSG_UDP_CREATED_REQ;
                handle_udp_lifecycle(req, reply, created ? 9u : 11u,
                                     created ? "ipc.udpCreated" : "ipc.udpClosed");
                if (!send_message(s, created ? EXL_MSG_UDP_CREATED_REPLY : EXL_MSG_UDP_CLOSED_REPLY,
                                  &reply, sizeof(reply))) break;
            } else if (head.type == EXL_MSG_UDP_CONNECT_REQ) {
                if (head.length != sizeof(exl_udp_connect_req)) break;
                const exl_udp_connect_req &req = *(const exl_udp_connect_req *)payload;
                if (!exl_udp_validation::valid_connect(req)) break;
                exl_udp_connect_reply reply;
                handle_udp_connect(req, reply);
                if (!send_message(s, EXL_MSG_UDP_CONNECT_REPLY, &reply, sizeof(reply))) break;
            } else if (head.type == EXL_MSG_UDP_DATAGRAM_REQ) {
                if (head.length < sizeof(exl_udp_datagram_req)) break;
                exl_udp_datagram_req &req = *(exl_udp_datagram_req *)payload;
                if (!exl_udp_validation::valid_datagram(req, head.length)) break;
                exl_udp_datagram_reply reply;
                handle_udp_datagram(req, head.length, reply);
                if (!send_message(s, EXL_MSG_UDP_DATAGRAM_REPLY, &reply, sizeof(reply))) break;
            }
        }

        TlsSetValue(g_udp_tls, 0);
        __atomic_add_fetch(&g_udp_session, 1, __ATOMIC_ACQ_REL);
        __atomic_store_n(&g_socket, INVALID_SOCKET, __ATOMIC_RELEASE);
        closesocket(s);
        { trace::line out; trace::prefix(out, "ipc.disconnect"); trace::finish(out); }
        if (g_running) Sleep(2000);
    }
    HeapFree(heap, 0, payload);
    return 0;
}

static void start()
{
    wchar_t endpoint[128];
    if (!GetEnvironmentVariableW(L"EXITLAG_NETD", endpoint, sizeof(endpoint) / sizeof(endpoint[0]))) return;
    g_running = 1;
    CreateThread(0, 0, thread_main, 0, 0, 0);
}

static void stop()
{
    __atomic_store_n(&g_running, 0, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_udp_session, 1, __ATOMIC_ACQ_REL);
}

} // namespace ipc

#define NFAPI_EXPORT __declspec(dllexport)

NFAPI_EXPORT int nf_getProcessNameFromKernel(unsigned long process_id, wchar_t *buffer, unsigned long length)
{
    trace::line out; trace::prefix(out, "nf_getProcessNameFromKernel");
    out.text(" processId="); out.decimal(process_id);
    out.text(" buffer="); out.pointer(buffer);
    out.text(" length="); out.decimal(length);
    // Documented: non-zero on success with the image name written to buffer.
    // The real driver answers from the kernel; here the answer is taken from the
    // OS for the same PID. No name is invented: if the process cannot be opened
    // or queried, the call still fails.
    ipc::pid_origin origin = ipc::process_pid_origin(process_id);
    if (origin == ipc::pid_ambiguous) {
        if (buffer && length) buffer[0] = 0;
        out.text(" source=ambiguous policy=fail");
        trace::result(out, 0); trace::finish(out); return 0;
    }
    if (!trace::policy_succeeds("nf_getProcessNameFromKernel") || !buffer || !length) {
        out.text(" policy=fail"); trace::result(out, 0); trace::finish(out); return 0;
    }
    // A PID reported by the helper is a Linux PID and must be resolved there;
    // calling OpenProcess with it could name an unrelated Wine process.
    if (origin == ipc::pid_linux) {
        int ok = ipc::resolve_linux_pid(process_id, buffer, length);
        // A second domain can be recorded while the helper is answering. Never
        // return a name after the numeric PID has become ambiguous.
        if (ipc::process_pid_origin(process_id) != ipc::pid_linux) {
            buffer[0] = 0; ok = 0;
        }
        out.text(" source=helper policy=succeed");
        if (ok) { out.text(" name="); out.wide_ascii(buffer, 260); }
        else out.text(" name=unresolved");
        trace::result(out, ok); trace::finish(out); return ok;
    }
    HANDLE process = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, process_id);
    if (!process) {
        if (ipc::process_pid_origin(process_id) == ipc::pid_ambiguous) buffer[0] = 0;
        out.text(" source=windows policy=succeed openProcess=failed");
        trace::result(out, 0); trace::finish(out); return 0;
    }
    DWORD written = length;
    BOOL ok = QueryFullProcessImageNameW(process, 0, buffer, &written);
    CloseHandle(process);
    ipc::pid_origin current_origin = ipc::process_pid_origin(process_id);
    if (current_origin == ipc::pid_linux || current_origin == ipc::pid_ambiguous) {
        buffer[0] = 0;
        out.text(" source=changed-domain policy=fail");
        trace::result(out, 0); trace::finish(out); return 0;
    }
    if (!ok) {
        out.text(" policy=succeed queryImageName=failed");
        trace::result(out, 0); trace::finish(out); return 0;
    }
    out.text(" policy=succeed name="); out.wide_ascii(buffer, 260);
    out.text(" chars="); out.decimal(written);
    trace::result(out, 1); trace::finish(out); return 1;
}

NFAPI_EXPORT void nf_setIPEventHandler(NF_IPEventHandler *handler)
{
    trace::line out; trace::prefix(out, "nf_setIPEventHandler");
    trace::callbacks(out, handler, 2); trace::finish(out);
}

NFAPI_EXPORT NF_STATUS nf_setTCPFlowCtl(ENDPOINT_ID id, unsigned int handle)
{
    trace::line out; trace::prefix(out, "nf_setTCPFlowCtl");
    out.text(" id="); out.hex(id); out.text(" fcHandle="); out.decimal(handle);
    NF_STATUS st = trace::status_for(out, "nf_setTCPFlowCtl");
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT unsigned long nf_getExtensionsVersion()
{
    trace::line out; trace::prefix(out, "nf_getExtensionsVersion");
    unsigned long value = 0;
    if (trace::policy_succeeds("nf_getExtensionsVersion")) { value = trace::policy_extensions_version(); out.text(" policy=succeed"); }
    else out.text(" policy=fail");
    trace::result(out, value); trace::finish(out); return value;
}

static void flowctl_text(trace::line &out, const NF_FLOWCTL_DATA __unaligned *data)
{
    out.text(" data="); out.pointer(data);
    if (!data) return;
    out.text(" sizeof=16 inLimit="); out.decimal(data->inLimit); out.text(" outLimit="); out.decimal(data->outLimit);
    out.text(" raw:"); trace::safe_hex(out, data, sizeof(NF_FLOWCTL_DATA));
}

NFAPI_EXPORT NF_STATUS nf_addFlowCtl(NF_FLOWCTL_DATA __unaligned *data, unsigned int *handle)
{
    trace::line out; trace::prefix(out, "nf_addFlowCtl"); flowctl_text(out, data);
    out.text(" handleOut="); out.pointer(handle);
    if (handle) { out.text(" handleOutBefore="); out.decimal(*handle); }
    NF_STATUS st = trace::status_for(out, "nf_addFlowCtl");
    // Documented success contract: *pFcHandle receives a new non-zero flow-control
    // handle. Handles are allocated sequentially; no shaping is implemented.
    if (st == NF_STATUS_SUCCESS && handle) {
        static volatile long next_handle;
        unsigned int value = (unsigned int)__atomic_add_fetch(&next_handle, 1, __ATOMIC_SEQ_CST);
        *handle = value;
        out.text(" handleOutAfter="); out.decimal(value);
    }
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT NF_STATUS nf_deleteFlowCtl(unsigned int handle)
{
    trace::line out; trace::prefix(out, "nf_deleteFlowCtl"); out.text(" fcHandle="); out.decimal(handle);
    NF_STATUS st = trace::status_for(out, "nf_deleteFlowCtl");
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT NF_STATUS nf_getFlowCtlStat(unsigned int handle, NF_FLOWCTL_STAT __unaligned *stat)
{
    trace::line out; trace::prefix(out, "nf_getFlowCtlStat"); out.text(" fcHandle="); out.decimal(handle);
    out.text(" statOut="); out.pointer(stat);
    NF_STATUS st = trace::status_for(out, "nf_getFlowCtlStat");
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT NF_STATUS nf_setFlowCtlQueueParams(unsigned int handle, NF_FCQUEUE_PARAMS __unaligned *params)
{
    trace::line out; trace::prefix(out, "nf_setFlowCtlQueueParams"); out.text(" fcHandle="); out.decimal(handle);
    // ExitLag extension; layout not in the public SDK. Dump readable bytes only.
    out.text(" params="); out.pointer(params); out.text(" layout=opaque "); trace::safe_hex(out, params, 128);
    NF_STATUS st = trace::status_for(out, "nf_setFlowCtlQueueParams");
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT NF_STATUS nf_modifyFlowCtl(unsigned int handle, NF_FLOWCTL_DATA __unaligned *data)
{
    trace::line out; trace::prefix(out, "nf_modifyFlowCtl"); out.text(" fcHandle="); out.decimal(handle);
    flowctl_text(out, data);
    NF_STATUS st = trace::status_for(out, "nf_modifyFlowCtl");
    trace::result(out, st); trace::finish(out); return st;
}

NFAPI_EXPORT NF_STATUS nf_setUDPFlowCtl(ENDPOINT_ID id, unsigned int handle)
{
    trace::line out; trace::prefix(out, "nf_setUDPFlowCtl"); out.text(" id="); out.hex(id);
    out.text(" fcHandle="); out.decimal(handle);
    NF_STATUS st = trace::status_for(out, "nf_setUDPFlowCtl");
    if (!ipc::report_udp_state(EXL_UDP_API_SET_FLOWCTL, id, (int)st, handle, 0, 0)) st = NF_STATUS_FAIL;
    trace::result(out, st); trace::finish(out);
    return st;
}

// One log line per NF_RULE_EX: decoded fields per nfdriver_data.h 1.7.7.1 (packed,
// 643 bytes) followed by the raw structure bytes.
static void rule_line(long seq, int index, int count, const NF_RULE_EX __unaligned *r)
{
    if (!trace::research_trace_enabled()) return;
    trace::line out;
    out.text("seq="); out.decimal((unsigned long)seq); out.text(" call=nf_setRulesEx.rule");
    out.text(" index="); out.decimal(index); out.text(" of="); out.decimal(count); out.text(" at="); out.pointer(r);
    out.text(" protocol="); out.signed_decimal(r->protocol);
    out.text(r->protocol == 6 ? "(TCP)" : r->protocol == 17 ? "(UDP)" : r->protocol == 0 ? "(any)" : "(?)");
    out.text(" processId="); out.decimal(r->processId);
    out.text(" direction="); out.decimal(r->direction);
    out.text(r->direction == 1 ? "(IN)" : r->direction == 2 ? "(OUT)" : r->direction == 3 ? "(BOTH)" : r->direction == 0 ? "(any)" : "(?)");
    out.text(" localPort="); out.decimal(r->localPort); out.text(" remotePort="); out.decimal(r->remotePort);
    out.text(" family="); out.decimal(r->ip_family);
    out.text(r->ip_family == 2 ? "(AF_INET)" : r->ip_family == 23 ? "(AF_INET6)" : r->ip_family == 0 ? "(any)" : "(?)");
    out.text(" localIp="); trace::ip_text(out, r->ip_family, r->localIpAddress);
    out.text(" localMask="); trace::ip_text(out, r->ip_family, r->localIpAddressMask);
    out.text(" remoteIp="); trace::ip_text(out, r->ip_family, r->remoteIpAddress);
    out.text(" remoteMask="); trace::ip_text(out, r->ip_family, r->remoteIpAddressMask);
    out.text(" filteringFlag="); out.hex(r->filteringFlag); out.character('(');
    {
        unsigned long f = r->filteringFlag; bool first = true;
        struct { unsigned long bit; const char *name; } names[] = {
            {1, "BLOCK"}, {2, "FILTER"}, {4, "SUSPENDED"}, {8, "OFFLINE"}, {16, "INDICATE_CONNECT_REQUESTS"},
            {32, "DISABLE_REDIRECT_PROTECTION"}, {64, "PEND_CONNECT_REQUEST"}, {128, "FILTER_AS_IP_PACKETS"},
            {256, "READONLY"}, {512, "CONTROL_FLOW"}, {1024, "REDIRECT"}, {2048, "BYPASS_IP_PACKETS"} };
        if (!f) out.text("ALLOW");
        for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
            if (f & names[i].bit) { if (!first) out.character('|'); out.text(names[i].name); first = false; f &= ~names[i].bit; }
        if (f) { if (!first) out.character('|'); out.text("unknown:"); out.hex(f); }
    }
    out.character(')');
    out.text(" processName="); out.wide_ascii(r->processName, 260);
    out.text(" localPortRange="); out.decimal(r->localPortRange.valueLow); out.character('-'); out.decimal(r->localPortRange.valueHigh);
    out.text(" remotePortRange="); out.decimal(r->remotePortRange.valueLow); out.character('-'); out.decimal(r->remotePortRange.valueHigh);
    out.text(" redirectTo="); trace::sockaddr_text(out, r->redirectTo);
    out.text(" redirectToRaw="); out.byte_array(r->redirectTo, 28);
    out.text(" localProxyProcessId="); out.decimal(r->localProxyProcessId);
    out.text(" raw:"); trace::safe_hex(out, r, sizeof(NF_RULE_EX));
    trace::finish(out);
}

NFAPI_EXPORT NF_STATUS nf_setRulesEx(NF_RULE_EX __unaligned *rules, int count)
{
    trace::line out; trace::prefix(out, "nf_setRulesEx"); out.text(" rules="); out.pointer(rules);
    out.text(" count="); out.signed_decimal(count); out.text(" sizeofRule="); out.decimal(sizeof(NF_RULE_EX));
    out.text(" totalBytes="); out.decimal(count > 0 ? (unsigned __int64)count * sizeof(NF_RULE_EX) : 0);
    long seq = trace::sequence;
    NF_STATUS st = trace::status_for(out, "nf_setRulesEx");
    trace::result(out, st); trace::finish(out);
    if (rules && count > 0) {
        unsigned __int64 readable = trace::readable_bytes(rules, (unsigned __int64)count * sizeof(NF_RULE_EX));
        int captured = (int)(readable / sizeof(NF_RULE_EX));
        for (int i = 0; i < captured && i < 256; ++i) rule_line(seq, i, count, &rules[i]);
    }
    return st;
}

NFAPI_EXPORT NF_STATUS nf_init(const char *driver_name, NF_EventHandler *handler)
{
    compat::install_main_iat_guards();
    compat::log_main_iat_guards();
    {
        // Say which success policy this run uses, so a capture is never
        // ambiguous about whether it exercised the production surface.
        trace::line mode; trace::prefix(mode, "policy.mode");
        mode.text(trace::policy_is_production() ? " source=built-in-table"
                                                : " source=EXITLAG_NFAPI_SUCCEED-override");
        mode.text(" supported="); mode.decimal(trace::supported_export_count());
        trace::finish(mode);
    }
    trace::line out; trace::prefix(out, "nf_init");
    if (trace::research_trace_enabled()) {
        out.text(" driverNamePtr="); out.pointer(driver_name);
        out.text(" driverName="); out.quoted_ascii(driver_name, 256);
        trace::callbacks(out, handler, 16);
    } else {
        out.text(" driverName="); out.quoted_ascii(driver_name, 256);
        out.text(" handler="); out.text(handler ? "present" : "absent");
    }
    NF_STATUS st = trace::status_for(out, "nf_init");
    trace::result(out, st); trace::finish(out);
    if (st == NF_STATUS_SUCCESS) { inject::g_handler = handler; inject::start(handler); ipc::start(); }
    return st;
}

NFAPI_EXPORT void nf_free()
{
    trace::line out; trace::prefix(out, "nf_free"); trace::finish(out);
    inject::stop();
    ipc::stop();
}

static NF_STATUS log_udp_post(const char *name, unsigned int api, ENDPOINT_ID id, const unsigned char *remote,
                              const char *buffer, int length, NF_UDP_OPTIONS __unaligned *options)
{
    trace::line out; trace::prefix(out, name); out.text(" id="); out.hex(id);
    unsigned char wire[28]; unsigned int options_length;
    if (!ipc::current_udp_event(id) ||
        !ipc::prepare_udp_post(remote, buffer, length, options, wire, options_length)) {
        out.text(" reason=invalid-arguments-or-no-synchronous-event");
        trace::result(out, NF_STATUS_FAIL); trace::finish(out); return NF_STATUS_FAIL;
    }
    out.text(" remote="); trace::sockaddr_text(out, wire);
    out.text(" length="); out.signed_decimal(length);
    if (buffer && length > 0) { out.text(" payloadHead:"); trace::safe_hex(out, buffer, length < 64 ? (unsigned)length : 64); }
    out.text(" optionsLength="); out.decimal(options_length);
    NF_STATUS st = trace::status_for(out, name);
    if (!ipc::report_udp_post(api, id, (int)st, wire, buffer, length, options)) st = NF_STATUS_FAIL;
    trace::result(out, st); trace::finish(out);
    return st;
}

NFAPI_EXPORT NF_STATUS nf_udpPostSend(ENDPOINT_ID id, const unsigned char *remote, const char *buffer,
                                      int length, NF_UDP_OPTIONS __unaligned *options)
{
    return log_udp_post("nf_udpPostSend", EXL_UDP_API_POST_SEND, id, remote, buffer, length, options);
}

NFAPI_EXPORT NF_STATUS nf_udpPostReceive(ENDPOINT_ID id, const unsigned char *remote, const char *buffer,
                                         int length, NF_UDP_OPTIONS __unaligned *options)
{
    return log_udp_post("nf_udpPostReceive", EXL_UDP_API_POST_RECEIVE, id, remote, buffer, length, options);
}

NFAPI_EXPORT NF_STATUS nf_udpDisableFiltering(ENDPOINT_ID id)
{
    trace::line out; trace::prefix(out, "nf_udpDisableFiltering"); out.text(" id="); out.hex(id);
    NF_STATUS st = trace::status_for(out, "nf_udpDisableFiltering");
    if (!ipc::report_udp_state(EXL_UDP_API_DISABLE_FILTERING, id, (int)st, 0, 0, 0)) st = NF_STATUS_FAIL;
    trace::result(out, st); trace::finish(out);
    return st;
}

NFAPI_EXPORT NF_STATUS nf_udpEnableFiltering(ENDPOINT_ID id)
{
    trace::line out; trace::prefix(out, "nf_udpEnableFiltering"); out.text(" id="); out.hex(id);
    NF_STATUS st = trace::status_for(out, "nf_udpEnableFiltering");
    if (!ipc::report_udp_state(EXL_UDP_API_ENABLE_FILTERING, id, (int)st, 0, 0, 0)) st = NF_STATUS_FAIL;
    trace::result(out, st); trace::finish(out);
    return st;
}

NFAPI_EXPORT NF_STATUS nf_udpAddRemoteAddrRule(ENDPOINT_ID id, NF_UDP_REMOTE_ADDR_RULE __unaligned *rule)
{
    trace::line out; trace::prefix(out, "nf_udpAddRemoteAddrRule"); out.text(" id="); out.hex(id);
    // ExitLag extension; layout not in the public SDK. Dump readable bytes only.
    out.text(" rule="); out.pointer(rule); out.text(" layout=opaque "); trace::safe_hex(out, rule, 128);
    NF_STATUS st = trace::status_for(out, "nf_udpAddRemoteAddrRule");
    unsigned int readable = rule ? (unsigned int)trace::readable_bytes(rule, 20) : 0;
    if (readable > 20) readable = 20;
    if (!ipc::report_udp_state(EXL_UDP_API_ADD_REMOTE_RULE, id, (int)st, 0, rule, readable)) st = NF_STATUS_FAIL;
    trace::result(out, st); trace::finish(out);
    return st;
}

} // namespace nfapi
