// The Windows client imports these SDK driver-management entry points.
// Linux routing belongs to the native backend; Windows driver installation is
// unsupported. Preserve the ABI and report failure without pretending success.
// SPDX-License-Identifier: GPL-3.0-only
#define WINAPI __stdcall
extern "C" __declspec(dllimport) void WINAPI SetLastError(unsigned long);
extern "C" __declspec(dllimport) void WINAPI OutputDebugStringA(const char *);

typedef enum _NF_STATUS {
    NF_STATUS_SUCCESS = 0,
    NF_STATUS_FAIL = -1,
} NF_STATUS;

namespace nfapi {
__declspec(dllexport) NF_STATUS nf_registerDriver(const char *)
{
    OutputDebugStringA("ExitLag Bridge: Windows driver registration is unsupported.\n");
    SetLastError(50); // ERROR_NOT_SUPPORTED
    return NF_STATUS_FAIL;
}

__declspec(dllexport) NF_STATUS nf_unRegisterDriver(const char *)
{
    OutputDebugStringA("ExitLag Bridge: Windows driver removal is unsupported.\n");
    SetLastError(50);
    return NF_STATUS_FAIL;
}
}
