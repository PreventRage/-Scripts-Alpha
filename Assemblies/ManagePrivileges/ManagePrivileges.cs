using System.Runtime.InteropServices;
public class ManagePrivileges
{
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern /*BOOL*/ bool CloseHandle(
        /*[in] HANDLE*/ IntPtr Handle
    );

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern /*BOOL*/ bool OpenProcessToken(
        /*[in] HANDLE*/ IntPtr ProcessHandle,
        /*[in] DWORD*/ int DesiredAccess,
        /*[out] PHANDLE*/ ref IntPtr TokenHandle
    );
    
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern /*BOOL*/ bool LookupPrivilegeValue(
        /*[in, optional] LPCWSTR*/ string? SystemName,
        /*[in] LPCWSTR*/ string Name,
        /*[out] PLUID*/ ref long Luid
    );

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TOKEN_PRIVILEGES__RoomForOne {
        /*DWORD*/ public int PrivilegeCount;
        /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
        /*LUID*/ public long Luid;
        /*DWORD*/ public int Attributes;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(
        /*HANDLE*/ IntPtr TokenHandle,
        /*BOOL*/ bool DisableAllPrivileges,
        /*PTOKEN_PRIVILEGES*/ ref TOKEN_PRIVILEGES__RoomForOne NewState,
        /*DWORD*/ int BufferLength,
        /*PTOKEN_PRIVILEGES*/ IntPtr PreviousState,
        /*PDWORD*/ IntPtr ReturnLength
    );

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct PRIVILEGE_SET__RoomForOne {
        /*DWORD*/ public int PrivilegeCount;
        /*DWORD*/ public int Control;
        /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
        /*LUID*/ public long Luid;
        /*DWORD*/ public int Attributes;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern /*BOOL*/ bool PrivilegeCheck(
        /*HANDLE*/ IntPtr TokenHandle,
        /*PPRIVILEGE_SET*/ ref PRIVILEGE_SET__RoomForOne RequiredPrivileges,
        /*LPBOOL*/ ref bool pfResult
      );    

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    internal const int PRIVILEGE_SET_ALL_NECESSARY = 0x00000001;

    public static bool CheckPrivilege(
        long processHandle,
        string privilege,
        out bool isEnabled)
    {
        bool succeeded = false;
        isEnabled = false; 

        IntPtr hProcess = new IntPtr(processHandle);
        IntPtr hToken = IntPtr.Zero;

        PRIVILEGE_SET__RoomForOne ps;
        ps.PrivilegeCount = 1;
        ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
        ps.Luid = 0;
        ps.Attributes = 0;

        // May now goto LReturn on failure

        if (!OpenProcessToken(
            hProcess,           // ProcessHandle
            TOKEN_QUERY,        // DesiredAccess
            ref hToken          // TokenHandle
        )) {
            goto LReturn;
        }
        if (!LookupPrivilegeValue(
            null,               // SystemName (null means local)
            privilege,          // Name
            ref ps.Luid         // Luid
        )) {
            goto LReturn;
        }
        if (!PrivilegeCheck(
            hToken,             // TokenHandle
            ref ps,             // RequiredPrivileges
            ref isEnabled       // pfResult
        )) {
            goto LReturn;
        }
        succeeded = true;
LReturn:
        if (hToken != IntPtr.Zero) {
            CloseHandle(hToken);
        }
        return succeeded;
    }

    public static bool EnablePrivilege(
        long processHandle,
        string privilege
    ) {
        return EnableOrDisablePrivilege(processHandle, privilege, true);
    }

    public static bool DisablePrivilege(
        long processHandle,
        string privilege
    ) {
        return EnableOrDisablePrivilege(processHandle, privilege, false);
    }

    public static bool EnableOrDisablePrivilege(
        long processHandle, // experiment with using IntPtr instead
        string privilege,
        bool enable
    ) {
        bool succeeded = false;

        IntPtr hProcess = new IntPtr(processHandle);
        IntPtr hToken = IntPtr.Zero;

        TOKEN_PRIVILEGES__RoomForOne tp;
        tp.PrivilegeCount = 1;
        tp.Luid = 0;
        tp.Attributes = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED;

        // May now goto LReturn on failure

        if (!OpenProcessToken(
            hProcess,           // ProcessHandle
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, // DesiredAccess
            ref hToken          // TokenHandle
        )) {
            goto LReturn;
        }
        if (!LookupPrivilegeValue(
            null,               // SystemName (null means local)
            privilege,          // Name
            ref tp.Luid         // Luid
        )) {
            goto LReturn;
        }
        if (!AdjustTokenPrivileges(
            hToken,             // TokenHandle
            false,              // DisableAllPrivileges
            ref tp,             // NewState
            0,                  // BufferLength
            IntPtr.Zero,        // PreviousState
            IntPtr.Zero         // ReturnLength
        )) {
            goto LReturn;
        }
        succeeded = true;
LReturn:
        if (hToken != IntPtr.Zero) {
            CloseHandle(hToken);
        }
        return succeeded;
    }
}
