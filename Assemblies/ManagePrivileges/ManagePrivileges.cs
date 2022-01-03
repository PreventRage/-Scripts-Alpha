using System;
using System.Runtime.InteropServices;
public class ManagePrivileges {
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern /*HANDLE*/ IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern /*BOOL*/ bool CloseHandle(
        /*[in] HANDLE*/ IntPtr Handle
    );

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern /*BOOL*/ bool OpenProcessToken(
        /*[in] HANDLE*/ IntPtr ProcessHandle,
        /*[in] DWORD*/ Int32 DesiredAccess,
        /*[out] PHANDLE*/ ref IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern /*BOOL*/ bool LookupPrivilegeValue(
        /*[in, optional] LPCWSTR*/ string? SystemName,
        /*[in] LPCWSTR*/ string Name,
        /*[out] PLUID*/ ref Int64 Luid
    );

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TOKEN_PRIVILEGES__RoomForOne {
        public /*DWORD*/ Int32 PrivilegeCount;
        /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
        public /*LUID*/ Int64 Luid;
        public /*DWORD*/ Int32 Attributes;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern /*BOOL*/bool AdjustTokenPrivileges(
        /*HANDLE*/ IntPtr TokenHandle,
        /*BOOL*/ [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        /*PTOKEN_PRIVILEGES*/ ref TOKEN_PRIVILEGES__RoomForOne NewState,
        /*DWORD*/ Int32 PreviousState_RoomInBytes,
        /*PTOKEN_PRIVILEGES*/ ref TOKEN_PRIVILEGES__RoomForOne PreviousState,
        /*PDWORD*/ out Int32 PreviousState_SizeInBytes
    );

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct PRIVILEGE_SET__RoomForOne {
        public /*DWORD*/ Int32 PrivilegeCount;
        public /*DWORD*/ Int32 Control;
        /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
        public /*LUID*/ Int64 Luid;
        public /*DWORD*/ Int32 Attributes;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern /*BOOL*/ bool PrivilegeCheck(
        /*HANDLE*/ IntPtr TokenHandle,
        /*PPRIVILEGE_SET*/ ref PRIVILEGE_SET__RoomForOne RequiredPrivileges,
        /*LPBOOL*/ ref bool pfResult
      );

    internal const Int32 SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const Int32 SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const Int32 TOKEN_QUERY = 0x00000008;
    internal const Int32 TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    internal const Int32 PRIVILEGE_SET_ALL_NECESSARY = 0x00000001;

    public static Int64 HandleOfCurrentProcess {
        get {
            return (Int64)GetCurrentProcess();
                // Apparently this is always -1 but you're supposed to be call to be safe
                // in case the system changes its mind some day?
        }
    }

    public static bool CheckPrivilege(
        Int64 processHandle,
        string privilege,
        out bool isEnabled) {
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

        TOKEN_PRIVILEGES__RoomForOne tpNew;
        tpNew.PrivilegeCount = 1;
        tpNew.Luid = 0; // we'll look up the proper value later
        tpNew.Attributes = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED;

        var tpOld = new TOKEN_PRIVILEGES__RoomForOne();
        Int32 tpOld_Room = Marshal.SizeOf(tpOld);
        Int32 tpOld_Size;

        // May now goto LReturn on failure

        if (!OpenProcessToken(
            hProcess,                   // ProcessHandle
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, // DesiredAccess
            ref hToken                  // TokenHandle
        )) {
            goto LReturn;
        }
        if (!LookupPrivilegeValue(
            null,                       // SystemName (null means local)
            privilege,                  // Name
            ref tpNew.Luid              // Luid
        )) {
            goto LReturn;
        }
        if (!AdjustTokenPrivileges(
            hToken,                     // TokenHandle
            false,                      // DisableAllPrivileges
            ref tpNew,                  // NewState
            tpOld_Room,                 // PreviousState_RoomInBytes
            ref tpOld,                  // PreviousState
            out tpOld_Size              // PreviousState_SizeInBytes
        )) {
            goto LReturn;
        }
        if (tpOld_Size != tpOld_Room) {
            // It's not clear this is an error, but I'm suspicious
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
