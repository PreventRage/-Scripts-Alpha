using System;
using System.Runtime.InteropServices;

public static class NyxNUtil {

    public static bool CloseHandle(Int64 Handle) {
        IntPtr h = new IntPtr(Handle);
        return Native.CloseHandle(h);
    }

    public static Int64 GetCurrentProcess() {
        return (Int64)Native.GetCurrentProcess();
            // Apparently this always returns a "pseudo-handle" equal to -1
            // that means "the current process" when passed to functions that
            // expect a Process handle
    }

    public static Int32 GetProcessId(Int64 ProcessHandle) {
        IntPtr h = new IntPtr(ProcessHandle);
        return (Int32)Native.GetProcessId(h);
    }

    // OpenProcess seems like a good thing to add

    [Flags]
    public enum TokenAccess : Int32 {
        TokenAdjustDefault = Native.TOKEN_ADJUST_DEFAULT, // Required to change the default owner, primary group, or DACL of an access token.
        TokenAdjustGroups = Native.TOKEN_ADJUST_GROUPS, // Required to adjust the attributes of the groups in an access token.
        TokenAdjustPrivileges = Native.TOKEN_ADJUST_PRIVILEGES, // Required to enable or disable the privileges in an access token.
        TokenAdjustSessionId = Native.TOKEN_ADJUST_SESSIONID, // Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required.
        TokenAssignPrimary = Native.TOKEN_ASSIGN_PRIMARY, // Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is also required to accomplish this task.
        TokenDuplicate = Native.TOKEN_DUPLICATE, // Required to duplicate an access token.
        TokenExecute = Native.TOKEN_EXECUTE, // Same as STANDARD_RIGHTS_EXECUTE.
        TokenImpersonate = Native.TOKEN_IMPERSONATE, // Required to attach an impersonation access token to a process.
        TokenQuery = Native.TOKEN_QUERY, // Required to query an access token.
        TokenQuerySource = Native.TOKEN_QUERY_SOURCE, // Required to query the source of an access token.
        TokenRead = Native.TOKEN_READ, // Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
        TokenWrite = Native.TOKEN_WRITE, // Combines STANDARD_RIGHTS_WRITE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, and TOKEN_ADJUST_DEFAULT.
        TokenAllAccess = Native.TOKEN_ALL_ACCESS, // Combines all possible access rights for a token.
    }

    public static bool OpenProcessToken(
        Int64 ProcessHandle,
        TokenAccess DesiredAccess,
        ref Int64 TokenHandle
    ) {
        IntPtr hProcess = new IntPtr(ProcessHandle);
        IntPtr hToken = IntPtr.Zero;
        if (Native.OpenProcessToken(hProcess, (Int32)DesiredAccess, ref hToken)) {
            TokenHandle = (Int64)hToken;
            return true;
        } else {
            return false;
        }
    }

    public static bool LookupPrivilegeValue(
        string SystemName, // null means local system
        string PrivilegeName, // Se* name of privilege
        ref Int64 PrivilegeLuid // "Locally Unique Identifier" of this Privilege
    ) {
        return Native.LookupPrivilegeValue(SystemName, PrivilegeName, ref PrivilegeLuid);
    }

    public static bool PrivilegeCheck(
        Int64 TokenHandle,
        Int64 PrivilegeLuid, // "Locally Unique Identifier" of this Privilege
        ref bool isEnabled
    ) {
        IntPtr hToken = new IntPtr(TokenHandle);

        Native.PRIVILEGE_SET_RoomForOne ps;
        ps.PrivilegeCount = 1;
        ps.Control = Native.PRIVILEGE_SET_ALL_NECESSARY;
        ps.Luid = PrivilegeLuid;
        ps.Attributes = 0;

        return Native.PrivilegeCheck(hToken, ref ps, ref isEnabled);
    }

    public static bool AdjustTokenPrivilege(
        Int64 TokenHandle,
        Int64 PrivilegeLuid,
        bool isEnabled
    ) {
        IntPtr hToken = new IntPtr(TokenHandle);

        var tpNew = new Native.TOKEN_PRIVILEGES_RoomForOne();
        tpNew.PrivilegeCount = 1;
        tpNew.Luid = PrivilegeLuid;
        tpNew.Attributes = isEnabled ? Native.SE_PRIVILEGE_ENABLED : Native.SE_PRIVILEGE_DISABLED;

        var tpOld = new Native.TOKEN_PRIVILEGES_RoomForOne();
        Int32 tpOld_Room = Marshal.SizeOf(tpOld);
        Int32 tpOld_Size;

        bool ok;
        ok = Native.AdjustTokenPrivileges(
            hToken,         // TokenHandle
            false,          // DisableAllPrivileges
            ref tpNew,      // NewState
            tpOld_Room,     // PreviousState_RoomInBytes
            ref tpOld,      // PreviousState
            out tpOld_Size  // PreviousState_SizeInBytes
        );
        return ok;
    }

    public static class Native {

        // CloseHandle

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /*BOOL*/ bool CloseHandle(
            /*[in] HANDLE*/ IntPtr Handle
        );


        // GetProcessId

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern /*DWORD*/ Int32 GetProcessId(
            /*[in] HANDLE*/ IntPtr ProcessHandle
        );


        // GetCurrentProcess

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern /*HANDLE*/ IntPtr GetCurrentProcess();


        // OpenProcessToken

        public const Int32 READ_CONTROL = 0x00020000;
        public const Int32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const Int32 STANDARD_RIGHTS_READ = READ_CONTROL;
        public const Int32 STANDARD_RIGHTS_WRITE = READ_CONTROL;
        public const Int32 STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
        public const Int32 STANDARD_RIGHTS_ALL = 0x001F0000;

        public const Int32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const Int32 TOKEN_DUPLICATE = 0x0002;
        public const Int32 TOKEN_IMPERSONATE = 0x0004;
        public const Int32 TOKEN_QUERY = 0x0008;
        public const Int32 TOKEN_QUERY_SOURCE = 0x0010;
        public const Int32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const Int32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const Int32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const Int32 TOKEN_ADJUST_SESSIONID = 0x0100;

        public const Int32 TOKEN_ALL_ACCESS = (
            STANDARD_RIGHTS_REQUIRED |
            TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE |
            TOKEN_IMPERSONATE |
            TOKEN_QUERY |
            TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS |
            TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID
        );

        public const Int32 TOKEN_READ = (
            STANDARD_RIGHTS_READ |
            TOKEN_QUERY
        );

        public const Int32 TOKEN_WRITE = (
            STANDARD_RIGHTS_WRITE |
            TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS |
            TOKEN_ADJUST_DEFAULT
        );

        public const Int32 TOKEN_EXECUTE = (
            STANDARD_RIGHTS_EXECUTE
        );

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /*BOOL*/ bool OpenProcessToken(
            /*[in] HANDLE*/ IntPtr ProcessHandle,
            /*[in] DWORD*/ Int32 DesiredAccess,
            /*[out] PHANDLE*/ ref IntPtr TokenHandle
        );


        // LookupPrivilegeValue

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ bool LookupPrivilegeValue(
            /*[in, optional] LPCWSTR*/ string SystemName,
            /*[in] LPCWSTR*/ string PrivilegeName,
            /*[out] PLUID*/ ref Int64 PrivilegeLuid
        );


        // PrivilegeCheck

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ bool PrivilegeCheck(
            /*HANDLE*/ IntPtr TokenHandle,
            /*PPRIVILEGE_SET*/ ref PRIVILEGE_SET_RoomForOne RequiredPrivileges,
            /*LPBOOL*/ ref bool pfResult
          );

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PRIVILEGE_SET_RoomForOne {
            public /*DWORD*/ Int32 PrivilegeCount;
            public /*DWORD*/ Int32 Control;
            /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
            public /*LUID*/ Int64 Luid;
            public /*DWORD*/ Int32 Attributes;
        }

        internal const Int32 PRIVILEGE_SET_ALL_NECESSARY = 0x00000001;


        // AdjustTokenPrivileges

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ bool AdjustTokenPrivileges(
            /*HANDLE*/ IntPtr TokenHandle,
            /*BOOL*/ [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            /*PTOKEN_PRIVILEGES*/ ref TOKEN_PRIVILEGES_RoomForOne NewState,
            /*DWORD*/ Int32 PreviousState_RoomInBytes,
            /*PTOKEN_PRIVILEGES*/ ref TOKEN_PRIVILEGES_RoomForOne PreviousState,
            /*PDWORD*/ out Int32 PreviousState_SizeInBytes
        );

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TOKEN_PRIVILEGES_RoomForOne {
            public /*DWORD*/ Int32 PrivilegeCount;
            /*LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
            public /*LUID*/ Int64 Luid;
            public /*DWORD*/ Int32 Attributes;
        }

        internal const Int32 SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const Int32 SE_PRIVILEGE_DISABLED = 0x00000000;
    }
}