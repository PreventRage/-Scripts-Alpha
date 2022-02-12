using System.Runtime.InteropServices;

public static class NyxNUtil {

    private static void ThrowLastError() {
        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
    }

    public static void CloseHandle(Int64 Handle) {
        if (Handle != 0) {
            IntPtr h = new IntPtr(Handle);
            if (!Native.CloseHandle(h)) {
                ThrowLastError();
            }
        }
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

    public static Int64 OpenProcessToken(Int64 ProcessHandle, TokenAccess DesiredAccess) {
        IntPtr hProcess = new IntPtr(ProcessHandle);
        IntPtr hToken;
        if (!Native.OpenProcessToken(hProcess, (Int32)DesiredAccess, out hToken)) {
            ThrowLastError();
        }
        return (Int64)hToken;
    }

    public static Int64 GetPrivilegeId(
        string PrivilegeName, // Se* name of privilege
        string? SystemName = null // null means local system
    ) {
        Int64 id;
        if (!Native.LookupPrivilegeValue(SystemName, PrivilegeName, out id)) {
            ThrowLastError();
        }
        return id;
    }

    public static Boolean HasPrivilege(
        Int64? ProcessHandle = null,
        Int64? TokenHandle = null,
        string? PrivilegeName = null,
        Int64? PrivilegeId = null
    ) {
        var args = PrivilegeArgs.Create(ProcessHandle, TokenHandle, PrivilegeName, PrivilegeId);
        try {
            return TokenHasPrivilege(args.TokenHandle, args.PrivilegeId);
        }
        finally {
            args.Dispose();
        }
    }

    public static Boolean TokenHasPrivilege(Int64 TokenHandle, Int64 PrivilegeId) {
        Native.PRIVILEGE_SET_RoomForOne ps;
        ps.PrivilegeCount = 1;
        ps.Control = Native.PRIVILEGE_SET_ALL_NECESSARY;
        ps.Luid = PrivilegeId;
        ps.Attributes = 0;

        IntPtr hToken = new IntPtr(TokenHandle);
        Boolean isEnabled;
        if (!Native.PrivilegeCheck(hToken, ref ps, out isEnabled)) {
            ThrowLastError();
        }
        return isEnabled;
    }

    public static void EnablePrivilege(
        Int64? ProcessHandle = null,
        Int64? TokenHandle = null,
        string? PrivilegeName = null,
        Int64? PrivilegeId = null,
        Boolean Enable = true
    ) {
        var args = PrivilegeArgs.Create(ProcessHandle, TokenHandle, PrivilegeName, PrivilegeId);
        try {
            EnableTokenPrivilege(args.TokenHandle, args.PrivilegeId, Enable);
        } finally {
            args.Dispose();
        }
    }

    public static void EnableTokenPrivilege(
        Int64 TokenHandle,
        Int64 PrivilegeId,
        Boolean Enable = true
    ) {
        IntPtr hToken = new IntPtr(TokenHandle);

        var tpNew = new Native.TOKEN_PRIVILEGES_RoomForOne();
        tpNew.PrivilegeCount = 1;
        tpNew.Luid = PrivilegeId;
        tpNew.Attributes = Enable ? Native.SE_PRIVILEGE_ENABLED : Native.SE_PRIVILEGE_DISABLED;

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

        // Somewhat weirdly AdjustTokenPrivileges sets error ERROR_NOT_ALL_ASSIGNED
        // while nevertheless returning success/true.
        if (!ok || Marshal.GetLastWin32Error() == Native.ERROR_NOT_ALL_ASSIGNED) {
            ThrowLastError();
        }
    }

    private class PrivilegeArgs : IDisposable {

        public Int64 TokenHandle;
        public Int64 PrivilegeId;

        private Boolean CloseTokenHandle;

        ~PrivilegeArgs() {
            Dispose(disposing: false);
        }

        public void Dispose() {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing) {
            if (this.CloseTokenHandle) {
                CloseHandle(this.TokenHandle);
                this.CloseTokenHandle = false;
            }
        }

        public static PrivilegeArgs Create(
            Int64? ProcessHandle,
            Int64? TokenHandle,
            string? PrivilegeName,
            Int64? PrivilegeId
        ) {
            var args = new PrivilegeArgs();
            try {
                // Get hToken + hTokenClose from TokenHandle or ProcessHandle or current process
                if (TokenHandle.HasValue) {
                    // use provided token
                    if (ProcessHandle.HasValue) {
                        throw new ArgumentException(
                            String.Format("Provide at most one of ProcessHandle or TokenHandle")
                        );
                    }
                    args.TokenHandle = TokenHandle.Value;
                } else {
                    // get token from process
                    Int64 hProcess;
                    if (ProcessHandle.HasValue) {
                        // ... from provided process
                        hProcess = ProcessHandle.Value;
                    } else {
                        // ... from current process
                        hProcess = GetCurrentProcess(); // doesn't need CloseHandle
                    }
                    args.TokenHandle = OpenProcessToken(
                        hProcess,
                        TokenAccess.TokenQuery | TokenAccess.TokenAdjustPrivileges
                    );
                    args.CloseTokenHandle = true;
                }

                // Get id from PrivilegeName or PrivilegeId
                if (PrivilegeId.HasValue) {
                    // use provided id
                    if (PrivilegeName != null) {
                        throw new ArgumentException(
                            String.Format("Provide at most one of PrivilegeName or PrivilegeId")
                        );
                    }
                    args.PrivilegeId = PrivilegeId.Value;
                } else if (PrivilegeName != null) {
                    args.PrivilegeId = GetPrivilegeId(PrivilegeName);
                } else {
                    throw new ArgumentException(
                        String.Format("Provide at least one of PrivilegeName or PrivilegeId")
                    );
                }

                return args;
            }
            catch {
                args.Dispose();
                throw;
            }
        }
    }

    private const string c_UacRegistryKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    private const string c_UacRegistryValue = "EnableLUA";

    public static Boolean IsUacEnabled {
        get {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                return false;
            }
            var key =
                Microsoft.Win32.Registry.LocalMachine.OpenSubKey(c_UacRegistryKey, false);
            if (key == null) {
                return false;
            }
            var value = key.GetValue(c_UacRegistryValue);
            if (value == null) {
                return false;
            }
            return value.Equals(1);
        }
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
            /*[out] PHANDLE*/ out IntPtr TokenHandle
        );


        // LookupPrivilegeValue

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ Boolean LookupPrivilegeValue(
            /*[in, optional] LPCWSTR*/ String? SystemName,
            /*[in] LPCWSTR*/ String PrivilegeName,
            /*[out] PLUID*/ out Int64 PrivilegeLuid
        );


        // TokenHasPrivilege

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ bool PrivilegeCheck(
            /*HANDLE*/ IntPtr TokenHandle,
            /*PPRIVILEGE_SET*/ ref PRIVILEGE_SET_RoomForOne RequiredPrivileges,
            /*LPBOOL*/ out bool pfResult
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

        internal const Int32 ERROR_NOT_ALL_ASSIGNED = 0x00000514; // WinError.h
    }
}

/*

public static class NyxPsUtil {


    public static class Native {


    public static bool CheckPrivilege(
        Int64 processHandle,
        string privilege,
        out bool isEnabled) {
        bool succeeded = false;
        isEnabled = false;

        IntPtr hProcess = new IntPtr(processHandle);
        IntPtr hToken = IntPtr.Zero;

        PRIVILEGE_SET_RoomForOne ps;
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
        if (!TokenHasPrivilege(
            hToken,             // TokenHandle
            ref ps,             // RequiredPrivileges
            out isEnabled       // pfResult
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

*/
