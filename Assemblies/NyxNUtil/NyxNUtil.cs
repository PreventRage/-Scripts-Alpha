using System.Runtime.InteropServices;

public static class NyxNUtil {

    private static void ThrowLastError() {
        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
    }

    public static void CloseHandle(Int64 Handle) {
        if (Handle != 0) {
            if (!Native.CloseHandle(new IntPtr(Handle))) {
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
        return Native.GetProcessId(new IntPtr(ProcessHandle));
    }

    // OpenProcess seems like a good thing to add

    [Flags]
    public enum TokenAccess : Int32 {
        AdjustDefault = Native.TOKEN_ADJUST_DEFAULT, // Required to change the default owner, primary group, or DACL of an access token.
        AdjustGroups = Native.TOKEN_ADJUST_GROUPS, // Required to adjust the attributes of the groups in an access token.
        AdjustPrivileges = Native.TOKEN_ADJUST_PRIVILEGES, // Required to enable or disable the privileges in an access token.
        AdjustSessionId = Native.TOKEN_ADJUST_SESSIONID, // Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required.
        AssignPrimary = Native.TOKEN_ASSIGN_PRIMARY, // Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is also required to accomplish this task.
        Duplicate = Native.TOKEN_DUPLICATE, // Required to duplicate an access token.
        Execute = Native.TOKEN_EXECUTE, // Same as STANDARD_RIGHTS_EXECUTE.
        Impersonate = Native.TOKEN_IMPERSONATE, // Required to attach an impersonation access token to a process.
        Query = Native.TOKEN_QUERY, // Required to query an access token.
        QuerySource = Native.TOKEN_QUERY_SOURCE, // Required to query the source of an access token.
        Read = Native.TOKEN_READ, // Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
        Write = Native.TOKEN_WRITE, // Combines STANDARD_RIGHTS_WRITE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, and TOKEN_ADJUST_DEFAULT.
        AllAccess = Native.TOKEN_ALL_ACCESS, // Combines all possible access rights for a token.
    }
     
    public static Int64 OpenProcessToken(Int64 ProcessHandle, TokenAccess DesiredAccess) {
        IntPtr hToken;
        if (!Native.OpenProcessToken(new IntPtr(ProcessHandle), (Int32)DesiredAccess, out hToken)) {
            ThrowLastError();
        }
        return (Int64)hToken;
    }

    public static T GetTokenInformation<T>(
        Int64? ProcessHandle = null,
        Int64? TokenHandle = null
    ) where T : new() {
        using var args = new TokenArgs(ProcessHandle, TokenHandle, ReadOnly: true);
        return GetTokenInformation<T>(args.TokenHandle);
    }

    public static T GetTokenInformation<T>(
        Int64 TokenHandle
     ) where T : new() {
        IntPtr h = new IntPtr(TokenHandle);
        var tie = Native.MapTokenInformationTypeToEnum.Value[typeof(T)];
        Int32 cb;
        Native.GetTokenInformation(h, tie, IntPtr.Zero, 0, out cb);
        IntPtr p = Marshal.AllocHGlobal(cb);
        Int32 cb2;
        if (!Native.GetTokenInformation(h, tie, p, cb, out cb2)) {
            ThrowLastError();
        }
        if (cb != cb2) {
            throw new Exception("Size of TokenInformation changed mysteriously");
        }
        T? result = Marshal.PtrToStructure<T>(p);
        if (result == null) {
            throw new Exception("PtrToStructure returned null");
        }
        return result;
    }

    //public static string GetSidString(byte[] sid) {
    //    IntPtr t;
    //    String result;
    //    if (!Native.ConvertSidToStringSid(sid, out ptrSid))
    //        throw new System.ComponentModel.Win32Exception();
    //    try {
    //        sidString = Marshal.PtrToStringAuto(ptrSid);
    //    }
    //    finally {
    //        LocalFree(ptrSid);
    //    }
    //    return sidString;
    //}

    private class TokenArgs : IDisposable {

        public Int64 TokenHandle { get; private set; }

        private Boolean hasBeenDisposed = false;
        private Boolean tokenHandleMustBeClosed = false;

        ~TokenArgs() {
            Dispose(false);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing) {
            if (!this.hasBeenDisposed) {
                if (this.tokenHandleMustBeClosed) {
                    CloseHandle(this.TokenHandle);
                    this.TokenHandle = 0;
                    this.tokenHandleMustBeClosed = false;
                }
                this.hasBeenDisposed = true;
            }
        }

        public TokenArgs(
            Int64? ProcessHandle,
            Int64? TokenHandle,
            Boolean? ReadOnly = null
         ) {
            try {
                if (TokenHandle != null) {
                    // use provided token
                    if (ProcessHandle != null) {
                        throw new ArgumentException(
                            String.Format("Provide at most one of ProcessHandle or TokenHandle")
                        );
                    }
                    this.TokenHandle = TokenHandle.Value;
                } else {
                    // get token from process
                    Int64 ProcessHandle_Actual;
                    if (ProcessHandle != null) {
                        // ... from provided process
                        ProcessHandle_Actual = ProcessHandle.Value;
                    } else {
                        // ... from current process
                        ProcessHandle_Actual = GetCurrentProcess(); // doesn't need CloseHandle
                    }
                    this.TokenHandle = OpenProcessToken(
                        ProcessHandle_Actual,
                        (ReadOnly == true) ?
                            TokenAccess.Read :
                            TokenAccess.Read | TokenAccess.Write
                    );
                    this.tokenHandleMustBeClosed = true;
                }
            }
            catch {
                this.Dispose(true);
                throw;
            }
        }
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
        using var args = new PrivilegeArgs(ProcessHandle, TokenHandle, PrivilegeName, PrivilegeId, ReadOnly: true);
        return TokenHasPrivilege(args.TokenHandle, args.PrivilegeId);
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
        using var args = new PrivilegeArgs(ProcessHandle, TokenHandle, PrivilegeName, PrivilegeId);
        EnableTokenPrivilege(args.TokenHandle, args.PrivilegeId, Enable);
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

    private class PrivilegeArgs : TokenArgs {

        public Int64 PrivilegeId { get; }

        public new void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        public PrivilegeArgs(
            Int64? ProcessHandle,
            Int64? TokenHandle,
            string? PrivilegeName,
            Int64? PrivilegeId,
            Boolean? ReadOnly = null
        ) : base(ProcessHandle, TokenHandle, ReadOnly) {
            try {
                if (PrivilegeId != null) {
                    // use provided id
                    if (PrivilegeName != null) {
                        throw new ArgumentException(
                            String.Format("Provide at most one of PrivilegeName or PrivilegeId")
                        );
                    }
                    this.PrivilegeId = PrivilegeId.Value;
                } else if (PrivilegeName != null) {
                    this.PrivilegeId = GetPrivilegeId(PrivilegeName);
                } else {
                    throw new ArgumentException(
                        String.Format("Provide at least one of PrivilegeName or PrivilegeId")
                    );
                }
            }
            catch {
                this.Dispose(true);
                throw;
            }

        }
    }

    private const string c_UacRegistryKeyName = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    private const string c_UacRegistryValueName = "EnableLUA";

    public static Boolean IsUacEnabled() {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            return false;
        }
        using var key =
            Microsoft.Win32.Registry.LocalMachine.OpenSubKey(c_UacRegistryKeyName, false);
        if (key == null) {
            return false;
        }
        var value = key.GetValue(c_UacRegistryValueName);
        if (value == null) {
            return false;
        }
        return value.Equals(1);
    }

    public static Boolean IsProcessElevated(Int64? ProcessHandle, Int64?TokenHandle) {
        using var args = new TokenArgs(ProcessHandle, TokenHandle, ReadOnly: true);
        return IsTokenElevated(args.TokenHandle);
    }

    public static Boolean IsTokenElevated(Int64 TokenHandle) {
        if (IsUacEnabled()) {
            Native.TOKEN_ELEVATION_TYPE elevation = Native.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;
        } else {

        }
        return false;
    }

    //    IntPtr tokenHandle = IntPtr.Zero;
    //        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_READ, out tokenHandle)) {
    //            throw new ApplicationException("Could not get process token.  Win32 Error Code: " +
    //                                           Marshal.GetLastWin32Error());
    //        }

    //        try {
    //            TOKEN_ELEVATION_TYPE elevationResult = TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;

    //            int elevationResultSize = Marshal.SizeOf(typeof(TOKEN_ELEVATION_TYPE));
    //            uint returnedSize = 0;

    //            IntPtr elevationTypePtr = Marshal.AllocHGlobal(elevationResultSize);
    //            try {
    //                bool success = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType,
    //                                                   elevationTypePtr, (uint)elevationResultSize,
    //                                                   out returnedSize);
    //                if (success) {
    //                    elevationResult = (TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(elevationTypePtr);
    //                    bool isProcessAdmin = elevationResult == TOKEN_ELEVATION_TYPE.TokenElevationTypeFull;
    //                    return isProcessAdmin;
    //                } else {
    //                    throw new ApplicationException("Unable to determine the current elevation.");
    //                }
    //            }
    //            finally {
    //                if (elevationTypePtr != IntPtr.Zero)
    //                    Marshal.FreeHGlobal(elevationTypePtr);
    //            }
    //        }
    //        finally {
    //            if (tokenHandle != IntPtr.Zero)
    //                CloseHandle(tokenHandle);
    //        }




    //    } else {

    //    }

    //}
    
    public static class Native {

        // CloseHandle

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /*BOOL*/ Boolean CloseHandle(
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
        public static extern /* BOOL */ Boolean OpenProcessToken(
            /* [in] HANDLE */ IntPtr ProcessHandle,
            /* [in] DWORD */ Int32 DesiredAccess,
            /* [out] PHANDLE */ out IntPtr TokenHandle
        );

        // ?

        public enum TOKEN_INFORMATION_CLASS {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES {
            public IntPtr Sid;
            public Int32 Attributes;
        }

        public enum TOKEN_ELEVATION_TYPE {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        public static readonly Lazy<Dictionary<Type, TOKEN_INFORMATION_CLASS>>
            MapTokenInformationTypeToEnum = new Lazy<Dictionary<Type, TOKEN_INFORMATION_CLASS>>(
                () => new Dictionary<Type, TOKEN_INFORMATION_CLASS>() {
                { typeof(TOKEN_USER), TOKEN_INFORMATION_CLASS.TokenUser }
                }
            );

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /* BOOL */ Boolean GetTokenInformation(
             /* [in] HANDLE */ IntPtr TokenHandle,
             /* [in] */ TOKEN_INFORMATION_CLASS TokenInformationClass,
             /* [out, optional] LPVOID */ IntPtr TokenInformation,
             /* [in] DWORD */ Int32 TokenInformation_RoomInBytes,
             /* [out] PDWORD */ out Int32 TokenInformation_SizeInBytes
        );


        // ?

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /* BOOL*/ Boolean ConvertSidToStringSid(
            /* [in] PSID */ IntPtr Sid,
            /* [out] LPSTR* */ out IntPtr StringSid);


        // LookupPrivilegeValue

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean LookupPrivilegeValue(
            /* [in, optional] LPCWSTR */ String? SystemName,
            /* [in] LPCWSTR */ String PrivilegeName,
            /* [out] PLUID */ out Int64 PrivilegeLuid
        );


        // TokenHasPrivilege

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ Boolean PrivilegeCheck(
            /*HANDLE*/ IntPtr TokenHandle,
            /*PPRIVILEGE_SET*/ ref PRIVILEGE_SET_RoomForOne RequiredPrivileges,
            /*LPBOOL*/ out Boolean pfResult
          );

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PRIVILEGE_SET_RoomForOne {
            public /* DWORD */ Int32 PrivilegeCount;
            public /* DWORD */ Int32 Control;
            /* LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY] ... */
            public /* LUID */ Int64 Luid;
            public /* DWORD */ Int32 Attributes;
        }

        internal const Int32 PRIVILEGE_SET_ALL_NECESSARY = 0x00000001;


        // AdjustTokenPrivileges

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean AdjustTokenPrivileges(
            /* HANDLE */ IntPtr TokenHandle,
            /* BOOL */ [MarshalAs(UnmanagedType.Bool)] Boolean DisableAllPrivileges,
            /* PTOKEN_PRIVILEGES */ ref TOKEN_PRIVILEGES_RoomForOne NewState,
            /* DWORD */ Int32 PreviousState_RoomInBytes,
            /* PTOKEN_PRIVILEGES */ ref TOKEN_PRIVILEGES_RoomForOne PreviousState,
            /* PDWORD */ out Int32 PreviousState_SizeInBytes
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
