using System.Runtime.InteropServices;
using System.Security.Principal;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class NyxNUtil {

    internal static int LastError() {
        return Marshal.GetLastWin32Error();
    }

    internal static Exception LastErrorException() {
        // Seems like there should be a Marshal.ExceptionForHR method to go with
        // (or maybe instead of) Marshal.ThrowExceptionForHR. Functions that always
        // throw don't seem very well supported in C#, [DoesNotReturn] not withstanding.
        // So instead we have this hack and end up throwing twice.
        Exception result;
        try {
            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            // Speaking of C# not supporting functions that never return. We can actually
            // never get here; ThrowExceptionForHR always throws. But the compiler doesn't
            // notice. So we have to initialize result on this bogus code-path too.
            result = new Exception("Should be impossible");
        }
        catch (Exception e) {
            result = e;
        }
        return result;
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    internal static void ThrowArgs(String? Message) {
        throw new ArgumentException(Message);
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    internal static void ThrowMisc(String? Message) {
        throw new Exception(Message);
    }

    internal static String StringFromWz(char[] Chars) {
        int length = Array.IndexOf(Chars, (char)0);
        return new string(Chars, 0, length);
    }

    public static void CloseHandle(Int64 Handle) {
        if (Handle != 0) {
            if (!Core.CloseHandle(new IntPtr(Handle))) {
                throw LastErrorException();
            }
        }
    }

    public static Int64 GetCurrentProcess() {
        return (Int64)Core.GetCurrentProcess();
        // Apparently this always returns a "pseudo-handle" equal to -1
        // that means "the current process" when passed to functions that
        // expect a Process handle
    }

    public static Int32 GetProcessId(Int64 ProcessHandle) {
        return Core.GetProcessId(new IntPtr(ProcessHandle));
    }

    // OpenProcess seems like a good thing to add

    #region Tokens

    [Flags]
    public enum TokenAccess : Int32 {
        AdjustDefault = Core.TOKEN_ADJUST_DEFAULT, // Required to change the default owner, primary group, or DACL of an access token.
        AdjustGroups = Core.TOKEN_ADJUST_GROUPS, // Required to adjust the attributes of the groups in an access token.
        AdjustPrivileges = Core.TOKEN_ADJUST_PRIVILEGES, // Required to enable or disable the privileges in an access token.
        AdjustSessionId = Core.TOKEN_ADJUST_SESSIONID, // Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required.
        AssignPrimary = Core.TOKEN_ASSIGN_PRIMARY, // Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is also required to accomplish this task.
        Duplicate = Core.TOKEN_DUPLICATE, // Required to duplicate an access token.
        Execute = Core.TOKEN_EXECUTE, // Same as STANDARD_RIGHTS_EXECUTE.
        Impersonate = Core.TOKEN_IMPERSONATE, // Required to attach an impersonation access token to a process.
        Query = Core.TOKEN_QUERY, // Required to query an access token.
        QuerySource = Core.TOKEN_QUERY_SOURCE, // Required to query the source of an access token.
        Read = Core.TOKEN_READ, // Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
        Write = Core.TOKEN_WRITE, // Combines STANDARD_RIGHTS_WRITE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, and TOKEN_ADJUST_DEFAULT.
        AllAccess = Core.TOKEN_ALL_ACCESS, // Combines all possible access rights for a token.
    }
     
    public static Int64 OpenProcessToken(Int64 ProcessHandle, TokenAccess DesiredAccess) {
        IntPtr hToken;
        if (!Core.OpenProcessToken(new IntPtr(ProcessHandle), (Int32)DesiredAccess, out hToken)) {
            throw LastErrorException();
        }
        return (Int64)hToken;
    }

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

    internal enum TOKEN_INFORMATION_CLASS {
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

    internal static T GetTokenInformation<T>(
        Int64 TokenHandle,
        TOKEN_INFORMATION_CLASS tic
    ) where T : struct {
        IntPtr p = IntPtr.Zero;
        try {
            IntPtr h = new IntPtr(TokenHandle);
            const int cbTry = 256;
            p = Marshal.AllocHGlobal(cbTry);
            Int32 cb;
            if (Core.GetTokenInformation(h, tic, p, cbTry, out cb)) {
                goto LSuccess;
            }
            if (cb > cbTry) {
                // All might not be lost. It appears we need more space.
                Marshal.FreeHGlobal(p);
                p = Marshal.AllocHGlobal(cb);
                Int32 cb2;
                if (Core.GetTokenInformation(h, tic, p, cb, out cb2)) {
                    if (cb != cb2) {
                        throw new Exception("Size of TokenInformation changed mysteriously");
                    }
                    goto LSuccess;
                }
            }
            // Failed
            throw LastErrorException();

        LSuccess:
            return Marshal.PtrToStructure<T>(p);
        }
        finally {
            if (p != IntPtr.Zero) {
                Marshal.FreeHGlobal(p);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_USER {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public Int32 Attributes;
    }

    public static SecurityIdentifier GetTokenUser(
        Int64? ProcessHandle = null,
        Int64? TokenHandle = null
    ) {
        using var args = new TokenArgs(ProcessHandle, TokenHandle, ReadOnly: true);
        var tu = GetTokenInformation<TOKEN_USER>(args.TokenHandle, TOKEN_INFORMATION_CLASS.TokenUser);
        return new SecurityIdentifier(tu.User.Sid);
    }

    #endregion

    #region SecurityIdentifiers (SIDs)

    public enum SidNameUse /* aka SID_NAME_USE */ {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel,
        SidTypeLogonSession
    }

    public class LookupAccountSidResult {
        public readonly String Name;
        public readonly String ReferencedDomainName;
        public readonly SidNameUse Use;

        internal LookupAccountSidResult(
            String Name,
            String ReferencedDomainName,
            SidNameUse Use
        ) {
            this.Name = Name;
            this.ReferencedDomainName = ReferencedDomainName;
            this.Use = Use;
        }
    }

    public static LookupAccountSidResult LookupAccountSid(
        SecurityIdentifier? sid = null,
        byte[]? sidAsBytes = null,
        String? SystemName = null
    ) {
        if (sidAsBytes == null) {
            if (sid == null) {
                ThrowArgs("Provide exactly one of sid or sidAsBytes");
            }
            sidAsBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidAsBytes, 0);
        }
        const int cb = 256;
        var name = new char[cb];
        UInt32 name_SizeInCharacters = cb;
        var referencedDomainName = new char[cb];
        UInt32 referencedDomainName_SizeInCharacters = cb;
        SidNameUse use;
        bool grew = false;
        for (int iTry = 1; ; iTry++) {
            if (Core.LookupAccountSid(
                SystemName,
                sidAsBytes,
                name,
                ref name_SizeInCharacters,
                referencedDomainName,
                ref referencedDomainName_SizeInCharacters,
                out use
            )) {
                // Success!
                return new LookupAccountSidResult(StringFromWz(name), StringFromWz(referencedDomainName), use);
            }
            // Lookup failed...
            if (iTry < 4) {
                // ... but it wasn't our last try yet. There are two cases where it's reasonable to
                // try again. Either we didn't allocate large enough buffers or Lookup timed out
                // trying to talk to a domain controller, etc.
                switch (LastError()) {
                    case Core.ERROR_INSUFFICIENT_BUFFER:
                        if (grew) {
                            ThrowMisc("We were told we need to grow more than once. Weird.");
                        }
                        if (name_SizeInCharacters > cb) {
                            name = new char[name_SizeInCharacters];
                            grew = true;
                        }
                        if (referencedDomainName_SizeInCharacters > cb) {
                            referencedDomainName = new char[referencedDomainName_SizeInCharacters];
                            grew = true;
                        }
                        if (!grew) {
                            ThrowMisc("We were told to grow but then neither buffer needed to grow. Weird.");
                        }
                        continue; // try again
                    case Core.ERROR_NONE_MAPPED:
                        // This is annoyingly returned both for SIDs that actually don't have an Account
                        // and in case of timeout. Guess it was a timeout.
                        Thread.Sleep(100);
                        continue; // try again
                }
            }
            // Failure!
            throw LastErrorException();
        }
    }

    #endregion

    #region Privileges

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

    public static Int64 GetPrivilegeId(
        string PrivilegeName, // Se* name of privilege
        string? SystemName = null // null means local system
    ) {
        Int64 id;
        if (!Core.LookupPrivilegeValue(SystemName, PrivilegeName, out id)) {
            throw LastErrorException();
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
        Core.PRIVILEGE_SET_RoomForOne ps;
        ps.PrivilegeCount = 1;
        ps.Control = Core.PRIVILEGE_SET_ALL_NECESSARY;
        ps.Luid = PrivilegeId;
        ps.Attributes = 0;

        IntPtr hToken = new IntPtr(TokenHandle);
        Boolean isEnabled;
        if (!Core.PrivilegeCheck(hToken, ref ps, out isEnabled)) {
            throw LastErrorException();
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

        var tpNew = new Core.TOKEN_PRIVILEGES_RoomForOne();
        tpNew.PrivilegeCount = 1;
        tpNew.Luid = PrivilegeId;
        tpNew.Attributes = Enable ? Core.SE_PRIVILEGE_ENABLED : Core.SE_PRIVILEGE_DISABLED;

        var tpOld = new Core.TOKEN_PRIVILEGES_RoomForOne();
        Int32 tpOld_Room = Marshal.SizeOf(tpOld);
        Int32 tpOld_Size;

        bool ok;
        ok = Core.AdjustTokenPrivileges(
            hToken,         // TokenHandle
            false,          // DisableAllPrivileges
            ref tpNew,      // NewState
            tpOld_Room,     // PreviousState_RoomInBytes
            ref tpOld,      // PreviousState
            out tpOld_Size  // PreviousState_SizeInBytes
        );

        // Somewhat weirdly AdjustTokenPrivileges sets error ERROR_NOT_ALL_ASSIGNED
        // while nevertheless returning success/true.
        if (!ok || Marshal.GetLastWin32Error() == Core.ERROR_NOT_ALL_ASSIGNED) {
            throw LastErrorException();
        }
    }

    #endregion // Privileges

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
            Core.TOKEN_ELEVATION_TYPE elevation = Core.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;
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
    
    public static class Core {

        internal const int NO_ERROR = 0;
        internal const int ERROR_INSUFFICIENT_BUFFER = 122;

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern /*BOOL*/ Boolean CloseHandle(
            /*[in] HANDLE hObject */ IntPtr Handle
        );

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern /*DWORD*/ Int32 GetProcessId(
            /*[in] HANDLE Process */ IntPtr ProcessHandle
        );

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

        public enum TOKEN_ELEVATION_TYPE {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean GetTokenInformation(
             /* [in] HANDLE " */ IntPtr TokenHandle,
             /* [in] " */ TOKEN_INFORMATION_CLASS TokenInformationClass,
             /* [out, optional] LPVOID " */ IntPtr TokenInformation,
             /* [in] DWORD TokenInformationLength */ Int32 TokenInformation_RoomInBytes,
             /* [out] PDWORD ReturnLength */ out Int32 TokenInformation_SizeInBytes
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean LookupAccountSid(
          /* [in, optional] LPCSTR lpSystemName */ String? SystemName,
          /* [in] PSID " */ byte[] Sid,
          /* [out, optional] LPSTR " */ char[]? Name,
          /* [in, out] LPDWORD cchName */ ref UInt32 Name_SizeInCharacters,
          /* [out, optional] LPSTR " */ char[]? ReferencedDomainName,
          /* [in, out] LPDWORD cchReferencedDomainName */ ref UInt32 ReferencedDomainName_SizeInCharacters,
          /* [out] PSID_NAME_USE peUse */ out SidNameUse Use);

        internal const int ERROR_NONE_MAPPED = 1332;

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean LookupPrivilegeValue(
            /* [in, optional] LPCWSTR lpSystemName */ String? SystemName,
            /* [in] LPCWSTR lpName */ String Name,
            /* [out] PLUID lpLuid */ out Int64 Luid
        );

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /*BOOL*/ Boolean PrivilegeCheck(
            /* [in] HANDLE ClientToken*/ IntPtr TokenHandle,
            /*[in, out] PPRIVILEGE_SET " */ ref PRIVILEGE_SET_RoomForOne RequiredPrivileges,
            /*[out] LPBOOL pfResult */ out Boolean Result
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

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern /* BOOL */ Boolean AdjustTokenPrivileges(
            /* [in] HANDLE " */ IntPtr TokenHandle,
            /* [in] BOOL " */ [MarshalAs(UnmanagedType.Bool)] Boolean DisableAllPrivileges,
            /* [in, optional] PTOKEN_PRIVILEGES " */ ref TOKEN_PRIVILEGES_RoomForOne NewState,
            /* [in] DWORD BufferLength */ Int32 PreviousState_RoomInBytes,
            /* [out, optional] PTOKEN_PRIVILEGES " */ ref TOKEN_PRIVILEGES_RoomForOne PreviousState,
            /* [out, optional] PDWORD ReturnLength */ out Int32 PreviousState_SizeInBytes
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
