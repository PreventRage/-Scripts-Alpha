# Nyx-Privilege

$ManagePrivileges_Code = @'
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
'@
$ManagePrivileges_Type = Add-Type -TypeDefinition $ManagePrivileges_Code -PassThru
$ManagePrivileges_Class = $ManagePrivileges_Type[0]
        
enum Privilege {
    SeAssignPrimaryTokenPrivilege
    SeAuditPrivilege
    SeBackupPrivilege
    SeChangeNotifyPrivilege
    SeCreateGlobalPrivilege
    SeCreatePagefilePrivilege
    SeCreatePermanentPrivilege
    SeCreateSymbolicLinkPrivilege
    SeCreateTokenPrivilege
    SeDebugPrivilege
    SeEnableDelegationPrivilege
    SeImpersonatePrivilege
    SeIncreaseBasePriorityPrivilege
    SeIncreaseQuotaPrivilege
    SeIncreaseWorkingSetPrivilege
    SeLoadDriverPrivilege
    SeLockMemoryPrivilege
    SeMachineAccountPrivilege
    SeManageVolumePrivilege
    SeProfileSingleProcessPrivilege
    SeRelabelPrivilege
    SeRemoteShutdownPrivilege
    SeRestorePrivilege
    SeSecurityPrivilege
    SeShutdownPrivilege
    SeSyncAgentPrivilege
    SeSystemEnvironmentPrivilege
    SeSystemProfilePrivilege
    SeSystemtimePrivilege
    SeTakeOwnershipPrivilege
    SeTcbPrivilege
    SeTimeZonePrivilege
    SeTrustedCredManAccessPrivilege
    SeUndockPrivilege
    SeUnsolicitedInputPrivilege
}

function ProcessHandleFromArgs {
    Param(
        [Parameter(Mandatory=$false)]
        $ProcessId,
        [Parameter(Mandatory=$false)]
        $ProcessHandle
    )
    if ($null -ne $ProcessHandle) {
        if ($null -ne $ProcessId) {
            Write-Error 'Specify at most one of ProcessId and ProcessHandle'
            return $null
        } else {
            return $ProcessHandle
        }
    } else {
        if ($null -eq $ProcessId) {
            $ProcessId = $pid
        }
        return (Get-Process -id $ProcessId).Handle
    }
}
function Test-Privilege {
    Param(
        # The privilege to test.
        [Parameter(Mandatory=$true, Position=1)]
        [Privilege]$Privilege, 
    
        # What to check for the specified privilege. You may specify either
        # ProcessId or ProcessHandle or neither (defaults to the current process).
        [Parameter(Mandatory=$false)]
        $ProcessId,
        [Parameter(Mandatory=$false)]
        $ProcessHandle
    )
    $ProcessHandle = ProcessHandleFromArgs -ProcessHandle $ProcessHandle -ProcessId $ProcessId
    $Enabled = $false;
    if (!$ManagePrivileges_Class::CheckPrivilege($ProcessHandle, $Privilege, [ref][bool]$Enabled)) {
        Write-Error "Unable to check privilege [$Privilege]"
    }
    return $Enabled;
}

function Set-Privilege {
    Param(
        # The privilege to set (enable or disable).
        [Parameter(Mandatory=$true, Position=1)]
        [Privilege]$Privilege,

        [Parameter(Mandatory=$false, Position=2)]
        [Boolean]$Enable,

        # What to check for the specified privilege. You may specify either
        # ProcessId or ProcessHandle or neither (defaults to the current process).
        [Parameter(Mandatory=$false)]
        $ProcessId,
        [Parameter(Mandatory=$false)]
        $ProcessHandle
    )

    $ProcessHandle = ProcessHandleFromArgs -ProcessHandle $ProcessHandle -ProcessId $ProcessId
    if (!$ManagePrivileges_Class::EnableOrDisablePrivilege($ProcessHandle, $Privilege, $Enable)) {
        Write-Error "Failed to $($Enable ? "enable" : "disable") privilege [$Privilege]"
    }
}

$AppId = '65E2E13A-7110-4912-9F03-9A42E253D8F6'

$CLSIDs = @(
   '4661626C-9F41-40A9-B3F5-5580E80CB347'
   '4B6C85F1-A6D9-433A-9789-89EA153626ED'
   'B31118B2-1F49-48E5-B6F5-BC21CAEC56FB'
   'CBC04AF1-25C7-4A4D-BB78-28284403510F'
)

$CLSIDLocations = @(
   'HKEY_CLASSES_ROOT\CLSID'
   'HKEY_CLASSES_ROOT\WOW6432Node\CLSID'
   'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID'
   'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID'
   'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID'
)

$AdditionalKeys = @(
   'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileNotification\TDL'
   'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileNotification\TDL'
)

$CurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$CurrentUser = New-Object System.Security.Principal.NTAccount($CurrentUserName)

function ProcessCLSIDs {
    foreach ($l in $CLSIDLocations) {
        foreach ($c in $CLSIDs) {
            $Path = RegistryPath $l -CLSID $c
            Write-Host "Checking $Path"
            if (Test-Path $Path) {
                Write-Host "Exists. Processing..."
                ProcessClsid $Path
            }
            else {
                Write-Host "Does not exist."
            }
        }
     }
}

function RegistryPath {
    Param( 
        [Parameter(Position=0, Mandatory = $True, ValueFromPipeline = $True)]
        $Key,
        [Parameter(Mandatory = $False)]
        $CLSID
    )
    $Path = "Registry::$Key"
    if ($null -ne $CLSID) {
        $Path = "$Path\{$CLSID}"
    }
    return $Path
}

function ProcessCLSID {
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        $Path
    )
    $p = Get-ItemProperty -Path $Path
    $pd = $p.'(default)'
    if ($pd -ne "tiledatamodelsvc")  {
        Write-Error "Key [$Path] does not appear to belong to TileDataModelSvc"
        return
    }
    $pd = $p.AppId
    if ($pd -ne "{$AppId}")  {
        Write-Error "Value [$Path].AppId doesn't match {$AppId}"
        return
    }
    $acl1 = Get-Acl $Path
    $acl1.ToString()

    # Change Owner to the local Administrators group

    $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey(
        'CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}',
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership
    )
    $regACL = $regKey.GetAccessControl()
    $regACL.SetOwner([System.Security.Principal.NTAccount]"Administrators")
    $regKey.SetAccessControl($regACL)

    # Change Permissions for the local Administrators group
    
    $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey(
        'CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}',
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    $regACL = $regKey.GetAccessControl()
    $regRule = New-Object System.Security.AccessControl.RegistryAccessRule (
        "Administrators",
        "FullControl",
        "ContainerInherit",
        "None",
        "Allow"
    )
    $regACL.SetAccessRule($regRule)
    $regKey.SetAccessControl($regACL)

    Remove-Item -Path $Path -Recurse
}

$IsPrivileged = Test-Privilege SeTakeOwnershipPrivilege
$IsPrivileged

#ProcessCLSIDs

#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileNotification\TDL

#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ProfileNotification\TDL

#Computer\HKEY_CLASSES_ROOT\CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}
#Computer\HKEY_CLASSES_ROOT\CLSID\{4B6C85F1-A6D9-433A-9789-89EA153626ED}
#Computer\HKEY_CLASSES_ROOT\CLSID\{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
#Computer\HKEY_CLASSES_ROOT\CLSID\{CBC04AF1-25C7-4A4D-BB78-28284403510F}

#Computer\HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}
#Computer\HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{4B6C85F1-A6D9-433A-9789-89EA153626ED}
#Computer\HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
#Computer\HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{CBC04AF1-25C7-4A4D-BB78-28284403510F}

#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{4B6C85F1-A6D9-433A-9789-89EA153626ED}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CBC04AF1-25C7-4A4D-BB78-28284403510F}

#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{4B6C85F1-A6D9-433A-9789-89EA153626ED}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{CBC04AF1-25C7-4A4D-BB78-28284403510F}

#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{4661626C-9F41-40A9-B3F5-5580E80CB347}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{4B6C85F1-A6D9-433A-9789-89EA153626ED}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
#Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{CBC04AF1-25C7-4A4D-BB78-28284403510F}

