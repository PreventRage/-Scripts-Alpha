# NyxUtil

function Assert {
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromRemainingArguments = $true
        )]
        $Value = $false,
        [Parameter(
            Mandatory=$false
        )]
        [string]$Msg = "Failed"
    )
    foreach ($x in $Value) {
        if (-not $x) {
            Write-Error $Msg
            return
        }
    }
}

$CurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$CurrentUser = New-Object System.Security.Principal.NTAccount($CurrentUserName)

$x = [NyxNUtil]::GetUser()
$y = [NyxNUtil]::LookupAccount($x)
      
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

function Test-Elevated {
    [CmdletBinding(
        PositionalBinding=$false
    )]    
    Param(
        [Parameter(Mandatory=$false)]
        [Nullable[Int64]]$ProcessHandle,

        [Parameter(Mandatory=$false)]
        [Nullable[Int64]]$TokenHandle,

        [Parameter(Mandatory=$false)]
        [Nullable[Boolean]]$Uac
    )

    $Result = [NyxNUtil]::IsElevated($ProcessHandle, $TokenHandle, $Uac)
    return $Result
}

function Test-Privilege {
    [CmdletBinding(
        PositionalBinding=$false
    )]    
    Param(
        [Parameter(Mandatory=$false)]
        [Nullable[Int64]]$ProcessHandle,

        [Parameter(Mandatory=$false)]
        [Nullable[Int64]]$TokenHandle,

        [Parameter(Mandatory=$false)]
        [String]$PrivilegeName,

        [Parameter(Mandatory=$false)]
        [Nullable[Int64]]$PrivilegeId
    )

    $Result = [NyxNUtil]::HasPrivilege($ProcessHandle, $TokenHandle, $PrivilegeName, $PrivilegeId)
    return $Result
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
    SetProcessHandleAndId
    # $ProcessHandle = ProcessHandleFromArgs @PSBoundParameters
    if (![NyxNUtil]::EnableOrDisablePrivilege($ProcessHandle, $Privilege, $Enable)) {
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

# $IsPrivileged = Test-Privilege SeTakeOwnershipPrivilege
# $IsPrivileged
# Set-Privilege SeTakeOwnershipPrivilege $True
# $IsPrivileged = Test-Privilege SeTakeOwnershipPrivilege
# $IsPrivileged



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




#     public static bool CheckPrivilege(
#         Int64 processHandle,
#         string privilege,
#         out bool isEnabled) {
#         bool succeeded = false;
#         isEnabled = false;

#         IntPtr hProcess = new IntPtr(processHandle);
#         IntPtr hToken = IntPtr.Zero;

#         PRIVILEGE_SET_RoomForOne ps;
#         ps.PrivilegeCount = 1;
#         ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
#         ps.Luid = 0;
#         ps.Attributes = 0;

#         // May now goto LReturn on failure

#         if (!OpenProcessToken(
#             hProcess,           // ProcessHandle
#             TOKEN_QUERY,        // DesiredAccess
#             ref hToken          // TokenHandle
#         )) {
#             goto LReturn;
#         }
#         if (!LookupPrivilegeValue(
#             null,               // SystemName (null means local)
#             privilege,          // Name
#             ref ps.Luid         // Luid
#         )) {
#             goto LReturn;
#         }
#         if (!PrivilegeCheck(
#             hToken,             // TokenHandle
#             ref ps,             // RequiredPrivileges
#             out isEnabled       // pfResult
#         )) {
#             goto LReturn;
#         }
#         succeeded = true;
#     LReturn:
#         if (hToken != IntPtr.Zero) {
#             CloseHandle(hToken);
#         }
#         return succeeded;
#     }

#     public static bool EnablePrivilege(
#         long processHandle,
#         string privilege
#     ) {
#         return EnableOrDisablePrivilege(processHandle, privilege, true);
#     }

#     public static bool DisablePrivilege(
#         long processHandle,
#         string privilege
#     ) {
#         return EnableOrDisablePrivilege(processHandle, privilege, false);
#     }

#     public static bool EnableOrDisablePrivilege(
#         long processHandle, // experiment with using IntPtr instead
#         string privilege,
#         bool enable
#     ) {
#         bool succeeded = false;

#         IntPtr hProcess = new IntPtr(processHandle);
#         IntPtr hToken = IntPtr.Zero;

#         TOKEN_PRIVILEGES__RoomForOne tpNew;
#         tpNew.PrivilegeCount = 1;
#         tpNew.Luid = 0; // we'll look up the proper value later
#         tpNew.Attributes = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED;

#         var tpOld = new TOKEN_PRIVILEGES__RoomForOne();
#         Int32 tpOld_Room = Marshal.SizeOf(tpOld);
#         Int32 tpOld_Size;

#         // May now goto LReturn on failure

#         if (!OpenProcessToken(
#             hProcess,                   // ProcessHandle
#             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, // DesiredAccess
#             ref hToken                  // TokenHandle
#         )) {
#             goto LReturn;
#         }
#         if (!LookupPrivilegeValue(
#             null,                       // SystemName (null means local)
#             privilege,                  // Name
#             ref tpNew.Luid              // Luid
#         )) {
#             goto LReturn;
#         }
#         if (!AdjustTokenPrivileges(
#             hToken,                     // TokenHandle
#             false,                      // DisableAllPrivileges
#             ref tpNew,                  // NewState
#             tpOld_Room,                 // PreviousState_RoomInBytes
#             ref tpOld,                  // PreviousState
#             out tpOld_Size              // PreviousState_SizeInBytes
#         )) {
#             goto LReturn;
#         }
#         if (tpOld_Size != tpOld_Room) {
#             // It's not clear this is an error, but I'm suspicious
#             goto LReturn; 
#         }
#         succeeded = true;
#     LReturn:
#         if (hToken != IntPtr.Zero) {
#             CloseHandle(hToken);
#         }
#         return succeeded;
#     }

# */
# }