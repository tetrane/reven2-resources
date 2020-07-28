<#

.NOTES
 - Disclaimer: This script is provided as-is with no guarantee. Please make sure 
   to backup the target system before any use.
 - Date: 12/2018
 - Author: This script has been developped by Tetrane, gathering tips from several 
   public sources.
 - Credits: Special credits to Richard Newton - https://github.com/Sycnex/Windows10Debloater.
 - License: MIT License
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

.SYNOPSIS
    Script used to make a light Windows system.

.DESCRIPTION
Important Notes:
 - This script must be executed from an elevated Powershell prompt
 - Execution policy must be set to unrestricted:
    >Set-ExecutionPolicy Unrestricted
        (confirm)
 - The HardDeleteApplications option also disable some explorer functionalities such as the start menu or Cortana. But the rest is still functional.
 - A reboot is needed for most of these modification to be effective
 - Once the machine has rebooted, it may be necessary to wait a bit for .NET processus to end. The reason of this is unknown
 - The AV modification are not persistent through reboot. The command >script.ps1 -DisableAV MUST be launched after the reboot to be effective.

.PARAMETER All
    Clean all. In this case, functionality such as Startup menu,
    Search, Cortana and else won't be available. The most notably
    effect of this is that entire folder are deleted the dirty way.

.PARAMETER Basic
    Do not hard delete applications. This is effective but let some windows functionalities.

.PARAMETER DisableUAC
    Should UAC be disabled

.PARAMETER DisableVisualEffects
    Should we remove visual effects (best performances)?

.PARAMETER DisableAV
    Should we disable some AV functionalities?
    Namely:
     - Disable Real-time monitory (occurs when a new binary is launched)
     - Exclude detection for C:\ and all extension
     - Never send samples
     - Update signature every 24h (maximum available...)
    This must be launched after the reboot, effects are not persistent:
    > script.ps1 -DisableAV

.PARAMETER DisableScheduledTasks
    Should we disable some scheduled tasks? AFAIK, there is no hard side
    effects to this parameters.

.PARAMETER EnableCDRomAutoRun
    Should we set the autorun when a CDROM is mounted? This mean that
    Windows will look for autorun.inf at the root directory of the mounted
    device and interpret it automatically. This is useful to automatically
    copy imported files from DVD to the VM.

.PARAMETER DisableServices
    Should we disable useless services? Some specific features may not work
    anymore but if needed these services can be re-activated.

.PARAMETER HardDeleteApplications
    Should we hard delete some useless windows application. This will
    affect user experience as we delete the Cortana files for the least.
    After this, the startup menu won't be available for example. But
    applications like Skype and OneDrive won't be running anymore in
    background.

.PARAMETER DeleteAuthorizedApps
    Should we delete authorized apps (with Remove-AppxPackage). Many application
    cannot be deleted this way. This may be used when HardDeleteApplications
    is too much.

.PARAMETER DisableTelemetry
    Should we disable some telemetry related options.

.EXAMPLE
.\script.ps1
    => Execute All. (Disable visual effects, hard delete of some applications, disable scheduled tasks, services, and else.). Equivalent of .\script.ps1 -All

.EXAMPLE
.\script.ps1 -DisableAV
    => Disable only some parameters from the AV. Specificities of what is disabled are available with Get-Help

.EXAMPLE
.\script.ps1 -DisableVisualEffects -DisableServices -DisableScheduledTasks -EnableCDRomAutoRun
    => Disable visual effects (like shadowing, blinking cursor and else), some services, scheduled tasks and enable the autorun from mounted CDRom
#>


param(
[Parameter(HelpMessage=@'
Clean all. In this case, functionality such as Startup menu
Search, Cortana and else won't be available. The most notably
effect of this is that entire folder are deleted the dirty way.
'@
)]
[switch]$All,
[Parameter(HelpMessage=@"
Do not hard delete applications. This is effective but let some windows functionalities.
"@)]
[switch]$Basic,

[Parameter(HelpMessage="Should we disable UAC?")]
[switch]$DisableUAC,

[Parameter(HelpMessage="Should we remove visual effects (best performances)?")]
[switch]$DisableVisualEffects,

[Parameter(HelpMessage=@"
Should we disable some AV functionalities?
namely:
 - Disable Realtime monitory (occurs when a new binary is launched)
 - Exclude detection for C:\ and all extension
 - Never send samples
 - Update signature every 24h (maximum available...)
This must be launched after the reboot, effects are not persistent:
>script.ps1 -DisableAV
"@)]
[switch]$DisableAV,

[Parameter(HelpMessage=@"
Should we disable some scheduled tasks? AFAIK, there is no hard side
effects to this parameters.
"@)]
[switch]$DisableScheduledTasks,

[Parameter(HelpMessage=@"
Should we set the autorun when a CDROM is mounted? This mean that
Windows will look for autorun.inf at the root directory of the mounted
device and interpret it automatically. This is useful to automatically
copy imported files from DVD to the VM.
"@)]
[switch]$EnableCDRomAutoRun,

[Parameter(HelpMessage=@"
Should we disable useless services? Some specific features may not work
anymore but if needed these services can be re-activated.
"@)]
[switch]$DisableServices,

[Parameter(HelpMessage=@"
Should we hard delete some useless windows application. This will
affect user experience as we delete the Cortana files for the least.
After this, the startup menu won't be available for example. But
applications like Skype and OneDrive won't be running anymore in
background.
"@)]
[switch]$HardDeleteApplications,
[Parameter(HelpMessage=@"
Should we delete authorized apps (with Remove-AppxPackage). Many application
cannot be deleted this way. This may be used when HardDeleteApplications
is too much.
"@)]
[switch]$DeleteAuthorizedApps,
[Parameter(HelpMessage=@"
Should we disable some telemetry related options.
"@)]
[switch]$DisableTelemetry

)



# Add other hives
$null = New-PSDrive -Name HKU  -PSProvider Registry -Root Registry::HKEY_USERS
$null = New-PSDrive -Name HKCR -PSProvider Registry -Root Registry::HKEY_CLASSES_ROOT
$null = New-PSDrive -Name HKCC -PSProvider Registry -Root Registry::HKEY_CURRENT_CONFIG



function Test-RegistryValue
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Name
        )
    try {
        Get-ItemProperty -Path $Path | Select-Object - ExpandProperty $Name -ErrorAction Stop | Out-Null
        Write-Output "[*] Path exists : $Path"
        return $true
    }

    catch {
        Write-Output "[*] Path doesn't exists : $Path"
        return $false
    }
}

function Set-RegistryKey{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Name,
        [parameter(Mandatory=$true)]
        $Value,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]$PropertyType
        )

    if (Test-Path $Path)
    {
        if(Test-RegistryValue -Path $Path -Name $Name)
        {
            Write-Verbose "[+] Modifying existing: $Path $Name $Value"
            Set-ItemProperty -Path $Path -Name $Name -Value $Value
        }
        else
        {
            Write-Verbose "[+] Create new property: $Path $Name"
            if ($PropertyType)
            {
                New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value
            }
            else
            {
                New-ItemProperty -Path $Path -Name $Name -Value $Value
            }
        }
    }
    else
    {
        Write-Verbose "[+] Create new key and proprerty: $Path $Name"
        New-Item -Path $Path -Force
        if ($PropertyType)
        {
            New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value
        }
        else
        {
            New-ItemProperty -Path $Path -Name $Name -Value $Value
        }
    }
}


function Take-Permissions {
    # Developed for PowerShell v4.0
    # Required Admin privileges
    # Links:
    #   http://shrekpoint.blogspot.ru/2012/08/taking-ownership-of-dcom-registry.html
    #   http://www.remkoweijnen.nl/blog/2012/01/16/take-ownership-of-a-registry-key-in-powershell/
    #   https://powertoe.wordpress.com/2010/08/28/controlling-registry-acl-permissions-with-powershell/

    param($rootKey, $key, [System.Security.Principal.SecurityIdentifier]$sid = 'S-1-5-32-545', $recurse = $true)

    switch -regex ($rootKey) {
        'HKCU|HKEY_CURRENT_USER'    { $rootKey = 'CurrentUser' }
        'HKLM|HKEY_LOCAL_MACHINE'   { $rootKey = 'LocalMachine' }
        'HKCR|HKEY_CLASSES_ROOT'    { $rootKey = 'ClassesRoot' }
        'HKCC|HKEY_CURRENT_CONFIG'  { $rootKey = 'CurrentConfig' }
        'HKU|HKEY_USERS'            { $rootKey = 'Users' }
    }

    ### Step 1 - escalate current process's privilege
    # get SeTakeOwnership, SeBackup and SeRestore privileges before executes next lines, script needs Admin privilege
    $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong a, bool b, bool c, ref bool d);'
    $ntdll = Add-Type -Member $import -Name NtDll -PassThru
    $privileges = @{ SeTakeOwnership = 9; SeBackup =  17; SeRestore = 18 }
    foreach ($i in $privileges.Values) {
        $null = $ntdll::RtlAdjustPrivilege($i, 1, 0, [ref]0)
    }

    function Take-KeyPermissions {
        param($rootKey, $key, $sid, $recurse, $recurseLevel = 0)

        ### Step 2 - get ownerships of key - it works only for current key
        $regKey = [Microsoft.Win32.Registry]::$rootKey.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetOwner($sid)

        $regKey.SetAccessControl($acl)

        ### Step 3 - enable inheritance of permissions (not ownership) for current key from parent
        $acl.SetAccessRuleProtection($false, $false)
        $regKey.SetAccessControl($acl)

        ### Step 4 - only for top-level key, change permissions for current key and propagate it for subkeys
        # to enable propagations for subkeys, it needs to execute Steps 2-3 for each subkey (Step 5)
        if ($recurseLevel -eq 0) {
            $regKey = $regKey.OpenSubKey('', 'ReadWriteSubTree', 'ChangePermissions')
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
            $acl.ResetAccessRule($rule)
            $regKey.SetAccessControl($acl)
        }

        ### Step 5 - recursively repeat steps 2-5 for subkeys
        if ($recurse) {
            foreach($subKey in $regKey.OpenSubKey('').GetSubKeyNames()) {
                Take-KeyPermissions $rootKey ($key+'\'+$subKey) $sid $recurse ($recurseLevel+1)
            }
        }
    }

    Take-KeyPermissions $rootKey $key $sid $recurse
}

###### MOVEFILE stuff

$MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
$MOVEFILE_REPLACE_EXISTING = 0x00000001

$memberDefinition = @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@


$kernel32 = Add-Type -Name Kernel32 -MemberDefinition $memberDefinition -PassThru



$AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

 public class TokenManipulator
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  [DllImport("kernel32.dll", ExactSpelling = true)]
  internal static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
  phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
  ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool AddPrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
  public static bool RemovePrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_DISABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
 }
"@
add-type $AdjustTokenPrivileges

#Activate necessary User privileges to make changes without NTFS perms
[void][TokenManipulator]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
[void][TokenManipulator]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
[void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions


#Obtain a copy of the initial ACL
#$FolderACL = Get-ACL $Folder - gives error when run against a folder with no User perms or ownership
#Create a new ACL object for the sole purpose of defining a new owner, and apply that update to the existing folder's ACL
$NewOwnerACL = New-Object System.Security.AccessControl.DirectorySecurity

# Get current computername\username to set new ACLs
#Establish the folder as owned by BUILTIN\Administrators, guaranteeing the following ACL changes can be applied
$User = New-Object System.Security.Principal.NTAccount(whoami)
$Admin = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
$NewAccessRuleFolderCurrentUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $User,
          "FullControl",
          "ContainerInherit,ObjectInherit",
          "None",
          "Allow")
$NewAccessRuleFolderAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $Admin,
          "FullControl",
          "ContainerInherit,ObjectInherit",
          "None",
          "Allow")

$NewAccessRuleFileCurrentUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $User,
          "FullControl",
          "None",
          "None",
          "Allow")
$NewAccessRuleFileAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $Admin,
          "FullControl",
          "None",
          "None",
          "Allow")

$NewOwnerACL.SetOwner($User)
$NewOwnerACL.AddAccessRule($NewAccessRuleFolderCurrentUser)
$NewOwnerACL.AddAccessRule($NewAccessRuleFolderAdmin)




function DeleteLockedDirectory{
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path
        )
    Write-Output "[+] Processing $s"
    $Folder.SetAccessControl($NewOwnerACL)
    $acl = Get-Acl $Folder.FullName
    $acl.SetOwner($User)
    Set-Acl $Folder.FullName $acl
    $acl = Get-Acl $Folder.FullName
    $acl.AddAccessRule($NewAccessRuleFolderCurrentUser)
    Set-Acl $Folder.FullName $acl
    # Do this for all subfolder
    $subFolders = Get-ChildItem $Folder.FullName -Directory -Recurse
    Foreach ($subFolder in $subFolders)
    {
      $acl = Get-Acl $subFolder.FullName
      $acl.SetOwner($User)
      Set-Acl $subFolder.FullName $acl
      $acl = Get-Acl $subFolder.FullName
      $acl.AddAccessRule($NewAccessRuleFolderCurrentUser)
      $acl.AddAccessRule($NewAccessRuleFolderAdmin)
      Set-Acl $subFolder.FullName $acl
    }
    # and also for all files
    $subFiles = Get-ChildItem $Folder.FullName -File -Recurse
    Foreach ($subFile in $subFiles)
    {
      $acl = Get-Acl $subFile.FullName
      $acl.SetOwner($User)
      Set-Acl $subFile.FullName $acl
      $acl = Get-Acl $subFile.FullName
      $acl.AddAccessRule($NewAccessRuleFileCurrentUser)
      $acl.AddAccessRule($NewAccessRuleFileAdmin)
      Set-Acl $subFile.FullName $acl
    }
    Write-Output "[+] Access rights changed to current user. Proceeding to deletion of $Folder.FullName content"
     # Delete files
    $subFiles = Get-ChildItem $Folder.FullName -File -Recurse
    Foreach($subFile in $subFiles)
    {
      $MoveFileResult = $Kernel32::MoveFileEx($subFile.FullName, "$env:LOCALAPPDATA\\temp.txt", $MOVEFILE_DELAY_UNTIL_REBOOT -bor $MOVEFILE_REPLACE_EXISTING)
      if ($MoveFileResult -eq $False)
      {
          Write-Error "[-] MoveFile failed."
          throw (New-Object ComponentModel.Win32Exception)
      }
      else
      {
          #Write-Output("Successfully planned move file")
      }
    }

}

# Disable some AV stuff
Function Disable-AVStuff
{
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -ExclusionPath "C:\"
    Set-MpPreference -ExclusionExtension "*"
    Set-MpPreference -SubmitSamplesConsent 2 # Never send
    Set-MpPreference -SignatureUpdateInterval 24 # 24h, maximum.
}

Function Remove-ONLINEAppxProvisionedPackage {
    Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

Function Remove-Keys {
    #These are the registry keys that it will delete.

    $Keys = @(

        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"

        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"

        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )

    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Verbose "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
}

Function Disable-TelemetryAndStuff
{
    #Disables Windows Feedback Experience
    Write-Verbose "[+] Disabling Windows Feedback Experience program"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name "Enabled" -Value 0

    #Stops Cortana from being used as part of your Windows Search Function
    Write-Verbose "[+] Stopping Cortana from being used as part of your Windows Search Function"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name "AllowCortana" -Value 0

    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Verbose "[+] Stopping the Windows Feedback Experience program"
    Set-RegistryKey -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name "PeriodInNanoSeconds" -Value 0

    Write-Verbose "[+] Adding Registry key to prevent bloatware apps from returning"
    #Prevents bloatware applications from returning
    Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

    Write-Verbose "[+] Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    Set-RegistryKey -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic' -Name "FirstRunSucceeded" -Value 0

    #Disables live tiles
    Write-Verbose "[+] Disabling live tiles"
    Set-RegistryKey -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name "NoTileApplicationNotification" -Value 1

    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Verbose "[+] Turning off Data Collection"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name "AllowTelemetry" -Value 0

    #Disables People icon on Taskbar
    Write-Verbose "[+] Disabling People icon on Taskbar"
    Set-RegistryKey -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name "PeopleBand" -Value 0

    #Disables suggestions on start menu
    Write-Verbose "[+] Disabling suggestions on the Start Menu"
    Set-RegistryKey -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name "SystemPaneSuggestionsEnabled" -Value 0

    #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
    reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
    Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
    reg unload HKU\Default_User
}


Function FixWhitelistedApps {

    If(!(Get-AppxPackage -AllUsers | Select Microsoft.WindowsCalculators)) {

    #Credit to abulgatz for the 4 lines of code
    Get-AppxPackage -allusers Microsoft.Paint3D | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.WindowsCalculator | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -allusers Microsoft.Windows.Photos | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} }
}


Function Disable-OptionalFeature {
    Write-Output "[!] This function needs internet access..."
    $features = Get-WindowsOptionalFeature -Online -FeatureName *
    foreach ($f in $features) {
        Disable-WindowsOptionalFeature -FeatureName $f.FeatureName -Online -NoRestart -Remove
    }
}



# Clear some system apps:
#########################################
function HardDelete-SystemApps {
    $apps_folders = Get-ChildItem -Path "C:\Windows\SystemApps\" -Directory -Force | Select-Object

    $todelete = "Cortana",
                "Cloud",
                # "InputApp",
                "BioEnrollment",
                "creddialog",
                # "Edge",
                # "PPIProjection_10",
                # "Win32WebViewHost",
                "AddSuggested",
                "AppRep",
                # "AppResolver",
                # "AssignedAccessLock",
                "CapturePicker",
                # "ContentDelivery",
                # "FilePicker",
                "narrator",
                "OOBENetwork",
                "PeopleExper",
                "PinningConfir",
                "SecHealthUI",
                # "SecureAssessment",
                "XGpuEject",
                "XboxGame",
                "ParentalControls",
                # "ShellExperienceHost",
                "CBSPreview"
    foreach ($Folder in $apps_folders)
    {
      foreach ($s in $todelete)
      {
        if ($Folder.name.Contains($s))
        {
            DeleteLockedDirectory $Folder.name
        }
      }
    }
}

# Clear some Windows Apps from LOCALAPPDATA
#########################################
function HardDelete-WindowsAppsAPPDATA
{
    $Directory = Join-Path $env:LOCALAPPDATA "Microsoft"
    $win_apps_folders_localdata = Get-ChildItem -Path $Directory -Directory -Force | Select-Object

    $todelete_localdata = "OneDrive",
                "MediaPlayer"

    foreach ($Folder in $win_apps_folders_localdata)
    {
      foreach ($s in $todelete_localdata)
      {
        if ($Folder.name.Contains($s))
        {
            DeleteLockedDirectory $Folder.name
        }

      }
    }
}

# Clear some Windows Apps from Program Files
#########################################
function HardDelete-WindowsAppsProgramFiles
{
    $Directory = "C:\Program Files\WindowsApps"
    $win_apps_folders = Get-ChildItem -Path $Directory -Directory -Force | Select-Object

    $todelete_winapp = "Advertising",
                "BingWeather",
                "Microsoft3DViewer",
                "MicrosoftOfficeHub",
                "MixedReality",
                "OneNote",
                "People",
                "Print3D",
                "ScreenSketch",
                "SkypeApp",
                "StorePurchaseApp",
                # "windowscommunicationapps",
                "WindowsFeedbackHub",
                "WindowsMaps",
                "WindowsSoundRecorder",
                # "WindowsStore",
                "Xbox",
                "SolitaireCollection",
                "bingfinance",
                # "DesktopAppInstaller",
                "GetHelp",
                "Getstarted",
                "HEIFImageExtension",
                "LanguageExperiencePacken",
                "Messaging",
                "3DViewer",
                "OfficeHub",
                "StickyNotes",
                "MixedReality",
                "MSPaint",
                "OneConnect",
                "ScreenSketch",
                "Engagement",
                # "Store",
                # "VP9VideoExtensions",
                "Wallet",
                "WebMediaExtensions",
                "WebpImageExtension",
                "Photos",
                "Alarms",
                # "Calculator",
                "Camera",
                "communicationsapps",
                "FeedbackHub",
                "Maps",
                "SoundRecorder",
                "YourPhone",
                "ZuneMusic",
                "ZuneVideo"


    foreach ($Folder in $win_apps_folders)
    {
      foreach ($s in $todelete_winapp)
      {
        if ($Folder.name.Contains($s))
        {
            DeleteLockedDirectory $Folder.name
        }

      }
    }
}

function Disable-VisualEffectsAndStuff
{

    Set-RegistryKey -Path "HKLM:System\CurrentControlSet\Control\Window" -Name "ErrorMode" -Value 00000002
    # Settings "Visual Effects" to custom, so we can modify them afterwards
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "VisualFXSetting" -Value 00000003

    #Now disable each effects
    # Disable Show translucent selection rectangle
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 00000000
    # Disable "Show shadows under windows"
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListViewShadow" -Value 00000000
    # From regshot
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 00000000
    # Drag full windows#Disable "Animate windows when minimizing and maximizing"
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop\" -Name "DragFullWindows" -PropertyType "String" -Value 0
    #Disable "Animate windows when minimizing and maximizing"
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -PropertyType "String" -Value 0
    # Disable the rest of the visual effects
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop\" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x01,0x80, 0x10, 0x00, 0x00, 0x00))
    #Disable “Animations in the taskbar”
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 00000000
    # Disable “Enable Peek”
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 00000000
    # Disable “Save Taskbar Thumbnail Previews”
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\DWM" -Name "AlwaysHibernateThumbnails" -Value 00000000
    # Disable “Smooth edges of screen fonts”
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop" -Name "FontSmoothing" -PropertyType "String" -Value 0
    # Disable cursor blink rate
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop" -Name "CursorBlinkRate" -PropertyType "String" -Value -1

    # Disable Internet Explorer First Run Wizard
    Set-RegistryKey -Path "HKLM:SOFTWARE\Policies\Microsoft\InternetExplorer\Main" -Name "DisableFirstRunCustomize" -Value 1
    # Reduce menu show delay
    Set-RegistryKey -Path "HKCU:Control Panel\Desktop" -Name "MenuShowDelay" -PropertyType "String" -Value 0

    # Remove the Action Center Sidebar
    Set-RegistryKey -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseActionCenterExperience" -PropertyType "DWord" -Value 0
    Set-RegistryKey -Path "HKCU:Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\PushNotification" -Name "ToastEnabled" -Value 0

    # Remove OneDrive from context menu
    Set-RegistryKey -Path "HKCR:CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
    #
    Set-RegistryKey -Path "HKCR:Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0


    # Remove Quick Access IconsOnly
    Take-Permissions "HKCR" "CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}"
    Set-RegistryKey -Path "HKCR:CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Name "Attributes" -Value 0xa0100000
    # Remove homegroup icon from navication
    Take-Permissions "HKCR" "CLSID\{b4fb3f98-c1ea-428d-a78a-d1f5659cba93}"
    Set-RegistryKey -Path "HKCR:CLSID\{b4fb3f98-c1ea-428d-a78a-d1f5659cba93}" -Name "System.IsPinnedToNameSpaceTree" -Value 0

    #Remove Network Icon from navigation pane
    #Take-Permissions "HKCR" "CLSID\{f02c1a0d-be21-4350-88b0-7367fc96ef3c}"
    #Set-RegistryKey -Path "HKCR:CLSID\{f02c1a0d-be21-4350-88b0-7367fc96ef3c}" -Name "System.IsPinnedToNameSpaceTree" -Value 0

    # Remove Removable Drive Icon from Navigation Pane of this PC
    # TODO : Adapt Set-Registry key to delete. Also, this may be handy so we let it for now.
    # Set-RegistryKey -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{f5fb2c77-0e2f-4a16-a381-3e560c68bc83}"

    # Display File Extension...
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
}


function Disable-UAC{
<#
.SYNOPSIS
    Disable UAC
.DESCRIPTION
    Disable UAC

.NOTES
    Disable UAC by modifying registry key. Keys are:
        - "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin"
        - "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"
#>
    $osversion = (Get-CimInstance Win32_OperatingSystem).Version
    $version = $osversion.split(".")[0]

    if ($version -eq 10) {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0"
    } ElseIf ($Version -eq 6) {
        $sub = $version.split(".")[1]
        if ($sub -eq 1 -or $sub -eq 0) {
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0"
        } Else {
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0"
        }
    } ElseIf ($Version -eq 5) {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0"
    } Else {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0"
    }
}

function Disable-UselessServices{
<#
.SYNOPSIS
    Disable extraneous services on Server 2016 Desktop Experience
.DESCRIPTION
    Disable extraneous services on Server 2016 Desktop Experience
.PARAMETER  ComputerName
    Disabled the services installed on the specified server. The default is the local computer.
.PARAMETER  PathFolder
    Specifies a path to log folder location.The default location is $env:USERPROFILE+'\DisablingServices\'
.EXAMPLE
    Disable-UselessServices -ComputerName srv01 -PathFolder C:\temp\DisabledServices\
.OUTPUTS
    Log file.
.NOTES
    This function is the one from CarlosDZRZ. I copied it as is and added a few services. It is probably redundant with some of other functions.
    Name: Disable-UselessServices
    Author: CarlosDZRZ
    DateCreated: 12/23/2017
.LINK
    https://gist.github.com/xtratoast/dea055ec0e1a31d91161b6d431e90146
    https://blogs.technet.microsoft.com/secguide/2017/05/29/guidance-on-disabling-system-services-on-windows-server-2016-with-desktop-experience/
    https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
    https://docs.microsoft.com/en-us/windows/application-management/per-user-services-in-windows
    https://technet.microsoft.com/en-us/library/cc959920.aspx
#>
[CmdletBinding()]
param(
    [String]$ComputerName = $env:COMPUTERNAME,
    [ValidateSet('ShouldBeDisabledOnly','ShouldBeDisabledAndDefaultOnly','OKToDisable','OKToDisablePrinter','OKToDisableDC')]
    [String]$Level = 'OKToDisablePrinter',
    [string]$PathFolder = $env:USERPROFILE+'\DisabledServices\'
)
Begin{
    $filename = "DisabledServices_" + $ComputerName
    if (!(Test-Path -Path $PathFolder -PathType Container)){
        New-Item -Path $PathFolder  -ItemType directory
        Write-Verbose "Create a new folder"
    }
    $filepath = $PathFolder + $filename +'.log'
    $stream = [System.IO.StreamWriter] $filepath
    #Set-Service : Service 'Contact Data (PimIndexMaintenanceSvc)' cannot be configured due to the following error: Access is denied. I need modify registry.
    [String[]]$Regedit_services = @(
                                        "CDPUserSvc",
                                        "PimIndexMaintenanceSvc",
                                        "OneSyncSvc",
                                        "UnistoreSvc",
                                        "UserDataSvc",
                                        "WpnUserService",
                                        "NgcSvc",
                                        "NgcCtnrSvc"
                                    )
    [String[]]$DisabledByDefault = @(
                                        "tzautoupdate",
                                        "Browser",
                                        "AppVClient",
                                        "NetTcpPortSharing",
                                        "CscService",
                                        "RemoteAccess",
                                        "SCardSvr",
                                        "UevAgentService",
                                        "WSearch"
                                    )
    [String[]]$ShouldBeDisabled = @(
                                        "XblAuthManager",
                                        "XblGameSave"
                                    )
    [String[]]$OKToDisable = @(
                                        "AxInstSV",
                                        "bthserv",
                                        "dmwappushservice",
                                        "MapsBroker",
                                        "lfsvc",             # location services
                                        "SharedAccess",
                                        "wlidsvc",           # windows live id
                                        # "lltdsvc",           # Link-Layer Topology Discovery Mapper
                                        # "NcbService",        # net connection broker
                                        "PhoneSvc",
                                        "PcaSvc",            # program compatibility
                                        "QWAVE",
                                        "RmSvc",
                                        "SensorDataService",
                                        "SensrSvc",
                                        "SensorService",
                                        # "ShellHWDetection", # mandatory for autoplay
                                        # "ScDeviceEnum",
                                        # "SSDPSRV",
                                        "WiaRpc",
                                        "TabletInputService",
                                        # "upnphost",
                                        "WalletService",
                                        "Audiosrv",
                                        "AudioEndpointBuilder",
                                        "FrameServer",
                                        "stisvc",
                                        "wisvc",
                                        "icssvc", # Windows Mobile Hotspot Service
                                        "WpnService",
                                        "EventLog",
                                        "wuauserv",
                                        "LicenseManager",
                                        # "Winmgmt", # This service is mandatory for MpPreference. Disable if needed.
                                        "FontCache",
                                        # "Wcmsvc", # Windows Connection Manager
                                        "DiagTrack",
                                        "DusmSvc" # Data Usage
                                )
    [String[]]$OKToDisableNotDCorPrint = @('Spooler')
    [String[]]$OKToDisableNotPrint = @('PrintNotify')
    [String[]]$ServicesToDisable = @()

    switch($Level)
    {
        'ShouldBeDisabledOnly'           { $ServicesToDisable += $ShouldBeDisabled }
        'ShouldBeDisabledAndDefaultOnly' { $ServicesToDisable += $ShouldBeDisabled + $DisabledByDefault }
        'OKToDisablePrinter'             { $ServicesToDisable += $ShouldBeDisabled + $DisabledByDefault + $OKToDisable + $Regedit_services}
        'OKToDisableDC'                  { $ServicesToDisable += $ShouldBeDisabled + $DisabledByDefault + $OKToDisable + $OKToDisableNotDCorPrint + $Regedit_services }
        'OKToDisable'                    { $ServicesToDisable += $ShouldBeDisabled + $DisabledByDefault + $OKToDisable + $OKToDisableNotDCorPrint + $OKToDisableNotPrint + $Regedit_services }
    }
}
Process{
    $InstalledServices = Get-Service -ComputerName $ComputerName

    foreach($Service in $ServicesToDisable)
    {
        if ($Regedit_services -contains $Service){
            #Take-Permissions "HKLM" "\SYSTEM\CurrentControlSet\Services\$Service"
            #Set-ItemProperty not ComputerName parameter
            if ($ComputerName -eq $env:COMPUTERNAME){
                #localhost
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Service" -Name "Start" -value 4 | Write-Verbose
                $stream.WriteLine("Disabled service: $Service")
            }
            else{
                #remote server
                Invoke-Command -ScriptBlock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($args[0])" -Name "Start" -value 4} -ArgumentList $Service -ComputerName $ComputerName | Write-Verbose
                $stream.WriteLine("Disabled service: $Service")
            }
        }
        elseif($InstalledServices.Name -contains $Service){
            Set-Service -Name $Service -ComputerName $ComputerName -StartupType Disabled | Write-Verbose
            $stream.WriteLine("Disabled service: $Service")
        }
    }
}
End{
    $stream.close()
}
}#end function Disable-UselessServices
#Take-Permissions "HKLM" "\SYSTEM\CurrentControlSet\Services\$Service"


function Disable-ScheduledTaskWrapper
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$TaskName
        )
    Write-Verbose "[+] Disabling task $TaskName"
    get-scheduledtask | where-object {($_.state -eq "Ready") -and ($_.taskname -like $TaskName)}|disable-scheduledtask | Out-Null
}

function Disable-ScheduledTasks
{
    [String[]]$TaskNames = @(

    "Smartscreenspecific",
    #Aggregates and uploads Application Telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
    "Microsoft Compatibility Appraiser",
    #Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
    "ProgramDataUpdater",
    #This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program.
    "Proxy",
    #If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft.
    "Consolidator",
    #The Kernel CEIP (Customer Experience Improvement Program) task collects additional information about the system and sends this data to Microsoft. If the user has not consented to participate in Windows CEIP, this task does nothing.
    "KernelCeipTask",
    #The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends to the Windows Device Connectivity engineering group at Microsoft. The information received is used to help improve the reliability, stability, and overall functionality of USB in Windows. If the user has not consented to participate in Windows CEIP, this task does not do anything.
    "UsbCeip",
    "DmClient",
    "QueueReporting",
    #This job sends data about windows based on user participation in the Windows Customer Experience Improvement Program
    "Uploader",
    #Initializes Family Safety monitoring and enforcement.
    "FamilySafetyMonitor",
    #Synchronizes the latest settings with the Family Safety website.
    "FamilySafetyRefresh",
    #Scans startup entries and raises notification to the user if there are too many startup entries.
    "StartupAppTask",
    #NTFS Volume Health Scan
    "ProactiveScan",
    #The Windows Scheduled Maintenance Task performs periodic maintenance of the computer system by fixing problems automatically or reporting them through the Action Center.
    "Scheduled",
    #The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program.
    "*DiskDiagnosticDataCollector*",
    #This task warns users about faults that occur on disks that support Self-Monitoring and Reporting Technology
    "*DiskDiagnosticResolver*",
    #This task optimizes local storage drives
    "ScheduledDefrag",
    #Protects user files from accidental loss by copying them to a backup location when the system is unattended
    "*File History*",
    #Measures a system’s performance and capabilities
    "WinSAT",
    #Schedules a memory diagnostic in response to system events
    "ProcessMemoryDiagnosticEvents",
    #Detects and mitigates problems in physical memory (RAM).
    "RunFullMemoryDiagnostic",
    #This task analyzes the system looking for conditions that may cause high energy use.
    "AnalyzeSystem",
    #Validates the Windows Recovery Environment.
    "VerifyWinRE",
    #Registry Idle Backup Task
    "RegIdleBackup",
    #This task creates regular system protection points.
    "SR",
    #The Windows Diagnostic Infrastructure Resolution host enables interactive resolutions for system problems detected by the Diagnostic Policy Service. It is triggered when necessary by the Diagnostic Policy Service in the appropriate user session. If the Diagnostic Policy Service is not running, the task will not run
    "ResolutionHost"
    )

    foreach ($task in $TaskNames)
    {
        Disable-ScheduledTaskWrapper $task
    }

}

Function Set-AutoRunINF
{
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 00000000
    Set-RegistryKey -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\AutorunINFLegacyArrival" -Name "(Default)" -PropertyType "String" -Value "MSAutoRun"
}

Function Remove-AuthorizedAppx
{
    get-appxpackage | remove-appxpackage -ErrorAction SilentlyContinue
    # Appx Remove
    <#
    Get-AppxPackage *SolitaireCollection* | Remove-AppxPackage
    Get-AppxPackage *BingWeather* | Remove-AppxPackage
    Get-AppxPackage *bingfinance* | Remove-AppxPackage
    Get-AppxPackage *DesktopAppInstaller* | Remove-AppxPackage
    Get-AppxPackage *Advertising* | Remove-AppxPackage
    Get-AppxPackage *BingWeather* | Remove-AppxPackage
    Get-AppxPackage *GetHelp* | Remove-AppxPackage
    Get-AppxPackage *Getstarted* | Remove-AppxPackage
    Get-AppxPackage *HEIFImageExtension* | Remove-AppxPackage
    Get-AppxPackage *LanguageExperiencePacken* | Remove-AppxPackage
    Get-AppxPackage *Messaging* | Remove-AppxPackage
    Get-AppxPackage *3DViewer* | Remove-AppxPackage
    Get-AppxPackage *OfficeHub* | Remove-AppxPackage
    Get-AppxPackage *StickyNotes* | Remove-AppxPackage
    Get-AppxPackage *MixedReality* | Remove-AppxPackage
    Get-AppxPackage *MSPaint* | Remove-AppxPackage
    Get-AppxPackage *OneNote* | Remove-AppxPackage
    Get-AppxPackage *OneConnect* | Remove-AppxPackage
    #Get-AppxPackage *People* | Remove-AppxPackage # Not authorized
    Get-AppxPackage *Print3D* | Remove-AppxPackage
    Get-AppxPackage *ScreenSketch* | Remove-AppxPackage
    Get-AppxPackage *Engagement* | Remove-AppxPackage
    Get-AppxPackage *Store* | Remove-AppxPackage
    Get-AppxPackage *SkypeApp* | Remove-AppxPackage
    Get-AppxPackage *StorePurchaseApp* | Remove-AppxPackage
    Get-AppxPackage *VP9VideoExtensions* | Remove-AppxPackage
    Get-AppxPackage *Wallet* | Remove-AppxPackage
    Get-AppxPackage *WebMediaExtensions* | Remove-AppxPackage
    Get-AppxPackage *WebpImageExtension* | Remove-AppxPackage
    Get-AppxPackage *Photos* | Remove-AppxPackage
    Get-AppxPackage *Alarms* | Remove-AppxPackage
    Get-AppxPackage *Calculator* | Remove-AppxPackage
    Get-AppxPackage *Camera* | Remove-AppxPackage
    Get-AppxPackage *communicationsapps* | Remove-AppxPackage
    Get-AppxPackage *FeedbackHub* | Remove-AppxPackage
    Get-AppxPackage *Maps* | Remove-AppxPackage
    Get-AppxPackage *SoundRecorder* | Remove-AppxPackage
    Get-AppxPackage *Store* | Remove-AppxPackage
    Get-AppxPackage *XboxApp* | Remove-AppxPackage
    Get-AppxPackage *YourPhone* | Remove-AppxPackage
    Get-AppxPackage *ZuneMusic* | Remove-AppxPackage
    Get-AppxPackage *ZuneVideo* | Remove-AppxPackage
    #>
}




<#
Write-Output "[+] Connected to the internet, Removing some apps with builtin tools."
Remove-ONLINEAppxProvisionedPackage
#>

$allArgs = $PSBoundParameters.Values + $Args
if($allArgs.Count -eq 0)
{
    Write-Output "No argument provided, doing nothing and exiting."
    exit 1
}

if($HardDeleteApplications -or $All)
{
    Write-Output "[+] Hard Delete of WindowsApps applications"
    HardDelete-WindowsAppsAPPDATA
    Write-Output "[+] Hard Delete of SystemApps applications"
    HardDelete-SystemApps
    Write-Output "[+] Hard Delete of APPDATA applications"
    HardDelete-WindowsAppsProgramFiles
}
if($DisableAV -or $All -or $Basic)
{
    Write-Output "[+] Disable some AV stuff"
    Disable-AVStuff
}
if($DisableUAC -or $All -or $Basic)
{
    Write-Output "[+] Disable UAC"
    Disable-UAC
}
if($DisableVisualEffects -or $All -or $Basic)
{
    Write-Output "[+] Disable Visual effects and stuff"
    Disable-VisualEffectsAndStuff
}
if($DisableTelemetry -or $All -or $Basic)
{
    Write-Output "[+] Stopping telemetry, disabling unneccessary scheduled tasks, and preventing bloatware from returning."
    Disable-TelemetryAndStuff
    Write-Output "[+] Remove some keys related to apps."
    Remove-Keys
}
if($EnableCDRomAutoRun -or $All -or $Basic)
{
    Write-Output "[+] Set auto execute the autorun.inf at mount"
    Set-AutoRunINF
}
if($DisableServices -or $All -or $Basic)
{
    Write-Output "[+] Disable some services"
    Disable-UselessServices
}
if($DisableScheduledTasks -or $All -or $Basic)
{
    Write-Output "[+] Disable Scheduled tasks"
    Disable-ScheduledTasks
}
<# # Doesn't work for unknown reason, block the rest of the script...
if($DeleteAuthorizedApps -or $All -or $Basic)
{
    Write-Output "[+] Delete authorized apps"
    Remove-AuthorizedAppx
}
#>





# End of script, ask user for restart

$shell = New-Object -comobject "WScript.Shell"
$choice = $shell.popup("Most of previous operations needs a reboot to be effective. Restart now? Use Get-Help for important notes.", 0, "Reboot required", 1+32) # type of buttons + windows

<#
Type of buttons :
                Value     Buttons
0                OK        OK                   - This is the Default
1                OC        OK Cancel
2                AIR       Abort Ignore Retry
3                YNC       Yes No Cancel
4                YN        Yes No
5                RC        Retry Cancel

Return value :
    -1 Timeout
     1  OK
     2  Cancel
     3  Abort
     4  Retry
     5  Ignore
     6  Yes
     7  No
#>

if (($choice -eq 1) -or ($choice -eq -1) )
{
    Write-Output "[+] Restarting computer..."
    Restart-Computer
}
else
{
    Write-Output "[+] Most of effects won't be effective until next reboot."
    Write-Output "END. "
}

