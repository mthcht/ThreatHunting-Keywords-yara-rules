rule PrivescCheck
{
    meta:
        description = "Detection patterns for the tool 'PrivescCheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivescCheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string1 = /.{0,1000}\/PrivescCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string2 = /.{0,1000}\\PrivescCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string3 = /.{0,1000}Find\-ProtectionSoftware.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string4 = /.{0,1000}Get\-AclModificationRights.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string5 = /.{0,1000}Get\-DecodedPassword.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string6 = /.{0,1000}Get\-DecryptedPassword.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string7 = /.{0,1000}Get\-ExploitableUnquotedPath.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string8 = /.{0,1000}Get\-RemoteDesktopUserSessionList.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string9 = /.{0,1000}Get\-RemoteDesktopUserSessionList\..{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string10 = /.{0,1000}Get\-SccmCacheFolder.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string11 = /.{0,1000}Get\-ShadowCopies.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string12 = /.{0,1000}Get\-VaultCreds.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string13 = /.{0,1000}Invoke\-AirstrikeAttackCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string14 = /.{0,1000}Invoke\-ApplicationsOnStartupCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string15 = /.{0,1000}Invoke\-BitlockerCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string16 = /.{0,1000}Invoke\-CredentialFilesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string17 = /.{0,1000}Invoke\-CredentialGuardCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string18 = /.{0,1000}Invoke\-DefenderExclusionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string19 = /.{0,1000}Invoke\-DllHijackingCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string20 = /.{0,1000}Invoke\-DriverCoInstallersCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string21 = /.{0,1000}Invoke\-EndpointProtectionCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string22 = /.{0,1000}Invoke\-ExploitableLeakedHandlesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string23 = /.{0,1000}Invoke\-GPPPasswordCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string24 = /.{0,1000}Invoke\-HardenedUNCPathCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string25 = /.{0,1000}Invoke\-HijackableDllsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string26 = /.{0,1000}Invoke\-HotFixVulnCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string27 = /.{0,1000}Invoke\-InstalledProgramsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string28 = /.{0,1000}Invoke\-InstalledServicesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string29 = /.{0,1000}Invoke\-LapsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string30 = /.{0,1000}Invoke\-LocalAdminGroupCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string31 = /.{0,1000}Invoke\-LsaProtectionCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string32 = /.{0,1000}Invoke\-MachineRoleCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string33 = /.{0,1000}Invoke\-ModifiableProgramsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string34 = /.{0,1000}Invoke\-NamedPipePermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string35 = /.{0,1000}Invoke\-NetworkAdaptersCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string36 = /.{0,1000}Invoke\-PowerShellHistoryCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string37 = /.{0,1000}Invoke\-PowershellTranscriptionCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string38 = /.{0,1000}Invoke\-PrintNightmareCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string39 = /.{0,1000}Invoke\-PrivescCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string40 = /.{0,1000}Invoke\-RegistryAlwaysInstallElevatedCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string41 = /.{0,1000}Invoke\-RunningProcessCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string42 = /.{0,1000}Invoke\-SccmCacheFolderCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string43 = /.{0,1000}Invoke\-ScheduledTasksImagePermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string44 = /.{0,1000}Invoke\-ScheduledTasksUnquotedPathCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string45 = /.{0,1000}Invoke\-SCMPermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string46 = /.{0,1000}Invoke\-SensitiveHiveFileAccessCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string47 = /.{0,1000}Invoke\-SensitiveHiveShadowCopyCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string48 = /.{0,1000}Invoke\-ServicesImagePermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string49 = /.{0,1000}Invoke\-ServicesPermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string50 = /.{0,1000}Invoke\-ServicesPermissionsRegistryCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string51 = /.{0,1000}Invoke\-ServicesUnquotedPathCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string52 = /.{0,1000}Invoke\-SystemStartupCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string53 = /.{0,1000}Invoke\-SystemStartupHistoryCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string54 = /.{0,1000}Invoke\-TcpEndpointsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string55 = /.{0,1000}Invoke\-ThirdPartyDriversCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string56 = /.{0,1000}Invoke\-UacCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string57 = /.{0,1000}Invoke\-UdpEndpointsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string58 = /.{0,1000}Invoke\-UnattendFilesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string59 = /.{0,1000}Invoke\-UserCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string60 = /.{0,1000}Invoke\-UserEnvCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string61 = /.{0,1000}Invoke\-UserGroupsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string62 = /.{0,1000}Invoke\-UserPrivilegesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string63 = /.{0,1000}Invoke\-UserRestrictedSidsCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string64 = /.{0,1000}Invoke\-UserSessionListCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string65 = /.{0,1000}Invoke\-UsersHomeFolderCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string66 = /.{0,1000}Invoke\-VaultCredCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string67 = /.{0,1000}Invoke\-VaultListCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string68 = /.{0,1000}Invoke\-WindowsUpdateCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string69 = /.{0,1000}Invoke\-WinlogonCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string70 = /.{0,1000}Invoke\-WlanProfilesCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string71 = /.{0,1000}itm4n\/PrivescCheck.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string72 = /.{0,1000}PrivescCheck\.ps1.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string73 = /.{0,1000}PrivescCheck_.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string74 = /.{0,1000}PrivescCheckAsciiReport.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string75 = /.{0,1000}Test\-DllExists.{0,1000}/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string76 = /.{0,1000}Test\-HijackableDll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
