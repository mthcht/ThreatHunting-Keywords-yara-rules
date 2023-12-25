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
        $string1 = /\sGet\-ServiceFromRegistry\s\-Name\sSpooler/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string2 = /\s\-Report\sPrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string3 = /\$LolDriversVulnerable/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string4 = /\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string5 = /\\PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string6 = /\\PrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string7 = /\\src\\check\\Credentials\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string8 = /Find\-ProtectionSoftware/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string9 = /Get\-AclModificationRights/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string10 = /Get\-DecodedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string11 = /Get\-DecryptedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string12 = /Get\-ExploitableUnquotedPath/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string13 = /Get\-LolDrivers\s/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string14 = /Get\-RemoteDesktopUserSessionList/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string15 = /Get\-RemoteDesktopUserSessionList\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string16 = /Get\-SccmCacheFolder/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string17 = /Get\-ShadowCopies/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string18 = /Get\-VaultCreds/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string19 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string20 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string21 = /Invoke\-ApplicationsOnStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string22 = /Invoke\-BitlockerCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string23 = /Invoke\-CcmNaaCredentialsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string24 = /Invoke\-CredentialFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string25 = /Invoke\-CredentialGuardCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string26 = /Invoke\-DefenderExclusionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string27 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string28 = /Invoke\-DriverCoInstallersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string29 = /Invoke\-EndpointProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string30 = /Invoke\-ExploitableLeakedHandlesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string31 = /Invoke\-GPPPasswordCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string32 = /Invoke\-HardenedUNCPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string33 = /Invoke\-HijackableDllsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string34 = /Invoke\-HotFixVulnCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string35 = /Invoke\-InstalledProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string36 = /Invoke\-InstalledServicesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string37 = /Invoke\-LapsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string38 = /Invoke\-LocalAdminGroupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string39 = /Invoke\-LsaProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string40 = /Invoke\-MachineRoleCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string41 = /Invoke\-ModifiableProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string42 = /Invoke\-NamedPipePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string43 = /Invoke\-NetworkAdaptersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string44 = /Invoke\-PowerShellHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string45 = /Invoke\-PowershellTranscriptionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string46 = /Invoke\-PrintNightmareCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string47 = /Invoke\-PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string48 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string49 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string50 = /Invoke\-RunningProcessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string51 = /Invoke\-SccmCacheFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string52 = /Invoke\-ScheduledTasksImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string53 = /Invoke\-ScheduledTasksUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string54 = /Invoke\-SCMPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string55 = /Invoke\-SensitiveHiveFileAccessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string56 = /Invoke\-SensitiveHiveShadowCopyCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string57 = /Invoke\-ServicesImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string58 = /Invoke\-ServicesPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string59 = /Invoke\-ServicesPermissionsRegistryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string60 = /Invoke\-ServicesUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string61 = /Invoke\-SystemStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string62 = /Invoke\-SystemStartupHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string63 = /Invoke\-TcpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string64 = /Invoke\-ThirdPartyDriversCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string65 = /Invoke\-UacCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string66 = /Invoke\-UdpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string67 = /Invoke\-UnattendFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string68 = /Invoke\-UserCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string69 = /Invoke\-UserEnvCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string70 = /Invoke\-UserGroupsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string71 = /Invoke\-UserPrivilegesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string72 = /Invoke\-UserRestrictedSidsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string73 = /Invoke\-UserSessionListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string74 = /Invoke\-UsersHomeFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string75 = /Invoke\-VaultCredCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string76 = /Invoke\-VaultListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string77 = /Invoke\-WindowsUpdateCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string78 = /Invoke\-WinlogonCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string79 = /Invoke\-WlanProfilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string80 = /itm4n\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string81 = /Microsoft\\Windows\\Recent\\PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string82 = /MISC_HIJACKABLE_DLL/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string83 = /Password.{0,1000}S0urce0fThePr0blem/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string84 = /Password.{0,1000}S3cr3tS3rvic3/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string85 = /PointAndPrint\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string86 = /PrivescCheck\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string87 = /PrivescCheck_.{0,1000}\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string88 = /PrivescCheckAsciiReport/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string89 = /Test\-DllExists/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string90 = /Test\-HijackableDll/ nocase ascii wide

    condition:
        any of them
}
