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
        $string1 = /\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string2 = /\\PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string3 = /Find\-ProtectionSoftware/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string4 = /Get\-AclModificationRights/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string5 = /Get\-DecodedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string6 = /Get\-DecryptedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string7 = /Get\-ExploitableUnquotedPath/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string8 = /Get\-RemoteDesktopUserSessionList/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string9 = /Get\-RemoteDesktopUserSessionList\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string10 = /Get\-SccmCacheFolder/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string11 = /Get\-ShadowCopies/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string12 = /Get\-VaultCreds/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string13 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string14 = /Invoke\-ApplicationsOnStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string15 = /Invoke\-BitlockerCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string16 = /Invoke\-CredentialFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string17 = /Invoke\-CredentialGuardCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string18 = /Invoke\-DefenderExclusionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string19 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string20 = /Invoke\-DriverCoInstallersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string21 = /Invoke\-EndpointProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string22 = /Invoke\-ExploitableLeakedHandlesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string23 = /Invoke\-GPPPasswordCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string24 = /Invoke\-HardenedUNCPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string25 = /Invoke\-HijackableDllsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string26 = /Invoke\-HotFixVulnCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string27 = /Invoke\-InstalledProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string28 = /Invoke\-InstalledServicesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string29 = /Invoke\-LapsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string30 = /Invoke\-LocalAdminGroupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string31 = /Invoke\-LsaProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string32 = /Invoke\-MachineRoleCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string33 = /Invoke\-ModifiableProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string34 = /Invoke\-NamedPipePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string35 = /Invoke\-NetworkAdaptersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string36 = /Invoke\-PowerShellHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string37 = /Invoke\-PowershellTranscriptionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string38 = /Invoke\-PrintNightmareCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string39 = /Invoke\-PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string40 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string41 = /Invoke\-RunningProcessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string42 = /Invoke\-SccmCacheFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string43 = /Invoke\-ScheduledTasksImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string44 = /Invoke\-ScheduledTasksUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string45 = /Invoke\-SCMPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string46 = /Invoke\-SensitiveHiveFileAccessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string47 = /Invoke\-SensitiveHiveShadowCopyCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string48 = /Invoke\-ServicesImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string49 = /Invoke\-ServicesPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string50 = /Invoke\-ServicesPermissionsRegistryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string51 = /Invoke\-ServicesUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string52 = /Invoke\-SystemStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string53 = /Invoke\-SystemStartupHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string54 = /Invoke\-TcpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string55 = /Invoke\-ThirdPartyDriversCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string56 = /Invoke\-UacCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string57 = /Invoke\-UdpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string58 = /Invoke\-UnattendFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string59 = /Invoke\-UserCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string60 = /Invoke\-UserEnvCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string61 = /Invoke\-UserGroupsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string62 = /Invoke\-UserPrivilegesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string63 = /Invoke\-UserRestrictedSidsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string64 = /Invoke\-UserSessionListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string65 = /Invoke\-UsersHomeFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string66 = /Invoke\-VaultCredCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string67 = /Invoke\-VaultListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string68 = /Invoke\-WindowsUpdateCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string69 = /Invoke\-WinlogonCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string70 = /Invoke\-WlanProfilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string71 = /itm4n\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string72 = /PrivescCheck\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string73 = /PrivescCheck_.{0,1000}\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string74 = /PrivescCheckAsciiReport/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string75 = /Test\-DllExists/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string76 = /Test\-HijackableDll/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string77 = /PointAndPrint\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string78 = /\\src\\check\\Credentials\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string79 = /Get\-LolDrivers\s/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string80 = /Password.{0,1000}S3cr3tS3rvic3/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string81 = /Password.{0,1000}S0urce0fThePr0blem/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string82 = /\$LolDriversVulnerable/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string83 = /Invoke\-CcmNaaCredentialsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string84 = /MISC_HIJACKABLE_DLL/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string85 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string86 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string87 = /\sGet\-ServiceFromRegistry\s\-Name\sSpooler/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string88 = /\\PrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string89 = /\s\-Report\sPrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string90 = /Microsoft\\Windows\\Recent\\PrivescCheck/ nocase ascii wide

    condition:
        any of them
}
