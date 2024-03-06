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
        $string3 = /\s\-Report\sPrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string4 = /\$LolDriversVulnerable/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string5 = /\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string6 = /\\PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string7 = /\\PrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string8 = /\\PrivescCheck_/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string9 = /\\src\\check\\Credentials\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string10 = /\<title\>PrivescCheck\sReport\<\/title\>/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string11 = /Find\-ProtectionSoftware/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string12 = /Get\-AclModificationRights/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string13 = /Get\-DecodedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string14 = /Get\-DecryptedPassword/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string15 = /Get\-ExploitableUnquotedPath/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string16 = /Get\-LolDrivers/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string17 = /Get\-RemoteDesktopUserSessionList/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string18 = /Get\-RemoteDesktopUserSessionList\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string19 = /Get\-SccmCacheFolder/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string20 = /Get\-ShadowCopies/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string21 = /Get\-VaultCreds/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string22 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string23 = /Invoke\-AirstrikeAttackCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string24 = /Invoke\-ApplicationsOnStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string25 = /Invoke\-BitlockerCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string26 = /Invoke\-CcmNaaCredentialsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string27 = /Invoke\-CredentialFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string28 = /Invoke\-CredentialGuardCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string29 = /Invoke\-DefenderExclusionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string30 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string31 = /Invoke\-DriverCoInstallersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string32 = /Invoke\-EndpointProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string33 = /Invoke\-ExploitableLeakedHandlesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string34 = /Invoke\-GPPPasswordCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string35 = /Invoke\-HardenedUNCPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string36 = /Invoke\-HijackableDllsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string37 = /Invoke\-HotFixVulnCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string38 = /Invoke\-InstalledProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string39 = /Invoke\-InstalledServicesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string40 = /Invoke\-LapsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string41 = /Invoke\-LocalAdminGroupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string42 = /Invoke\-LsaProtectionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string43 = /Invoke\-MachineRoleCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string44 = /Invoke\-ModifiableProgramsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string45 = /Invoke\-NamedPipePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string46 = /Invoke\-NetworkAdaptersCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string47 = /Invoke\-PowerShellHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string48 = /Invoke\-PowershellTranscriptionCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string49 = /Invoke\-PrintNightmareCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string50 = /Invoke\-PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string51 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string52 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string53 = /Invoke\-RunningProcessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string54 = /Invoke\-SccmCacheFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string55 = /Invoke\-ScheduledTasksImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string56 = /Invoke\-ScheduledTasksUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string57 = /Invoke\-SCMPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string58 = /Invoke\-SensitiveHiveFileAccessCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string59 = /Invoke\-SensitiveHiveShadowCopyCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string60 = /Invoke\-ServicesImagePermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string61 = /Invoke\-ServicesPermissionsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string62 = /Invoke\-ServicesPermissionsRegistryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string63 = /Invoke\-ServicesUnquotedPathCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string64 = /Invoke\-SystemStartupCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string65 = /Invoke\-SystemStartupHistoryCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string66 = /Invoke\-TcpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string67 = /Invoke\-ThirdPartyDriversCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string68 = /Invoke\-UacCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string69 = /Invoke\-UdpEndpointsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string70 = /Invoke\-UnattendFilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string71 = /Invoke\-UserCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string72 = /Invoke\-UserEnvCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string73 = /Invoke\-UserGroupsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string74 = /Invoke\-UserPrivilegesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string75 = /Invoke\-UserRestrictedSidsCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string76 = /Invoke\-UserSessionListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string77 = /Invoke\-UsersHomeFolderCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string78 = /Invoke\-VaultCredCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string79 = /Invoke\-VaultListCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string80 = /Invoke\-WindowsUpdateCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string81 = /Invoke\-WinlogonCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string82 = /Invoke\-WlanProfilesCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string83 = /itm4n\/PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string84 = /Microsoft\\Windows\\Recent\\PrivescCheck/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string85 = /MISC_HIJACKABLE_DLL/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string86 = /Password.{0,1000}S0urce0fThePr0blem/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string87 = /Password.{0,1000}S3cr3tS3rvic3/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string88 = /PointAndPrint\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string89 = /PrivescCheck\.ps1/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string90 = /PrivescCheck_.{0,1000}\./ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string91 = /PrivescCheckAsciiReport/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string92 = /Test\-DllExists/ nocase ascii wide
        // Description: Privilege Escalation Enumeration Script for Windows
        // Reference: https://github.com/itm4n/PrivescCheck
        $string93 = /Test\-HijackableDll/ nocase ascii wide

    condition:
        any of them
}
