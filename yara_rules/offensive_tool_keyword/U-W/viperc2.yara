rule viperc2
{
    meta:
        description = "Detection patterns for the tool 'viperc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "viperc2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string1 = /.{0,1000}\/\.msf4\/.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string2 = /.{0,1000}\/hackerid\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string3 = /.{0,1000}\/loot_default\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string4 = /.{0,1000}\/loot_default\/.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string5 = /.{0,1000}\/loot_default\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string6 = /.{0,1000}\/RGPerson\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string7 = /.{0,1000}\/root\/viper\/.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string8 = /.{0,1000}\/root\/viper\/dist.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string9 = /.{0,1000}\/SHELLCODELOADER.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string10 = /.{0,1000}\/stinger_client\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string11 = /.{0,1000}\/viper\.conf.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string12 = /.{0,1000}\/viper\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string13 = /.{0,1000}\/viper\.sln.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string14 = /.{0,1000}\/viper\/Docker\/.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string15 = /.{0,1000}\/viper\/Docker\/nginxconfig\/htpasswd.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string16 = /.{0,1000}\/vipermsf.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string17 = /.{0,1000}\/viperpython.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string18 = /.{0,1000}\/viperpython\.git.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string19 = /.{0,1000}_GetNetLoggedon\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string20 = /.{0,1000}a7469955bff5e489d2270d9b389064e1.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string21 = /.{0,1000}auto_pass_the_hash\..{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string22 = /.{0,1000}Bot_MSF_Exp_.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string23 = /.{0,1000}Bot_Python_Poc_Log4j2_VMwareHorizon\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string24 = /.{0,1000}BrowserBookmarkDiscovery_BrowserHistory\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string25 = /.{0,1000}BrowserGhost\-N.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string26 = /.{0,1000}cd40dbcdae84b1c8606f29342066547069ed5a33.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string27 = /.{0,1000}Collection_ArchiveCollectedData_ArchiveViaCustomMethod\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string28 = /.{0,1000}Collection_ArchiveCollectedData_ArchiveViaCustomMethod_7z\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string29 = /.{0,1000}CommandAndControl_.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string30 = /.{0,1000}CredentialAccess_CredentialDumping_BrowserDataCSharp\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string31 = /.{0,1000}CredentialAccess_CredentialDumping_KiwiOnLocal\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string32 = /.{0,1000}CredentialAccess_CredentialDumping_SunLogin\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string33 = /.{0,1000}CredentialAccess_CredentialDumping_WindowsHashDump\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string34 = /.{0,1000}CredentialAccess_CredentialDumping_WindowsWDigestEnable\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string35 = /.{0,1000}CredentialAccess_CredentialInFiles_BrowserData\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string36 = /.{0,1000}CredentialAccess_CredentialInFiles_WindowsSoftware\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string37 = /.{0,1000}CredentialAccess_InputCapture_CredUIPromptForWindowsCredentialsW\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string38 = /.{0,1000}DefenseEvasion_CodeSigning_PeSigningAuthHijack\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string39 = /.{0,1000}DefenseEvasion_CodeSigning_StolenMircosoftWindowsSignature\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string40 = /.{0,1000}DefenseEvasion_ProcessInjection_CobaltStrikeOnline\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string41 = /.{0,1000}DefenseEvasion_ProcessInjection_CsharpAssemblyLoader\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string42 = /.{0,1000}DefenseEvasion_ProcessInjection_CsharpAssemblyLoaderPlus\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string43 = /.{0,1000}DefenseEvasion_ProcessInjection_ExampleModule\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string44 = /.{0,1000}DefenseEvasion_ProcessInjection_PeLoader\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string45 = /.{0,1000}DefenseEvasion_ProcessInjection_PowershellRunInMem\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string46 = /.{0,1000}DefenseEvasion_ProcessInjection_ProcessHandle\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string47 = /.{0,1000}DefenseEvasion_ProcessInjection_PythonRunInMem\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string48 = /.{0,1000}DefenseEvasion_ProcessInjection_SessionClone\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string49 = /.{0,1000}DefenseEvasion_ProcessInjection_ShellcodeLoader\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string50 = /.{0,1000}DefenseEvasion_ProcessInjection_WindowsSystem\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string51 = /.{0,1000}DefenseEvasion_SubvertTrustControls_CloneSSLPem\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string52 = /.{0,1000}DirectDLL_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string53 = /.{0,1000}DirectDLL_x86\.dll.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string54 = /.{0,1000}Discovery_AccountDiscovery_GetNetDomainUser\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string55 = /.{0,1000}Discovery_AccountDiscovery_PowerView\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string56 = /.{0,1000}Discovery_ApplicationWindowDiscovery_EnumApplication\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string57 = /.{0,1000}Discovery_Microphone_CallInfo\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string58 = /.{0,1000}Discovery_Microphone_camera\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string59 = /.{0,1000}Discovery_Microphone_record_mic\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string60 = /.{0,1000}Discovery_NetworkServiceScanning_ARPScan\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string61 = /.{0,1000}Discovery_NetworkServiceScanning_NbtScanByPython\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string62 = /.{0,1000}Discovery_NetworkServiceScanning_NextnetByPE\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string63 = /.{0,1000}Discovery_NetworkServiceScanning_PingByPython\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string64 = /.{0,1000}Discovery_NetworkServiceScanning_PortScanByPython\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string65 = /.{0,1000}Discovery_NetworkServiceScanning_PortScanWithServiceByPython\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string66 = /.{0,1000}Discovery_NetworkShareDiscovery_PowerView\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string67 = /.{0,1000}Discovery_PermissionGroupsDiscovery_PowerView\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string68 = /.{0,1000}Discovery_QueryRegistry_GetDotNetVersions\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string69 = /.{0,1000}Discovery_QueryRegistry_GetRDPPort\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string70 = /.{0,1000}Discovery_RemoteSystemDiscovery_GetDomainIPAddress\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string71 = /.{0,1000}Discovery_RemoteSystemDiscovery_GetNetComputer\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string72 = /.{0,1000}Discovery_RemoteSystemDiscovery_GetNetDomain\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string73 = /.{0,1000}Discovery_RemoteSystemDiscovery_GetNetDomainController\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string74 = /.{0,1000}Discovery_SecuritySoftwareDiscovery_ListAVByTasklist\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string75 = /.{0,1000}Discovery_SystemNetworkConnectionsDiscovery_GetPublicIP\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string76 = /.{0,1000}Discovery_SystemUserDiscovery_GetLastLoggedOn\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string77 = /.{0,1000}Discovery_SystemUserDiscovery_GetLoggedOnLocal\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string78 = /.{0,1000}DomainTrustDiscovery_PowerView\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string79 = /.{0,1000}dswmiexec\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string80 = /.{0,1000}EfsPotato\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string81 = /.{0,1000}Eternalblue\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string82 = /.{0,1000}Execution_CommandAndScriptingInterpreter_UploadAndExec\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string83 = /.{0,1000}Execution_UserExecution_CallbackCreateThreadpoolWait\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string84 = /.{0,1000}Execution_UserExecution_CallbackCreateTimerQueue\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string85 = /.{0,1000}Execution_UserExecution_CallbackEnumChildWindows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string86 = /.{0,1000}Execution_UserExecution_CallbackEnumWindows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string87 = /.{0,1000}Execution_UserExecution_DirectConnectReverseHTTPS\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string88 = /.{0,1000}Execution_UserExecution_DirectConnectReverseTCPRc4\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string89 = /.{0,1000}Execution_UserExecution_FakePPID\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string90 = /.{0,1000}Execution_UserExecution_LinuxBaseShellcodeLoader\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string91 = /.{0,1000}Execution_UserExecution_LinuxSelfGuardLoader\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string92 = /.{0,1000}Execution_UserExecution_NtCreateSection\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string93 = /.{0,1000}Execution_UserExecution_Syscall_inject\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string94 = /.{0,1000}Execution_UserExecution_VSSyscallProject\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string95 = /.{0,1000}FakePPID\..{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string96 = /.{0,1000}filemsf\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string97 = /.{0,1000}GeneratesShellcodeFromPEorDll.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string98 = /.{0,1000}GetWindowsCredentials\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string99 = /.{0,1000}http:\/\/vpsip:28888.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string100 = /.{0,1000}HttpProxyScan_Log4J2\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string101 = /.{0,1000}InitialAccess_SpearphishingAttachment_FakeWordDoc\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string102 = /.{0,1000}InitialAccess_SpearphishingAttachment_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string103 = /.{0,1000}Invoke\-S4U\-persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string104 = /.{0,1000}Invoke\-Service\-persistence\.ps1.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string105 = /.{0,1000}Ladon\-N20\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string106 = /.{0,1000}Ladon\-N40\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string107 = /.{0,1000}LateralMovement_.{0,1000}_Exploit.{0,1000}\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string108 = /.{0,1000}LateralMovement_ExploitationOfRemoteServices_AuxiliaryMs17010\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string109 = /.{0,1000}LateralMovement_ExploitationOfRemoteServices_MS17010\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string110 = /.{0,1000}LateralMovement_Other_Ladon\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string111 = /.{0,1000}LateralMovement_PassTheHash_ByInvokeWMIExec\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string112 = /.{0,1000}LateralMovement_PassTheHash_ByWmi\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string113 = /.{0,1000}LateralMovement_PassTheTicket_ByPsexec\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string114 = /.{0,1000}LateralMovement_PassTheTicket_BySharpwmi\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string115 = /.{0,1000}LateralMovement_PassTheTicket_ByWmi\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string116 = /.{0,1000}laZagne\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string117 = /.{0,1000}MDSDLL_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string118 = /.{0,1000}MDSDLL_x86\.dll.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string119 = /.{0,1000}mimikatz_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string120 = /.{0,1000}mimikatz_x86\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string121 = /.{0,1000}MimikatzByPowerShellForDomain\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string122 = /.{0,1000}MimikatzOnLocal\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string123 = /.{0,1000}mitmdump\s\-.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string124 = /.{0,1000}msf\-json\-rpc\..{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string125 = /.{0,1000}MsfModule.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string126 = /.{0,1000}msfmodule\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string127 = /.{0,1000}MsfModuleAsFunction.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string128 = /.{0,1000}nextnet\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string129 = /.{0,1000}Persistence_AccountManipulation_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string130 = /.{0,1000}Persistence_Guard_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string131 = /.{0,1000}Persistence_LogonScripts_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string132 = /.{0,1000}Persistence_NewService_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string133 = /.{0,1000}Persistence_OfficeApplicationStartup_OfficeTest\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string134 = /.{0,1000}Persistence_Other_WindowsLibraryMs\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string135 = /.{0,1000}Persistence_RegistryRunKeys_SharpHide\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string136 = /.{0,1000}Persistence_RegistryRunKeys_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string137 = /.{0,1000}Persistence_ScheduledTask_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string138 = /.{0,1000}Persistence_WinlogonHelperDLL_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string139 = /.{0,1000}portScanWithService\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string140 = /.{0,1000}portScanWithService\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string141 = /.{0,1000}PostMulitDomainSpider\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string142 = /.{0,1000}PostMulitMsfGetDomainInfoByBloodHound\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string143 = /.{0,1000}PostPowershellPowerViewAddNetUser\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string144 = /.{0,1000}PostPowershellPowerViewGetNetGroup\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string145 = /.{0,1000}PostPowershellPowerViewGetNetGroupMember\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string146 = /.{0,1000}PostPowershellPowerViewGetNetProcess\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string147 = /.{0,1000}PostPowershellPowerViewUserHunter\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string148 = /.{0,1000}PostRewMsfAuxiliaryCVE.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string149 = /.{0,1000}PostRewMsfExample\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string150 = /.{0,1000}PostRewMsfPostConfInfos\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string151 = /.{0,1000}PowerView_dev\.ps1.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string152 = /.{0,1000}PrivilegeEscalation_BypassUserAccountControl_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string153 = /.{0,1000}PrivilegeEscalation_EnumPatchExample_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string154 = /.{0,1000}PrivilegeEscalation_ExploitationForPrivilegeEscalation_CVE_2021_40449\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string155 = /.{0,1000}PrivilegeEscalation_ExploitationForPrivilegeEscalation_EfsPotato\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string156 = /.{0,1000}PrivilegeEscalation_ExploitationForPrivilegeEscalation_SweetPotato\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string157 = /.{0,1000}PrivilegeEscalation_ExploitationForPrivilegeEscalation_Windows\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string158 = /.{0,1000}PrivilegeEscalation_ProcessInjection_Getsystem\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string159 = /.{0,1000}ResourceDevelopment_EstablishAccounts_RGPerson\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string160 = /.{0,1000}ResourceDevelopment_Server_DNSLog\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string161 = /.{0,1000}ResourceDevelopment_Server_LDAPServer\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string162 = /.{0,1000}ResourceDevelopment_WebServices_TencentAPIGateway\.py.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string163 = /.{0,1000}SharpHide\-N.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string164 = /.{0,1000}SharpHound\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string165 = /.{0,1000}SharpHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string166 = /.{0,1000}SharpKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string167 = /.{0,1000}SharpSploit\.dll.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string168 = /.{0,1000}sharpwmi\-N.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string169 = /.{0,1000}sigthief\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string170 = /.{0,1000}SSHBruteForce\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string171 = /.{0,1000}SweetPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string172 = /.{0,1000}SweetPotato\-N.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string173 = /.{0,1000}VbulletinWidgetTemplateRce\.py.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string174 = /.{0,1000}viper\/.{0,1000}\.sock.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string175 = /.{0,1000}viper\-dev\.conf.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string176 = /.{0,1000}viperpython\-dev.{0,1000}/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string177 = /.{0,1000}viperpython\-main.{0,1000}/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string178 = /.{0,1000}viperzip\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
