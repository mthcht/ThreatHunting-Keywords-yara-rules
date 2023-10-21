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
        $string1 = /\/\.msf4\// nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string2 = /\/hackerid\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string3 = /\/loot_default\/.*\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string4 = /\/loot_default\/.*\.ps1/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string5 = /\/loot_default\/.*\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string6 = /\/RGPerson\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string7 = /\/root\/viper\// nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string8 = /\/root\/viper\/dist/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string9 = /\/SHELLCODELOADER/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string10 = /\/stinger_client\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string11 = /\/viper\.conf/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string12 = /\/viper\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string13 = /\/viper\.sln/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string14 = /\/viper\/Docker\// nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string15 = /\/viper\/Docker\/nginxconfig\/htpasswd/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string16 = /\/vipermsf/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string17 = /\/viperpython/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string18 = /\/viperpython\.git/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string19 = /_GetNetLoggedon\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string20 = /a7469955bff5e489d2270d9b389064e1/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string21 = /auto_pass_the_hash\./ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string22 = /Bot_MSF_Exp_.*\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string23 = /Bot_Python_Poc_Log4j2_VMwareHorizon\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string24 = /BrowserBookmarkDiscovery_BrowserHistory\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string25 = /BrowserGhost\-N.*\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string26 = /cd40dbcdae84b1c8606f29342066547069ed5a33/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string27 = /Collection_ArchiveCollectedData_ArchiveViaCustomMethod\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string28 = /Collection_ArchiveCollectedData_ArchiveViaCustomMethod_7z\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string29 = /CommandAndControl_.*\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string30 = /CredentialAccess_CredentialDumping_BrowserDataCSharp\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string31 = /CredentialAccess_CredentialDumping_KiwiOnLocal\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string32 = /CredentialAccess_CredentialDumping_SunLogin\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string33 = /CredentialAccess_CredentialDumping_WindowsHashDump\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string34 = /CredentialAccess_CredentialDumping_WindowsWDigestEnable\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string35 = /CredentialAccess_CredentialInFiles_BrowserData\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string36 = /CredentialAccess_CredentialInFiles_WindowsSoftware\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string37 = /CredentialAccess_InputCapture_CredUIPromptForWindowsCredentialsW\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string38 = /DefenseEvasion_CodeSigning_PeSigningAuthHijack\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string39 = /DefenseEvasion_CodeSigning_StolenMircosoftWindowsSignature\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string40 = /DefenseEvasion_ProcessInjection_CobaltStrikeOnline\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string41 = /DefenseEvasion_ProcessInjection_CsharpAssemblyLoader\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string42 = /DefenseEvasion_ProcessInjection_CsharpAssemblyLoaderPlus\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string43 = /DefenseEvasion_ProcessInjection_ExampleModule\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string44 = /DefenseEvasion_ProcessInjection_PeLoader\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string45 = /DefenseEvasion_ProcessInjection_PowershellRunInMem\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string46 = /DefenseEvasion_ProcessInjection_ProcessHandle\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string47 = /DefenseEvasion_ProcessInjection_PythonRunInMem\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string48 = /DefenseEvasion_ProcessInjection_SessionClone\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string49 = /DefenseEvasion_ProcessInjection_ShellcodeLoader\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string50 = /DefenseEvasion_ProcessInjection_WindowsSystem\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string51 = /DefenseEvasion_SubvertTrustControls_CloneSSLPem\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string52 = /DirectDLL_x64\.dll/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string53 = /DirectDLL_x86\.dll/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string54 = /Discovery_AccountDiscovery_GetNetDomainUser\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string55 = /Discovery_AccountDiscovery_PowerView\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string56 = /Discovery_ApplicationWindowDiscovery_EnumApplication\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string57 = /Discovery_Microphone_CallInfo\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string58 = /Discovery_Microphone_camera\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string59 = /Discovery_Microphone_record_mic\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string60 = /Discovery_NetworkServiceScanning_ARPScan\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string61 = /Discovery_NetworkServiceScanning_NbtScanByPython\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string62 = /Discovery_NetworkServiceScanning_NextnetByPE\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string63 = /Discovery_NetworkServiceScanning_PingByPython\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string64 = /Discovery_NetworkServiceScanning_PortScanByPython\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string65 = /Discovery_NetworkServiceScanning_PortScanWithServiceByPython\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string66 = /Discovery_NetworkShareDiscovery_PowerView\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string67 = /Discovery_PermissionGroupsDiscovery_PowerView\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string68 = /Discovery_QueryRegistry_GetDotNetVersions\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string69 = /Discovery_QueryRegistry_GetRDPPort\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string70 = /Discovery_RemoteSystemDiscovery_GetDomainIPAddress\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string71 = /Discovery_RemoteSystemDiscovery_GetNetComputer\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string72 = /Discovery_RemoteSystemDiscovery_GetNetDomain\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string73 = /Discovery_RemoteSystemDiscovery_GetNetDomainController\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string74 = /Discovery_SecuritySoftwareDiscovery_ListAVByTasklist\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string75 = /Discovery_SystemNetworkConnectionsDiscovery_GetPublicIP\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string76 = /Discovery_SystemUserDiscovery_GetLastLoggedOn\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string77 = /Discovery_SystemUserDiscovery_GetLoggedOnLocal\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string78 = /DomainTrustDiscovery_PowerView\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string79 = /dswmiexec\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string80 = /EfsPotato\-.*\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string81 = /Eternalblue\-.*\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string82 = /Execution_CommandAndScriptingInterpreter_UploadAndExec\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string83 = /Execution_UserExecution_CallbackCreateThreadpoolWait\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string84 = /Execution_UserExecution_CallbackCreateTimerQueue\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string85 = /Execution_UserExecution_CallbackEnumChildWindows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string86 = /Execution_UserExecution_CallbackEnumWindows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string87 = /Execution_UserExecution_DirectConnectReverseHTTPS\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string88 = /Execution_UserExecution_DirectConnectReverseTCPRc4\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string89 = /Execution_UserExecution_FakePPID\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string90 = /Execution_UserExecution_LinuxBaseShellcodeLoader\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string91 = /Execution_UserExecution_LinuxSelfGuardLoader\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string92 = /Execution_UserExecution_NtCreateSection\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string93 = /Execution_UserExecution_Syscall_inject\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string94 = /Execution_UserExecution_VSSyscallProject\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string95 = /FakePPID\./ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string96 = /filemsf\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string97 = /GeneratesShellcodeFromPEorDll/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string98 = /GetWindowsCredentials\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string99 = /http:\/\/vpsip:28888/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string100 = /HttpProxyScan_Log4J2\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string101 = /InitialAccess_SpearphishingAttachment_FakeWordDoc\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string102 = /InitialAccess_SpearphishingAttachment_Windows\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string103 = /Invoke\-S4U\-persistence\.ps1/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string104 = /Invoke\-Service\-persistence\.ps1/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string105 = /Ladon\-N20\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string106 = /Ladon\-N40\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string107 = /LateralMovement_.*_Exploit.*\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string108 = /LateralMovement_ExploitationOfRemoteServices_AuxiliaryMs17010\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string109 = /LateralMovement_ExploitationOfRemoteServices_MS17010\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string110 = /LateralMovement_Other_Ladon\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string111 = /LateralMovement_PassTheHash_ByInvokeWMIExec\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string112 = /LateralMovement_PassTheHash_ByWmi\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string113 = /LateralMovement_PassTheTicket_ByPsexec\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string114 = /LateralMovement_PassTheTicket_BySharpwmi\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string115 = /LateralMovement_PassTheTicket_ByWmi\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string116 = /laZagne\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string117 = /MDSDLL_x64\.dll/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string118 = /MDSDLL_x86\.dll/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string119 = /mimikatz_x64\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string120 = /mimikatz_x86\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string121 = /MimikatzByPowerShellForDomain\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string122 = /MimikatzOnLocal\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string123 = /mitmdump\s\-/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string124 = /msf\-json\-rpc\./ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string125 = /MsfModule/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string126 = /msfmodule\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string127 = /MsfModuleAsFunction/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string128 = /nextnet\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string129 = /Persistence_AccountManipulation_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string130 = /Persistence_Guard_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string131 = /Persistence_LogonScripts_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string132 = /Persistence_NewService_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string133 = /Persistence_OfficeApplicationStartup_OfficeTest\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string134 = /Persistence_Other_WindowsLibraryMs\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string135 = /Persistence_RegistryRunKeys_SharpHide\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string136 = /Persistence_RegistryRunKeys_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string137 = /Persistence_ScheduledTask_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string138 = /Persistence_WinlogonHelperDLL_Windows\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string139 = /portScanWithService\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string140 = /portScanWithService\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string141 = /PostMulitDomainSpider\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string142 = /PostMulitMsfGetDomainInfoByBloodHound\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string143 = /PostPowershellPowerViewAddNetUser\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string144 = /PostPowershellPowerViewGetNetGroup\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string145 = /PostPowershellPowerViewGetNetGroupMember\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string146 = /PostPowershellPowerViewGetNetProcess\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string147 = /PostPowershellPowerViewUserHunter\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string148 = /PostRewMsfAuxiliaryCVE.*\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string149 = /PostRewMsfExample\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string150 = /PostRewMsfPostConfInfos\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string151 = /PowerView_dev\.ps1/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string152 = /PrivilegeEscalation_BypassUserAccountControl_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string153 = /PrivilegeEscalation_EnumPatchExample_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string154 = /PrivilegeEscalation_ExploitationForPrivilegeEscalation_CVE_2021_40449\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string155 = /PrivilegeEscalation_ExploitationForPrivilegeEscalation_EfsPotato\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string156 = /PrivilegeEscalation_ExploitationForPrivilegeEscalation_SweetPotato\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string157 = /PrivilegeEscalation_ExploitationForPrivilegeEscalation_Windows\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string158 = /PrivilegeEscalation_ProcessInjection_Getsystem\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string159 = /ResourceDevelopment_EstablishAccounts_RGPerson\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string160 = /ResourceDevelopment_Server_DNSLog\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string161 = /ResourceDevelopment_Server_LDAPServer\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string162 = /ResourceDevelopment_WebServices_TencentAPIGateway\.py/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string163 = /SharpHide\-N.*\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string164 = /SharpHound\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string165 = /SharpHound\.ps1/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string166 = /SharpKatz\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string167 = /SharpSploit\.dll/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string168 = /sharpwmi\-N.*\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string169 = /sigthief\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string170 = /SSHBruteForce\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string171 = /SweetPotato\.exe/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string172 = /SweetPotato\-N.*\.exe/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string173 = /VbulletinWidgetTemplateRce\.py/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string174 = /viper\/.*\.sock/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string175 = /viper\-dev\.conf/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string176 = /viperpython\-dev/ nocase ascii wide
        // Description: viperpython backend - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/viperpython
        $string177 = /viperpython\-main/ nocase ascii wide
        // Description: vipermsf Metasploit - Viper is a graphical intranet penetration tool which modularizes and weaponizes the tactics and technologies commonly used in the process of Intranet penetration
        // Reference: https://github.com/FunnyWolf/vipermsf
        $string178 = /viperzip\.exe/ nocase ascii wide

    condition:
        any of them
}