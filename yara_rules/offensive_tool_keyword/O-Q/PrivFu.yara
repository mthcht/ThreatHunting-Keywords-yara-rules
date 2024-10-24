rule PrivFu
{
    meta:
        description = "Detection patterns for the tool 'PrivFu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivFu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string1 = /\.exe\s\-i\s\-c\spowershell\s\-e\snetlogon/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string2 = /\.exe\s\-m\sexec\s\-c\s\"whoami\s\/priv/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string3 = /\.exe\s\-m\sexec\s\-s\s\-e\sS\-1\-5\-20/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string4 = /\.exe\s\-m\sfind\s\-r\stcb/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string5 = /\.exe\s\-m\ssid\s\-l\s\-s\sS\-1\-5\-18/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string6 = /\/BackgroundShell\.exe/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string7 = /\/DesktopShell\.exe/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string8 = /\/PrintSpoofer\.exe/ nocase ascii wide
        // Description: Kernel Mode WinDbg extension for token privilege edit
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string9 = /\/PrivEditor\.dll/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string10 = /\/PrivFu\.git/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string11 = /\/SeAuditPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string12 = /\/SeBackupPrivilegePoC\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string13 = /\/SecondaryLogonVariant\.exe/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string14 = /\/SwitchPriv\.exe/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string15 = /\/TokenAssignor\.exe/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string16 = /\/TokenDump\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string17 = /\/TokenStealing/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string18 = /\/TokenStealing\.exe/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string19 = /\/UserRightsUtil\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string20 = /\/WfpTokenDup\.exe/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string21 = /\[\+\]\sGot\sa\sS4U\slogon\stoken\s\(Handle\s\=\s/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string22 = /\[\+\]\sHKLM\\\\SAM\sis\ssaved\ssuccessfully/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string23 = /\[\+\]\sImpersonation\sas\ssmss\.exe/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string24 = /\[\+\]\sImpersonation\sas\swinlogon\.exe\sis\ssuccessful/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string25 = /\[\+\]\sSeTcbPrivilege\sis\senabled\ssuccessfully/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string26 = /\\\\\.\\pipe\\PrivFu/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string27 = /\\\\HackSysExtremeVulnerableDriver/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string28 = /\\BackgroundShell\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string29 = /\\CreateTokenVariant\.exe/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string30 = /\\DesktopShell\.exe/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string31 = /\\NamedPipeClient\.exe/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string32 = /\\NamedPipeClient\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string33 = /\\PrintSpoofer\.cs/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string34 = /\\PrintSpoofer\.exe/ nocase ascii wide
        // Description: Kernel Mode WinDbg extension for token privilege edit
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string35 = /\\PrivEditor\.dll/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string36 = /\\PrivEditor\\/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string37 = /\\PrivFu\.txt/ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string38 = /\\S4uDelegator\./ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string39 = /\\SeAuditPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string40 = /\\SeBackupPrivilegePoC\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string41 = /\\SecondaryLogonVariant\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string42 = /\\SeRestorePrivilegeTestFile\.txt/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string43 = /\\SwitchPriv\.exe/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string44 = /\\SwitchPriv\.sln/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string45 = /\\TokenAssignor\.exe/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string46 = /\\TokenDump\.cs/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string47 = /\\TokenDump\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string48 = /\\TokenDump\.exe/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string49 = /\\TokenDump\.sln/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string50 = /\\TokenStealing\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string51 = /\\TrustExec\.exe/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string52 = /\\TrustExec\.exe/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string53 = /\\UserRightsUtil\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string54 = /\\WfpTokenDup\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string55 = /\>CreateAssignTokenVariant\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string56 = /\>CreateImpersonateTokenVariant\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string57 = /\>DebugInjectionVariant\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string58 = /\>DebugUpdateProcVariant\</ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string59 = /\>EfsPotato\</ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string60 = /\>NamedPipeImpersonation\</ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string61 = /\>PrintSpoofer\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string62 = /\>RestoreServiceModificationVariant\</ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string63 = /\>S4uDelegator\</ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string64 = /\>S4ULogonShell\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string65 = /\>SeAuditPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string66 = /\>SeBackupPrivilegePoC\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string67 = /\>SecondaryLogonVariant\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string68 = /\>SeCreatePagefilePrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string69 = /\>SeCreateTokenPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string70 = /\>SeDebugPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string71 = /\>SeRestorePrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string72 = /\>SeSecurityPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string73 = /\>SeShutdownPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string74 = /\>SeSystemEnvironmentPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string75 = /\>SeTakeOwnershipPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string76 = /\>SeTcbPrivilegePoC\</ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string77 = /\>SeTrustedCredManAccessPrivilegePoC\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string78 = /\>TakeOwnershipServiceModificationVariant\</ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string79 = /\>TcbS4uImpersonationVariant\</ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string80 = /\>TokenStealing\</ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string81 = /\>UserRightsUtil\</ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string82 = /\>WfpTokenDup\</ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string83 = /03c1585bf3e2e6013e2f8cd34d34eedc9c4195dc72628a779db43cdd16b1a7cc/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string84 = /04FC654C\-D89A\-44F9\-9E34\-6D95CE152E9D/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string85 = /0817eb1eeb9b25430a2666b8bd637d83e8c3c10ba14a8f6db0b0d3147ce3ab4a/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string86 = /0A78E156\-D03F\-4667\-B70E\-4E9B4AA1D491/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string87 = /0CC923FB\-E1FD\-456B\-9FE4\-9EBA5A3DC2FC/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string88 = /1460d78f92f67929b451732af1d24752026b9d91fd85faec196460f7d4cac9f9/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string89 = /182e81c156f653dea62d0aaa97c23887cf99907e16503654bc1fb55405073903/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string90 = /1c14d0d58efdd3244a1fd4398ef9c65e96bfe4faccc168e7ace84728da908d9e/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string91 = /1cad3b4c47e6f3d4f97c3299b8d1498bd2a4cd3c7eb26f255f693bbcd46fe516/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string92 = /1eb987e0\-23a5\-415e\-9194\-cd961314441b/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string93 = /2297A528\-E866\-4056\-814A\-D01C1C305A38/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string94 = /2AD3951D\-DEA6\-4CF7\-88BE\-4C73344AC9DA/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string95 = /2b0ae5d810f64cc33f7f5df193aa56c3f39d85b0447242491da024b0a1b1a45a/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string96 = /2B704D89\-41B9\-4051\-A51C\-36A82ACEBE10/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string97 = /2fc2426035652b2ecfc952407b4d22ab78b9ae554da8f2466bccf48fa2a3870a/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string98 = /36f45e69b0d6ce0325647dbe792399267ce73266f5cc72ca6f2bd845ba5513c9/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string99 = /410D25CC\-A75E\-4B65\-8D24\-05FA4D8AE0B9/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string100 = /425e044558eb1b4ee187d3b222aa1c0cc62d760322d9d13c18c2aa7a3204c50d/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string101 = /4349B8A8\-F17B\-44D5\-AE4D\-21BE9C9D1573/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string102 = /449CE476\-7B27\-47F5\-B09C\-570788A2F261/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string103 = /44d1e4dd465f3d374a0dc3433672aecd70ec9b64ea0e8c59a71a4d9166cc52aa/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string104 = /487E2246\-72F1\-4BD3\-AA8A\-A9B8C79C9F28/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string105 = /4b9dbffee430d20fd696391f01a748edea00b6feaef8589f3ff33b01abe1bca8/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string106 = /4C496D14\-FA2B\-428C\-BB15\-20B25BAB9B73/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string107 = /4C574B86\-DC07\-47EA\-BB02\-FD50AE002910/ nocase ascii wide
        // Description: Kernel Mode WinDbg extension for token privilege edit
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string108 = /4C61F4EA\-D946\-4AF2\-924B\-7A873B4D964B/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string109 = /51650d59ffa17366d2190e05eb58c94975156449fce424f47cea328edcb561bf/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string110 = /522b08b506889d8b54c8e93b2c41e799bb49da1dde0176a2a97f52125a63898e/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string111 = /536361a703d684f914e9c94d99ef45a18cba34ff7f2bb045752afe2534b904fe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string112 = /5745976E\-48A7\-4F79\-9BAA\-82D1F43D1261/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string113 = /5ecc5632202031a45845046c5c8287530dbbdfb724af5ee412063865cf37d58e/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string114 = /6298ad100c27577260513c1e8045443ee1630de94b2aee6f0339d25e91ad6186/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string115 = /6302105A\-80BB\-4987\-82EC\-95973911238B/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string116 = /67830961a8dee229b3446833b1c4a2b6228ed3b949ee481ea3681bdb4a5f71c1/ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string117 = /6997ce0fe65943279981c444857b406b20ebe1736442c6f4c75dae0dbd7c9549/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string118 = /6A3F2F04\-3E48\-4E21\-9AB8\-0CA0998A2D01/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string119 = /6c1b2c4d2b69d38a438af8d9f8c8aa411111d35b03b988f7a3dc4b9aec0605c6/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string120 = /6c4696003fe73566fe0a2c42a4bbd3171f576fb8b0175fbcc13381109fd632b2/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string121 = /6E0D8D5C\-7B88\-4C77\-A347\-34F8B0FD2D75/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string122 = /6F99CB40\-8FEF\-4B63\-A35D\-9CEEC71F7B5F/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string123 = /733dafd81c4cd0b7f5daa7b44a543a73a7e68587c006523c5ba12b017b1a2e69/ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string124 = /7607CC54\-D49D\-4004\-8B20\-15555D58C842/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string125 = /83049a99591f84b7f50db732ccc8412b4e9b6e3bb188c00790880342d1e94cf0/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string126 = /86053063d021c510dd6ef09ac6e21ad5f6f6cb7081c53f8d5809a8c10eb562a2/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string127 = /86c9741c985ac8e026364c31af6c288c88e4d36d34321be5adb26c595d3f6675/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string128 = /8B723CB2\-017A\-4CB6\-B3E6\-C26E9F1F8B3C/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string129 = /8bdd98ae5c8a162a4292fe799be541c124775a34b31516789044c792ca6b4220/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string130 = /8DED0EC8\-3611\-4481\-88FC\-14B82531FD2B/ nocase ascii wide
        // Description: enable or disable specific token privileges for a process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string131 = /8F208DB9\-7555\-46D5\-A5FE\-2D7E85E05CAA/ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string132 = /9027a0ddabd5e6267e365572f404e2f0019a02d3f91f8434ca674765c46f4f22/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string133 = /95BB9D5E\-260F\-4A70\-B0FA\-0757A94EF677/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string134 = /9634c75573a4d30c694112af8658cd6cac1c265ac46ff27f20baf6714c1b9428/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string135 = /9A374E66\-70B5\-433D\-8D7D\-89E3F8AC0617/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string136 = /9ba444580d4d5eb6f4b020f68ee625a36b6c5b5210c128f148e4de929da0508d/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string137 = /9E36AE6E\-B9FD\-4B9B\-99BA\-42D3EACD7506/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string138 = /a076c96c9713804c8b2f26ffc09b931339be9f35227c749fb21fc9b574f97051/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string139 = /A318BEE3\-2BDB\-41A1\-BE56\-956774BBC12B/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string140 = /a4cba56cfdae80bcfad6745fb2ea7ffe407534d449414b198b5eea43239ba43c/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string141 = /a7fcb2adaf096a7aeab2cba92fb1c92091302b2dd18219ee4ec1aedd67383efc/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string142 = /af37338c3451aa6794a1fb6111c22cc9931d3a0d97cd9aa8326702d8ac87ac07/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string143 = /b1dfc417ce748ffeec95311109dae13142c638e58cfa86eb6e5a0865082428aa/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string144 = /B35266FB\-81FD\-4671\-BF1D\-CE6AEF8B8D64/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string145 = /b7651de4fa3eef93541b646ccef946ab0ea464ea937ab32e5c660cff82a808d9/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string146 = /B8FF9629\-B4CE\-4871\-A2CD\-8E6D73F6DF9E/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string147 = /bdf8e7a1e24bb1b99ff06801cabc7df8ab4f12684d9e349aeb6aa8c4cf891edd/ nocase ascii wide
        // Description: Kernel Mode WinDbg extension for token privilege edit
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string148 = /be1c2b305595e848c387fc8aa5c7ca24fc8104c21aaaad5c3c9fef50e57668db/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string149 = /bef212d845d5f4f1ed2413b300548cc9181641fe773a25c7a0f7ea021a50bb40/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string150 = /cb4591d160b6943c4af0374fa661a3f754682cc92c92f5b2382ac006ad8dad3b/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string151 = /ccadb82e7bf79fc75084693b04d8679aebfc06be44ff4ed70fddecb5680fbc37/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string152 = /ccf7f162f257c3cf8286009cfcd0869bc7bd78d38635f1b473d89c737b8fd2ff/ nocase ascii wide
        // Description: Tool to execute token assigned process
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string153 = /cec47972c55b72e21161ef0c26125d86c544b5aa1d95915347220935412a591a/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string154 = /cfc253a8282a4065ff78c11a6495632991b2651e12203dbbb11bdb21bc2cb74f/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string155 = /CreateAssignTokenVariant\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string156 = /CreateImpersonateTokenVariant\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string157 = /d201ba52fb577509eefe1e9e780fdcc45776a746ac6dbf913a315b34eb2134c7/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string158 = /d243029c00185f99446544ba5bb34e6c3002edd90603f4dbff8e2070c207e80c/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string159 = /d26f0536e66e9973021e728b5803d7ddeeb07f0fc4e4e1382dbda6384718cf37/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string160 = /d32e6555888090a428d9d01ea171521419948e23f7362d15dc9e5fa2f14c3440/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string161 = /D52AB3F8\-15D3\-49C5\-9EAC\-468CDF65FB22/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string162 = /d6db60417e9ca985a89101f7aa8b06a021fde4f5f7f7a58fa21b048008df2e56/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string163 = /daem0nc0re\/PrivFu/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string164 = /DebugInjectionVariant\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string165 = /DebugUpdateProcVariant\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string166 = /e95cf71f61072940249aa53e3816205ba0ad7d5fe5611344bbecfc83f9e6f86a/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string167 = /ea5dff2a0ded86187908ea824cf142496825b8eecc469c4351cb1cb99a36a07f/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string168 = /ee09b69221509034225e37497bc6bc00498fa914adb00b0fad89b39443a70db6/ nocase ascii wide
        // Description: inspect token information
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string169 = /ee21ea772594f2e49cabc02176dd935af45c0573a90ff3b10957a4f98c804e37/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string170 = /eead28e2afe2070b6a3f40d874c53870b13c705e90cb60520f3f52aca2ad8cf8/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string171 = /EfsPotato\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string172 = /f0e0e7cd303662f47ec9f5df7778faa0ff2a15110d21f5afbea031c6b02f8d9b/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string173 = /f285e0f2aa29132c803b6f135bcabd7b93c0f91d7340735f8c60ae90ad4f3f8e/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string174 = /f44f9465e65c790de6dd15f47e19e9f555c0e9aefa0194127ebea6e89dabcf0d/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string175 = /f92b1b55d9d3ab4cf2eafed6dfbbac7ff6db4d07d8902cf57e625b6adaf02611/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string176 = /FAFE5A3C\-05BC\-4B6F\-8BA4\-2B95027CBFEA/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string177 = /FCE55626\-886B\-4D3B\-B7AA\-92CECDA91514/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string178 = /HijackShellLib\.dll/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string179 = /NamedPipeImpersonation\.cs/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string180 = /NamedPipeImpersonation\.exe/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string181 = /NamedPipeImpersonation\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string182 = /printspoofer\.exe/ nocase ascii wide
        // Description: Kernel Mode WinDbg extension for token privilege edit
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string183 = /PrivEditor\s\-\sKernel\sMode\sWinDbg\sextension\sfor\stoken\sprivilege\sedit/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string184 = /PrivEditor\.dll/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string185 = /PrivFu\\PowerOfTcb/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string186 = /PrivFu\-main\.zip/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string187 = /PrivFu\-master/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string188 = /PrivFuPipeClient\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string189 = /RestoreServiceModificationVariant\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string190 = /S4uDelegator\./ nocase ascii wide
        // Description: perform S4U logon with SeTcbPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string191 = /S4uDelegator\.exe/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string192 = /S4ULogonShell\.exe/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string193 = /S4Util\s\-\sHelp\sfor\s\"enum\"\scommand/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string194 = /SeCreatePagefilePrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string195 = /SeCreateTokenPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string196 = /SeDebugPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string197 = /SeRestorePrivilegePoC\.exe/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string198 = /ServiceShell\s\-\sPoC\sto\screate\sService\sLogon\sprocess/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string199 = /ServiceShell\s\-\sPoC\sto\screate\sService\sLogon\sprocess/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string200 = /SeSecurityPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string201 = /SeShutdownPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string202 = /SeSystemEnvironmentPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string203 = /SeTakeOwnershipPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string204 = /SeTcbPrivilegePoC\.exe/ nocase ascii wide
        // Description: PoCs for sensitive token privileges such SeDebugPrivilege
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string205 = /SeTrustedCredManAccessPrivilegePoC\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string206 = /SwitchPriv\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string207 = /TakeOwnershipServiceModificationVariant\.exe/ nocase ascii wide
        // Description: get SYSTEM integrity level by abusing arbitrary kernel write vulnerability and token privileges
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string208 = /TcbS4uImpersonationVariant\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string209 = /TokenDump\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string210 = /TokenStealing\.cs/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string211 = /TokenStealing\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string212 = /TokenViewer\.exe/ nocase ascii wide
        // Description: execute process as NT SERVICE\TrustedInstaller group account
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string213 = /TrustExec\.exe\s\-m\sexec/ nocase ascii wide
        // Description: manage user right without secpol.msc
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string214 = /UserRightsUtil\.exe\s\-m\senum/ nocase ascii wide
        // Description: SeTcbPrivilege exploitation
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string215 = /VirtualShell\s\-\sPoC\sto\screate\svirtual\saccount\sprocess/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu
        $string216 = /WfpTokenDup\.exe\s\-/ nocase ascii wide
        // Description: ArtsOfGetSystem privesc tools
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string217 = /WfpTokenDup\.exe/ nocase ascii wide

    condition:
        any of them
}
