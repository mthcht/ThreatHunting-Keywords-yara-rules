rule AutoPwnKey
{
    meta:
        description = "Detection patterns for the tool 'AutoPwnKey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoPwnKey"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string1 = /\sAddNewAdminUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string2 = /\sAddScriptToRegistry\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string3 = /\sAutoCrypt\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string4 = /\sChromeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string5 = /\scmstp_uac\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string6 = /\sDenyOutboundFirewall\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string7 = /\sDomainTrustRecon\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string8 = /\sEdgeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string9 = /\sEnumerateDCs\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string10 = /\sIdentifyDomainAdmins\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string11 = /\sIdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string12 = /\sKeyLogger\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string13 = /\sPersistViaScheduledTask\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string14 = /\sPortScanner\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string15 = /\sReverseShell\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string16 = /\sUnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string17 = /\sUnconstrainedDelegationCheck\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string18 = /\sUnhookNTDLL\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string19 = "\"ServiceName=\"\"bypassit\"" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string20 = /\/AddNewAdminUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string21 = /\/AddScriptToRegistry\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string22 = /\/AutoCrypt\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string23 = /\/AutoPwnKey\.git/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string24 = /\/c\snet\sgroup\s.{0,100}Domain\sAdmins.{0,100}\s\/domain\s\>\>\soutput\.txt/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string25 = /\/ChromeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string26 = /\/cmstp_uac\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string27 = /\/DenyOutboundFirewall\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string28 = /\/DomainTrustRecon\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string29 = /\/EdgeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string30 = /\/EnumerateDCs\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string31 = /\/IdentifyDomainAdmins\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string32 = /\/IdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string33 = /\/KeyLogger\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string34 = /\/PersistViaScheduledTask\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string35 = /\/PortScanner\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string36 = /\/ReverseShell\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string37 = /\/UnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string38 = /\/UnhookNTDLL\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string39 = /\\AddNewAdminUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string40 = /\\AddScriptToRegistry\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string41 = /\\AutoCrypt\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string42 = /\\AutoPwnKey\-main/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string43 = /\\ChromeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string44 = /\\cmstp_uac\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string45 = /\\Crypttest\\.{0,100}\.encrypted/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string46 = /\\DenyOutboundFirewall\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string47 = /\\Documents\\Crypttest\\/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string48 = /\\DomainTrustRecon\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string49 = /\\EdgeDump\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string50 = /\\EnumerateDCs\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string51 = /\\IdentifyDomainAdmins\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string52 = /\\IdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string53 = /\\KeyLogger\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string54 = /\\PersistViaScheduledTask\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string55 = /\\PortScanner\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string56 = /\\ReverseShell\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string57 = /\\UnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string58 = /\\UnconstrainedDelegationCheck\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string59 = /\\UnhookNTDLL\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string60 = "0d0b7a5276ebfefb28407800d2ba37f5102c9917cacaac5b265df55f95759b14" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string61 = "2ffc8e93d89c9f9c090df5e44eb7921633c6954176b06183acbd459369a919b8" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string62 = "63da55b370a27e54e02b3d7b56515734dd12a930faec455beaf2c6e9bcbfab32" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string63 = "7b6b043f894bb0f34244c9cb88dc1cf801d16010817d51fe7c1f6be2af6b91bf" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string64 = "91a579342f9fd24373e7d273db24aa0f936c9cb7929a3f0dcee357a84173e1eb" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string65 = "9566f875d51e0259d3d64d6a20250ffaffd527e17e060cde0b77dea42a10a13e" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string66 = "9fc04e375ecd2d91dff8a0cd64fc10852bdca276699fd6d633b4e5537b7d5c5a" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string67 = "a83ba2c435fcf714eda4cc84cde9a72c8214157eba585b2debba0f9274af0e8f" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string68 = /AutoCrypt_Password\.txt/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string69 = "AutoPwnKey Agent Manager" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string70 = /AutoPwnKey\.AgentManager/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string71 = /autopwnkey\.db/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string72 = "AutoPwnKey-agent" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string73 = "AutoPwnKey-server" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string74 = "AutoPwnKey-server/logs" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string75 = "b5df5bd38cb4be2db37d159e001de5e5b6e9bbfc0f0e90a59827fd6290a1f05f" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string76 = "b7fa937e1b42914b6dee7a038520775e09532babd8c296a8e86db0faab66236c" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string77 = "c2109f44079ae2c753b2f2763562c141d7db57a33649baa7086b204109a98d25" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string78 = "c46f4d7407e46fd600a3e400128c22a599bf7152068af8304fbd47c91ca39698" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string79 = "c9d16fdf0e5aa489bd8c6f0d930a8c25d9ad665583adb7780bc261b4df9c639c" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string80 = "CroodSolutions/AutoPwnKey" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string81 = /curl\s\-L\s\-o\sahk\.exe\shttps\:\/\/github\.com\/AutoHotkey\// nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string82 = "d15d3424eed0a69503213f2c7261d831f676b51383f4a10924bee81ce0e47d49" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string83 = "deda1e50aa7963be239c0e43bb7dcd05014b1e048f89fe08f537ef0ce19afe58" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string84 = /Desktop\\AutoCrypt_Password\.txt/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string85 = /DiscoverBasicHostRecon\.ahk/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string86 = "e6d5759ff74805dfb7e2b133493111a1a265e06d4dfcee80302048b6a173334a" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string87 = "ef105cd1be00cf14b44173895a2610f5e5ed4d06390494be20bf7175215ea851" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string88 = "KeyLogger data received" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string89 = /Keylogger\sstarting\.\.\./ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string90 = /Keylogger\sstopping\.\.\./ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string91 = /keylogger_output_.{0,100}\.txt/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string92 = "Monitor KeyLogger output from a specific agent" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string93 = /netsh\sadvfirewall\sfirewall\sadd\srule\s.{0,100}Deny\sOutbound\sfor\s/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string94 = /self\.keylogger_widget/ nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string95 = "Starting AddUserToAdminGroup for user:" nocase ascii wide
        // Description: red teaming framework and testing tool using AutoHotKey
        // Reference: https://github.com/CroodSolutions/AutoPwnKey
        $string96 = "Starting AutoPwnKey Port Scanner at" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
