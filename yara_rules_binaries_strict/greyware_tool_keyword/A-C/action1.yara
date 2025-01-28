rule action1
{
    meta:
        description = "Detection patterns for the tool 'action1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "action1"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string1 = /\/action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string2 = /\\Action1\\7z\.dll/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string3 = /\\Action1\\Agent\\Certificate/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string4 = /\\Action1\\CrashDumps/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string5 = /\\Action1\\package_downloads/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string6 = /\\Action1\\scripts\\Run_PowerShell_/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string7 = /\\action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string8 = /\\ACTION1_AGENT\.EXE\-/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string9 = /\\action1_log_.{0,100}\.log/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string10 = /\\Windows\\Action1\\scripts\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string11 = "_renamed_by_Action1" nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string12 = /a1\-server\-prod\-even\.action1\.com/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string13 = "Action1 Corporation" nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string14 = "Action1 Endpoint Security" nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string15 = /Action1.{0,100}\'DestinationPort\'\>22543/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string16 = /Action1\\batch_data\\Run_Script__/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string17 = /Action1\\first_install\.tmp/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string18 = /Action1\\what_is_this\.txt/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string19 = /action1_agent\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string20 = /action1_agent\.exe\.connection/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string21 = /action1_remote\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string22 = /action1_update\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string23 = /C\:\\Windows\\Action1\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string24 = /C\:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Action1/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string25 = "'Company'>Action1 Corporation" nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string26 = /CurrentControlSet\\Services\\A1Agent/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string27 = /https\:\/\/app\.action1\.com\/agent\/.{0,100}\/Windows\/.{0,100}\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string28 = /InventoryApplicationFile\\action1_agent\.ex/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string29 = /InventoryApplicationFile\\action1_remote\.e/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string30 = /server\.action1\.com/ nocase ascii wide
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
