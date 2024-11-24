rule Supremo
{
    meta:
        description = "Detection patterns for the tool 'Supremo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supremo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string1 = " start SupremoService" nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string2 = /\sSupremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string3 = /\/Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string4 = /\\\\\.\\pipe\\Supremo/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string5 = /\\Control\\SafeBoot\\Network\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string6 = /\\CurrentControlSet\\Services\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string7 = /\\Program\sFiles\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string8 = /\\ProgramData\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string9 = /\\SOFTWARE\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string10 = /\\Software\\Supremo\\Printer\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string11 = /\\SOFTWARE\\WOW6432Node\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string12 = /\\Supremo\sRemote\sPrinter\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string13 = /\\Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string14 = /\\SUPREMO\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string15 = /\\Supremo_Client_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string16 = /\\Supremo_Helper_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string17 = /\\Supremo_Service/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string18 = /\\SupremoHelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string19 = /\\SupremoRemoteDesktop\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string20 = /\\Temp\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string21 = "application/x-supremo" nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string22 = /HKCR\\supremo\\shell\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string23 = "supremo remote control" nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string24 = /Supremo\.00\.Client\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string25 = /Supremo\.00\.FileTransfer\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string26 = /Supremo\.exe\s/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string27 = /supremogw.{0,100}\.nanosystems\.it/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string28 = /supremohelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string29 = /SupremoRemoteDesktop\\History\.txt/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string30 = /SupremoService\.00\.Service\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string31 = /SupremoService\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: https://www.supremocontrol.com
        $string32 = /SupremoSystem\.exe/ nocase ascii wide
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
