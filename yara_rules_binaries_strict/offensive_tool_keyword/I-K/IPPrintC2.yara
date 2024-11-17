rule IPPrintC2
{
    meta:
        description = "Detection patterns for the tool 'IPPrintC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPPrintC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string1 = /\\"IPPrint\sC2\sServer\\"/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string2 = /\$C2ExternalIP/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string3 = /\$EncodedCommandExfil/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string4 = /\$IPPrintC2/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string5 = /\/IPPrintC2\.git/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string6 = /4c02774a5edb8a559beebcb64833177a893b49fb8eb9bfd2e650155a207c7ba7/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string7 = /826c1daf512bcd2152b6328fc55b1ed403ed41fd1a6fc1afa6e35f34e4b9f8bc/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string8 = /c\:\\temp\\c2\.pdf/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string9 = /d222451147be2256c701679975cd45993377032f1d6afff27533bafda10c2afa/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string10 = /Diverto\/IPPrintC2/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string11 = /Invoke\-DatatExfiltration/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string12 = /Invoke\-FileC2Output/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string13 = /Invoke\-ReadC2Output/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string14 = /IPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string15 = /Where\sdo\syou\swant\sto\sstore\sPDF\sC2\soutput\s/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
