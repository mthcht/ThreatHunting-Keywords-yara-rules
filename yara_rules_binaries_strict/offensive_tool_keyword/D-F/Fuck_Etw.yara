rule Fuck_Etw
{
    meta:
        description = "Detection patterns for the tool 'Fuck-Etw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fuck-Etw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string1 = /\/etw\-fuck\.cpp/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string2 = /\/etw\-fuck\.exe/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string3 = /\/Fuck\-Etw\.git/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string4 = /\[\#\]\sReady\sFor\sETW\sPatch\./ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string5 = /\[\+\]\sETW\sPatched.{0,100}\sNo\sLogs\sNo\sCrime\s\!/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string6 = /\[i\]\sHooked\sNtdll\sBase\sAddress\s\:\s/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string7 = /\[i\]\sUnhooked\sNtdll\sBase\sAddress\:\s/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string8 = /\\etw\-fuck\.cpp/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string9 = /\\etw\-fuck\.exe/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string10 = "40E7714F-460D-4CA6-9A5A-FB32C6769BE4" nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string11 = /etw\-fuck\.exe\s/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string12 = "Fuck-Etw-main" nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string13 = "unkvolism/Fuck-Etw" nocase ascii wide
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
