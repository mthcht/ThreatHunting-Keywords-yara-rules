rule EventCleaner
{
    meta:
        description = "Detection patterns for the tool 'EventCleaner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventCleaner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string1 = /\/EventCleaner\.cpp/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string2 = /\/EventCleaner\.exe/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string3 = /\/EventCleaner\.git/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string4 = /\[\!\]\sinject\sdll\sinto\slog\sprocess\sfailure\s/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string5 = /\[\+\]\sdelete\ssingle\sevent\slog\ssucc/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string6 = /\[\+\]\ssecurity\sevtx\sfile\shandle\sunlock\ssucc/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string7 = /\\\\\.\\\\pipe\\\\kangaroo/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string8 = /\\EventCleaner\.cpp/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string9 = /\\EventCleaner\.exe/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string10 = /\\EventCleaner\.log/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string11 = /\\EventCleaner\.pdb/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string12 = /\\EventCleaner\.sln/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string13 = /\\EventCleaner\-master/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string14 = "0A2B3F8A-EDC2-48B5-A5FC-DE2AC57C8990" nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string15 = "D8A76296-A666-46C7-9CA0-254BA97E3B7C" nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string16 = "eventcleaner closehandle" nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string17 = "eventcleaner suspend" nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string18 = /EventCleaner\.exe\s/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string19 = /EventCleaner\.iobj/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string20 = /EventCleaner\\Debug\\/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string21 = /net\sstop\s\\\\"windows\sevent\slog\\\\"/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string22 = "QAX-A-Team/EventCleaner" nocase ascii wide
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
