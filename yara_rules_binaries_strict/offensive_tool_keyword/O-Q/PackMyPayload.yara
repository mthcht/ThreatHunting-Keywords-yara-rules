rule PackMyPayload
{
    meta:
        description = "Detection patterns for the tool 'PackMyPayload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PackMyPayload"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string1 = " --backdoor " nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string2 = /\/PackMyPayload\.git/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string3 = "/PackMyPayload/" nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string4 = /\[\+\]\sBackdoored\sexisting\s7zip\swith\sspecified\sinput\sfile/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string5 = /\[\+\]\sBackdoored\sexisting\sISO\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string6 = /\[\+\]\sBackdoored\sexisting\sMSI\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string7 = /\[\+\]\sBackdoored\sexisting\sVHD\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string8 = /Backdooring\sMSI\sfiles\sis\scurrently\snot\ssupported\./ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string9 = "ddde81ecf809882929faefd5887095a9d8671979f0c4d68579fa8b3a07674768" nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string10 = "File specifed to backdoor does not exist: " nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string11 = "mgeeky/PackMyPayload" nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string12 = /PackMyPayload\.py/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string13 = "PackMyPayload-master" nocase ascii wide
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
