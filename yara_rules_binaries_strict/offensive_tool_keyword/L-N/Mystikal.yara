rule Mystikal
{
    meta:
        description = "Detection patterns for the tool 'Mystikal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mystikal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string1 = /\smystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string2 = /\/MacroWord_Payload\/macro\.txt/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string3 = /\/Mystikal\.git/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string4 = /\/mystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string5 = /\/PDF_Payload\/script\.txt/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string6 = /\\mystikal\.py/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string7 = /D00MFist\/Mystikal/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string8 = /Mystikal\-main/ nocase ascii wide
        // Description: macOS Initial Access Payload Generator
        // Reference: https://github.com/D00MFist/Mystikal
        $string9 = /PDF_Payload.{0,100}Doomfist\.pdf/ nocase ascii wide
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
