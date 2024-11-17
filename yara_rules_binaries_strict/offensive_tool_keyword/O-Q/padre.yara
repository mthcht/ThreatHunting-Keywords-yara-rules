rule padre
{
    meta:
        description = "Detection patterns for the tool 'padre' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "padre"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string1 = /\sgo\sbuild\s\-o\spadre\s\./ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string2 = /\/padre\/pkg\/exploit/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string3 = /\\padre\\pkg\\exploit/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string4 = /github.{0,100}\/padre\.git/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string5 = /glebarez\/padre/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string6 = /Gw3kg8e3ej4ai9wffn\%2Fd0uRqKzyaPfM2UFq\%2F8dWmoW4wnyKZhx07Bg\=\=/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string7 = /\-p\s5000\:5000\spador_vuln_server/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string8 = /padre\s\-u\s.{0,100}http.{0,100}\:\/\// nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string9 = /padre\-master\.zip/ nocase ascii wide
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
