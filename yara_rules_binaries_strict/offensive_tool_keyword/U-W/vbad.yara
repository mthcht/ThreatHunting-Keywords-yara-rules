rule vbad
{
    meta:
        description = "Detection patterns for the tool 'vbad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vbad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string1 = /\sfake\ssmall\skeys\sbefore\sreal\sones\\"/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string2 = /\swill\sbe\sobfuscated\sand\sintegrated\sin\screated\sdocuments/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string3 = /\/VBad\.git/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string4 = /\\VBad\.py/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string5 = /7af0afcd0f9db86c97a7357aaaedd26ab3746e828d5c0febdd063099d0d3fee9/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string6 = /Pepitoh\/VBad/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string7 = /VBA\sObfuscation\sTools\scombined\swith\san\sMS\soffice\sdocument\sgenerator/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string8 = /Vbad\/VBad\.py/ nocase ascii wide
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
