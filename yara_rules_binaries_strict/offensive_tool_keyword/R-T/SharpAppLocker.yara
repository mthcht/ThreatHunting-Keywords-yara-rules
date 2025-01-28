rule SharpAppLocker
{
    meta:
        description = "Detection patterns for the tool 'SharpAppLocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAppLocker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string1 = " by Flangvik & Jean_Maes_1994" nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string2 = /\.exe\s\-\-effective\s\-\-allow\s\-\-outfile\s\\"C\:\\Windows\\Tasks\\Rules\.json\\"/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string3 = /\.exe\s\-\-effective\s\-\-allow\s\-\-rules\=\\"FileHashRule\,FilePathRule\\"\s\-\-outfile\=/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string4 = /\/SharpAppLocker\.git/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string5 = /\\SharpAppLocker\./ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string6 = "d43fc4c6e67a332b6abbb4b35186e9a20fa962c6aa4521f49b19f5bf372262d2" nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string7 = "f8e1e243c0648d5bfcd2bb529571b4506f26897574537cffbf1399a171746713" nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string8 = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string9 = "Flangvik/SharpAppLocker" nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string10 = /SharpAppLocker\.exe/ nocase ascii wide
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
