rule creddump7
{
    meta:
        description = "Detection patterns for the tool 'creddump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "creddump7"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string1 = /\scachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string2 = /\sdomcachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string3 = " install creddump7" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string4 = /\slsadump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string5 = /\slsasecrets\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string6 = /\spwdump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string7 = /\/cachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string8 = /\/creddump7\.git/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string9 = /\/creddump7\.git/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string10 = "/creddump7/releases/" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string11 = /\/domcachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string12 = /\/lsadump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string13 = /\/lsasecrets\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string14 = /\/pwdump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string15 = /\\cachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string16 = /\\creddump7\-master/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string17 = /\\domcachedump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string18 = /\\lsadump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string19 = /\\lsasecrets\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string20 = /\\pwdump\.py/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string21 = "17723167fed5ac513f66d4540006dc989d6cf341d43464d241f84daccf889f47" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string22 = "4595ba305652431a89d142e09e6e5a9e67515bec0864017e8331082d3004611f" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string23 = "5a66c739cbd2e664a77e6dbbdcb318ca7a99e1a98e9314b0a90ea20378cdb9bd" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string24 = "960ad2b1c19c9d10ecd0c64f6aee01d77564ac9e48b76247a217b637c1a6d482" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string25 = "9f10e67d819156bec13f1a307df49dcf21bd91ddff45205818e402899e58ccca" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string26 = "ac4319f7349146fa891f608416dbf40475ebfdbbbec155939eb34d8fa1a67079" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string27 = "CiscoCXSecurity/creddump7" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string28 = "creddump7 -" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string29 = /creddump7\.exe/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string30 = /creddump7\.win32\./ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string31 = /debian\.org\/pkg\-security\-team\/creddump7/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string32 = "df8687a87b12b4cfcd9cad7082ed7c92bb43726b0d026aeeae6efd575539c0e8" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string33 = "eab9878a9916e998587cf5587e3ac5ce0e5509713b3afe6e64003e8c6962b565" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string34 = "f379a925c80b2f5959d3b3a0658895f7dad370b7478736a2957bc1ae2b59f14c" nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string35 = /framework\.win32\.domcachedump/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string36 = /framework\.win32\.lsasecrets/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string37 = /https\:\/\/code\.google\.com\/p\/creddump\// nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string38 = /pwdump\.py\sSYSTEM\sSAM/ nocase ascii wide
        // Description: extracts various forms of credentials from Windows systems
        // Reference: https://github.com/CiscoCXSecurity/creddump7
        $string39 = /usr\/share\/wordlists\/rockyou\.txt/ nocase ascii wide
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
