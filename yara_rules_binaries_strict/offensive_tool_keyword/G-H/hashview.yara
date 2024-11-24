rule hashview
{
    meta:
        description = "Detection patterns for the tool 'hashview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string1 = /\shashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string2 = " hashview-agent " nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string3 = /\.\/hashview\// nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string4 = /\/hashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string5 = /\\hashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string6 = "DoNotUseThisPassword123!" nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string7 = /hashview.{0,100}\@.{0,100}localhost/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string8 = /hashview\/config\.conf/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string9 = "hashview/hashview" nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string10 = /hashview\-agent\..{0,100}\.tgz/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string11 = /hashview\-agent\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string12 = /rockyou\.txt\.gz/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string13 = /wordlists\/dynamic\-all\.txt/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string14 = /wordlists\/rockyou\.txt\'/ nocase ascii wide
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
