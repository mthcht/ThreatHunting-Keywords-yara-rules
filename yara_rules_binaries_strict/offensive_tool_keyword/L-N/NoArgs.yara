rule NoArgs
{
    meta:
        description = "Detection patterns for the tool 'NoArgs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoArgs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string1 = /\/NoArgs\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string2 = /\/NoArgs\.git/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string3 = /\[i\]\sArgument\sSpoofed\./ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string4 = /\\NoArgs\.cpp/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string5 = /\\NoArgs\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string6 = /\\NoArgs\.exe\.config/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string7 = /\\NoArgs\.exe\.log/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string8 = /\\NoArgs_Encrypted\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string9 = "6a14782fd71e08ded40b8652783cb49695b09e4abbaaf8c22cc22d582032191f" nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string10 = "8c7d64cec00aafa23884f1bb28337ef6ce49f2f90605800217f635526e38541d" nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string11 = "oh-az/NoArgs" nocase ascii wide
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
