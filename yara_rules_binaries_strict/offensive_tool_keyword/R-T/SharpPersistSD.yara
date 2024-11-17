rule SharpPersistSD
{
    meta:
        description = "Detection patterns for the tool 'SharpPersistSD' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPersistSD"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string1 = /\sSharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string2 = /\/SharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string3 = /\/SharpPersistSD\.git/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string4 = /\[\+\]\sUsing\sWMI\sto\sset\sWMI\sSD/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string5 = /\\SharpPersistSD\.cs/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string6 = /\\SharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string7 = /\\SharpPersistSD\.sln/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string8 = /107EBC1B\-0273\-4B3D\-B676\-DE64B7F52B33/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string9 = /1db1f717560d1c53a8ec668a80aad419da22a84b1705f7dfbcc3075634634f64/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string10 = /cybersectroll\/SharpPersistSD/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string11 = /e3e2ced2569d1ebef8f65b554979747881e5e060355fa6698c913036dfd892ba/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string12 = /f44bdc821e6588197e6d1b868a60aa140f20971a6eaeeb9e2a52bdb4065b7fd7/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string13 = /f93389056fa9ad53e214a468aa495adcb2ff1b75a64cd7df77a63a173066d05a/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string14 = /net\slocalgroup\sadministrators\s\/add\stroll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string15 = /net\susers\s\/add\stroll\sTrolololol123/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string16 = /SharpPersistSD\.RegHelper/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string17 = /SharpPersistSD\.SecurityDescriptor/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string18 = /SharpPersistSD\.SvcHelper/ nocase ascii wide
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
