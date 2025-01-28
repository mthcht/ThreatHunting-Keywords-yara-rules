rule BrowserGhost
{
    meta:
        description = "Detection patterns for the tool 'BrowserGhost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowserGhost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string1 = /\/BrowserGhost\.git/ nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string2 = "/BrowserGhost/releases/download/" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string3 = "/BrowserGhost/tarball/" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string4 = "/BrowserGhost/zipball/" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string5 = /\\BrowserGhost\.csproj/ nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string6 = /\\BrowserGhost\.sln/ nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string7 = /\\BrowserGhost\-master/ nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string8 = "0b0acd531970ccc941de33b65aed8a93a93374fa9d2791fb210e38828098db85" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string9 = "228e75216d4b2482e113e36823f9367ed46eae2d63a083c915bc282b709e758f" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string10 = "4af84ffd1badb65ce92e7d89e711b055e363db8bb59d8de5592d1215c626317d" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string11 = "60a78c06f7db71904cc08748c5b507bd88ed8a08c31f21d8a796c562a3f0c5b9" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string12 = "8b86dff9da37df4824039ae6da4e3ad9b27b2c25805990ede69b2e036dc30996" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string13 = /BrowserGhost\.exe/ nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string14 = "ce0ae1416a4841144e8a377eed2a11fef988b08042606bac8121b4a4abd5391e" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string15 = "F1653F20-D47D-4F29-8C55-3C835542AF5F" nocase ascii wide
        // Description: This is a tool for grabbing browser passwords
        // Reference: https://github.com/QAX-A-Team/BrowserGhost
        $string16 = "QAX-A-Team/BrowserGhost" nocase ascii wide
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
