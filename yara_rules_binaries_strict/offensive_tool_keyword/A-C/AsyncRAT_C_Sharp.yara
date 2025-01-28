rule AsyncRAT_C_Sharp
{
    meta:
        description = "Detection patterns for the tool 'AsyncRAT-C-Sharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AsyncRAT-C-Sharp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string1 = "/AsyncRAT-C%23" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string2 = "/AsyncRAT-C-Sharp" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string3 = /\\AsyncRAT\\/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string4 = /\\Plugins\\RemoteCamera\.dll/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string5 = /\\Plugins\\RemoteDesktop\.dll/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string6 = "0DE8DA5D-061D-4649-8A56-48729CF1F789" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string7 = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string8 = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string9 = "AsyncRAT  Simple RAT" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string10 = "AsyncRAT Server" nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string11 = /AsyncRAT\.exe/ nocase ascii wide
        // Description: Open-Source Remote Administration Tool For Windows C# (RAT)
        // Reference: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp
        $string12 = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
        // Description: user agent NIKMOK observed in AsyncRAT sample
        // Reference: https://x.com/g0njxa/status/1829177645348860120
        $string13 = "Hp6kvaq9BCyI" nocase ascii wide
        // Description: user agent NIKMOK observed in AsyncRAT sample
        // Reference: https://x.com/g0njxa/status/1829177645348860120
        $string14 = /User\-Agent.{0,100}NIKMOK/ nocase ascii wide
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
