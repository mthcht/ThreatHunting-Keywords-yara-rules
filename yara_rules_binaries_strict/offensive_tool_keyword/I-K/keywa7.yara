rule keywa7
{
    meta:
        description = "Detection patterns for the tool 'keywa7' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keywa7"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string1 = /\.exe\s\-\-lhost\s127\.0\.0\.1\s\-\-lport\s.{0,100}\s\-\-rhost\s/ nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string2 = "/keywa7/releases/download/" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string3 = "2d171b19906b039677a1213f32d27a9e1e4a0b96e9e071f7a8e8bd8a72e46243" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string4 = "571e01606bbaaab8febd88396cb3dd97eb8e883e6597d6a881f8c736eff5a05d" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string5 = "5c2a6754f5b9e92a49dfb22ce0644d0e4afaecc5b7a8d7e4714dfb578917c7d8" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string6 = "c7c2b1295dbc6b5b13330310465c771108fdeff7e7b37447bc449f6c535cfa62" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string7 = "d5aa5ef1208264ae918f0e285d358189f66d1166093657f0240a762220bd6a74" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string8 = "fb74046f994a179d004abc1f9a6a00ffa8867dc011d2e2e9ca432fe9225227c2" nocase ascii wide
        // Description: The tool that bypasses the firewall's Application Based Rules and lets you connect to anywhere
        // Reference: https://github.com/keywa7/keywa7
        $string9 = "keywa7/keywa7" nocase ascii wide
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
