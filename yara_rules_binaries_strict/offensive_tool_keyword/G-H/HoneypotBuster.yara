rule HoneypotBuster
{
    meta:
        description = "Detection patterns for the tool 'HoneypotBuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HoneypotBuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string1 = /\\InactiveDomainAdmins\.csv/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string2 = "7H0LmBxFtXBPd0/3vHe7Z3dmdrPZmTzp3ZldQrJ5LOGxeZ" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string3 = "7L0LgBxFtTDc093TPe/dntnM7G6Sncm" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string4 = "Fake Computer Objects Honey Pots" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string5 = "Fake Service Accounts Honey Tokens" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string6 = "Get-FakeServiceUsers" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string7 = "Get-InactiveDomainAdmins" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string8 = "Inactive Domain Admins Honey Tokens" nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string9 = /InjectedCredentials\.csv/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string10 = "Invoke-HoneypotBuster" nocase ascii wide
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
