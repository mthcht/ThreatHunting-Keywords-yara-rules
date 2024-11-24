rule ptunnel_ng
{
    meta:
        description = "Detection patterns for the tool 'ptunnel-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ptunnel-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string1 = " ptunnel-ng" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string2 = "/ptunnel-ng" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string3 = "/var/lib/ptunnel" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string4 = /nc\s127\.0\.0\.1\s4000/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string5 = /new\ssession\sto\s127\.0\.0\.1\:3000/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string6 = /ptunnel\-client\.log/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string7 = "ptunnel-data-recv" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string8 = "ptunnel-data-send" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string9 = "ptunnel-master" nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string10 = "ptunnel-ng " nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string11 = /ptunnel\-ng\.conf/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string12 = /ptunnel\-ng\.git/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string13 = /ptunnel\-ng\.service/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string14 = /ptunnel\-ng\.te/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string15 = /ptunnel\-ng\-x64\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string16 = /ptunnel\-ng\-x64\-dbg\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string17 = /ptunnel\-ng\-x86\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string18 = /ptunnel\-ng\-x86\-dbg\.exe/ nocase ascii wide
        // Description: Tunnel TCP connections through ICMP.
        // Reference: https://github.com/utoni/ptunnel-ng
        $string19 = /ptunnel\-server\.log/ nocase ascii wide
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
