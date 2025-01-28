rule dns2tcp
{
    meta:
        description = "Detection patterns for the tool 'dns2tcp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns2tcp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string1 = /\.dns2tcpdrc/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string2 = /\/\.dns2tcprc/
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string3 = "/debian/dns2tcp"
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string4 = /\/dns2tcp\.git/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string5 = "/dns2tcp/client/"
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string6 = "/dns2tcp/common/"
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string7 = "/dns2tcp/server"
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string8 = "/root/dns2tcp"
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string9 = /\\\\\.\\pipe\\win\-sux\-no\-async\-anon\-pipe\-.{0,100}\-/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string10 = /\\dns2tcp\\/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string11 = /\\dns2tcp\\server/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string12 = /\\dns2tcp\-0\./ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string13 = "alex-sector/dns2tcp" nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string14 = "apt install dns2tcp" nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string15 = /dns2tcp\-.{0,100}\.zip/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string16 = /dns2tcp\.exe/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string17 = /dns2tcp\.hsc\.fr/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string18 = /dns2tcp\.kali\.org/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string19 = /dns2tcp\.pid/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string20 = "dns2tcpc -z " nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string21 = /dns2tcpc\.exe/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string22 = "dns2tcpd --" nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string23 = "dns2tcpd -f " nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string24 = "dns2tcp-master" nocase ascii wide
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
