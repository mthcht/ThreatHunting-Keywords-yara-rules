rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string1 = " Author:ph4ntom" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string2 = /\s\-c\s.{0,100}\s\-s\s.{0,100}\s\-\-proxy\s.{0,100}\s\-\-proxyu\s.{0,100}\s\-\-proxyp\s.{0,100}\s\-\-reconnect\s/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string3 = /\sProxyStream\s.{0,100}Stowaway/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string4 = /\/script\/reuse\.py/
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string5 = /\/Stowaway\.git/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string6 = "/stowaway_admin"
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string7 = "/stowaway_agent"
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string8 = /\/windows_x64_admin\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string9 = /\/windows_x64_agent\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string10 = /\/windows_x86_admin\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string11 = /\/windows_x86_agent\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string12 = /\\mipsel_agent/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string13 = /\\Stowaway\\admin\\/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string14 = /\\Stowaway\\agent\\/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string15 = /\\Stowaway\\ansicon\\/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string16 = /\\windows_x64_admin\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string17 = /\\windows_x64_agent\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string18 = /\\windows_x86_admin\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string19 = /\\windows_x86_agent\.exe/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string20 = /\]\sStarting\sagent\snode\sactively\.Connecting\sto\s.{0,100}Reconnecting\severy\s.{0,100}\sseconds/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string21 = "1df8bc4fb468ccc0fd85b553411d9b3eb7a2ba4c4a4469ae41913eef9a9e65f6" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string22 = "a78d737f30e03d166d4e3e3b2dca71d54f1cbf582206dfe16a1e717ce3dc0ef7" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string23 = "ac9215db682509ab2bdcba7fe924d84dafa1d8aade87172c1c6328b2cb6c9e52" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string24 = /linux_x64_agent\s\-\-report\s.{0,100}\s\-l\s.{0,100}\s\-s\sph4ntom/
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string25 = "ph4ntonn/Stowaway" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string26 = /python\sreuse\.py\s\-\-start\s\-\-rhost\s.{0,100}\s\-\-rport\s/ nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string27 = "release/mipsel_agent" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string28 = "--socks5-proxy socks5" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string29 = "--socks5-proxyp socks5" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string30 = "--socks5-proxyu socks5" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string31 = "'start/stop iptables port reuse'" nocase ascii wide
        // Description: Stowaway -- Multi-hop Proxy Tool for pentesters
        // Reference: https://github.com/ph4ntonn/Stowaway
        $string32 = "Stowaway/admin/process" nocase ascii wide
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
