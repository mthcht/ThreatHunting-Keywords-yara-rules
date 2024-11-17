rule CyberGhost_VPN
{
    meta:
        description = "Detection patterns for the tool 'CyberGhost VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CyberGhost VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string1 = /\\AppData\\Local\\CyberGhost/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string2 = /\\Applications\\VPN\\Data\\OpenVPN\\/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string3 = /\\Applications\\VPN\\tunnel\.dll/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string4 = /\\Applications\\VPN\\wireguard\.dll/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string5 = /\\CyberGhost\s6\.lnk/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string6 = /\\CyberGhost\s7\.lnk/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string7 = /\\CyberGhost\s8\.lnk/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string8 = /\\CyberGhost\.VPN\..{0,100}\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string9 = /\\CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string10 = /\\Dashboard\.exe\.config/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string11 = /\\Program\sFiles\\CyberGhost/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string12 = /\\Windows\\Temp\\.{0,100}\\wireguard\.sys/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string13 = /\>CyberGhost\s6\sInstaller\</ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string14 = /\>CyberGhost\s7\sInstaller\</ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string15 = /\>CyberGhost\s8\sInstaller\</ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string16 = /api\.cyberghostvpn\.com/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string17 = /CyberGhost\s6\sService/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string18 = /CyberGhost\s7\sService/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string19 = /CyberGhost\s8\sService/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string20 = /CyberGhost\sS\.R\.L\./ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string21 = /CyberGhost\sTunnel\sClient\:/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string22 = /cyberghost.{0,100}\\Dashboard\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string23 = /cyberghost.{0,100}\\Dashboard\.Service\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string24 = /cyberghost.{0,100}\\wyUpdate\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string25 = /CyberGhost\.Browser\.dll/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string26 = /CyberGhost\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string27 = /CyberGhost\.resources\.dll/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string28 = /CyberGhost\.Service\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string29 = /CyberGhost\.Service\.InstallLog/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string30 = /CyberGhost\.Service\.pdb/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string31 = /CyberGhost\.VPNServices\.dll/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string32 = /CyberGhost6Service/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string33 = /CyberGhost7Service/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string34 = /CyberGhost8Service/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string35 = /CyberGhostTunnel\$CyberGhost\-WireGuard\-1/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string36 = /CyberGhostVPNSetup\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string37 = /CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string38 = /download\.cyberghostvpn\.com/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string39 = /feedback\.cyberghostvpn\.com/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string40 = /ffbkglfijbcbgblgflchnbphjdllaogb/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string41 = /payment\.cyberghostvpn\.com/ nocase ascii wide
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
