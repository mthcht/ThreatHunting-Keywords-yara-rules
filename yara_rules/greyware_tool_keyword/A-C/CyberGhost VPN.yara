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
        $string8 = /\\CyberGhost\.VPN\..{0,1000}\.exe/ nocase ascii wide
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
        $string12 = /\\Windows\\Temp\\.{0,1000}\\wireguard\.sys/ nocase ascii wide
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
        $string22 = /cyberghost.{0,1000}\\Dashboard\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string23 = /cyberghost.{0,1000}\\Dashboard\.Service\.exe/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://www.cyberghostvpn.com/
        $string24 = /cyberghost.{0,1000}\\wyUpdate\.exe/ nocase ascii wide
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

    condition:
        any of them
}
