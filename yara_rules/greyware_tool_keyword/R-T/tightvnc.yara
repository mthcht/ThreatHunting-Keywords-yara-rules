rule tightvnc
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string1 = /\s\-service\sTightVNC\sServer/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string2 = /\.\\TightVNC1/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string3 = /\.\\TightVNC2/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string4 = /\.\\TightVNC3/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string5 = /\/tightvnc\-.{0,1000}\.msi/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string6 = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string7 = /\\Programs\\TightVNC/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string8 = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string9 = /\\TightVNC\sServer/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string10 = /\\tightvnc\-/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string11 = /\\TightVNC_Service_Control/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string12 = /\\TVN_log_pipe_public_name/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string13 = /\>TightVNC\sViewer\</ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string14 = /00\:\\\.vnc\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string15 = /GlavSoft\sLLC\./ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string16 = /HKCR\\\.vnc/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string17 = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string18 = /ProgramData\\TightVNC/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string19 = /TightVNC\sService/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string20 = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string21 = /tvnserver/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string22 = /tvnserver\.exe/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string23 = /tvnviewer\.exe/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string24 = /VncViewer\.Config/ nocase ascii wide
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string25 = /www\.tightvnc\.com\/download\/.{0,1000}\=/ nocase ascii wide

    condition:
        any of them
}
