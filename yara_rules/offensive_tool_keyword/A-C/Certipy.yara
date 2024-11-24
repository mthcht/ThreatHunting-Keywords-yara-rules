rule Certipy
{
    meta:
        description = "Detection patterns for the tool 'Certipy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certipy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string1 = " certipy-ad" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string2 = /\s\-dns\-tcp\s\-nameserver\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string3 = " -no-pass -dns-tcp -nameserver" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string4 = " -old-bloodhound" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string5 = /\sshadow\sauto\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-account\s/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string6 = /\/Certipy\.git/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string7 = "/Certipy/" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string8 = "certipy account " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string9 = "certipy auth " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string10 = "certipy ca " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string11 = "certipy ca -backup" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string12 = "certipy cert " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string13 = "certipy find " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string14 = "certipy forge " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string15 = "certipy forge " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string16 = "certipy relay " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string17 = "certipy req " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string18 = "certipy shadow " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string19 = "certipy template " nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string20 = /certipy\-master\.zip/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string21 = "ly4k/Certipy" nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string22 = "certipy " nocase ascii wide

    condition:
        any of them
}
