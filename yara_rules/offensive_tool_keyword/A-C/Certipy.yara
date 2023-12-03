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
        $string1 = /.{0,1000}\scertipy\-ad.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string2 = /.{0,1000}\s\-dns\-tcp\s\-nameserver\s.{0,1000}\s\-dc\-ip.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string3 = /.{0,1000}\s\-no\-pass\s\-dns\-tcp\s\-nameserver.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string4 = /.{0,1000}\s\-old\-bloodhound.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string5 = /.{0,1000}\sshadow\sauto\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-account\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string6 = /.{0,1000}\/Certipy\.git.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string7 = /.{0,1000}\/Certipy\/.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string8 = /.{0,1000}certipy\saccount\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string9 = /.{0,1000}certipy\sauth\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string10 = /.{0,1000}certipy\sca\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string11 = /.{0,1000}certipy\sca\s\-backup.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string12 = /.{0,1000}certipy\scert\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string13 = /.{0,1000}certipy\sfind\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string14 = /.{0,1000}certipy\sforge\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string15 = /.{0,1000}certipy\sforge\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string16 = /.{0,1000}certipy\srelay\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string17 = /.{0,1000}certipy\sreq\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string18 = /.{0,1000}certipy\sshadow\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string19 = /.{0,1000}certipy\stemplate\s.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string20 = /.{0,1000}certipy\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string21 = /.{0,1000}ly4k\/Certipy.{0,1000}/ nocase ascii wide
        // Description: Tool for Active Directory Certificate Services enumeration and abuse
        // Reference: https://github.com/ly4k/Certipy
        $string22 = /certipy\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
