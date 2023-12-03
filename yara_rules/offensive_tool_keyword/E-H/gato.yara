rule gato
{
    meta:
        description = "Detection patterns for the tool 'gato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string1 = /.{0,1000}\/enumerate\/enumerate\.py.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string2 = /.{0,1000}\/gato\/.{0,1000}attack\.py.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string3 = /.{0,1000}gato\s.{0,1000}\sattack.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string4 = /.{0,1000}gato\s.{0,1000}\senumerate.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string5 = /.{0,1000}gato\s.{0,1000}\s\-\-http\-proxy.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string6 = /.{0,1000}gato\s.{0,1000}\s\-\-socks\-proxy.{0,1000}/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string7 = /.{0,1000}praetorian\-inc\/gato.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
