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
        $string1 = /\/enumerate\/enumerate\.py/
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string2 = /\/gato\/.{0,1000}attack\.py/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string3 = /gato\s.{0,1000}\sattack/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string4 = /gato\s.{0,1000}\senumerate/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string5 = /gato\s.{0,1000}\s\-\-http\-proxy/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string6 = /gato\s.{0,1000}\s\-\-socks\-proxy/ nocase ascii wide
        // Description: GitHub Self-Hosted Runner Enumeration and Attack Tool
        // Reference: https://github.com/praetorian-inc/gato
        $string7 = "praetorian-inc/gato" nocase ascii wide

    condition:
        any of them
}
