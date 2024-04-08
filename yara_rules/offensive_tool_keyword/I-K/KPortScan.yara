rule KPortScan
{
    meta:
        description = "Detection patterns for the tool 'KPortScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KPortScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string1 = /\/rdp_brute\.git/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string2 = /\\AppData\\Local\\Temp\\KPortScan/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string3 = /\\KPortScan\s3\.0\\/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string4 = /\\KPortScan\\/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string5 = /080c6108c3bd0f8a43d5647db36dc434032842339f0ba38ad1ff62f72999c4e5/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string6 = /KPortScan\.exe/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string7 = /KPortScan\.rar/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string8 = /KPortScan\.zip/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string9 = /KPortScan3\.exe/ nocase ascii wide
        // Description: port scanner used by attackers
        // Reference: https://github.com/stardust50578/rdp_brute
        $string10 = /stardust50578\/rdp_brute/ nocase ascii wide

    condition:
        any of them
}
